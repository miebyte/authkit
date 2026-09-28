package email

import (
	"context"
	"errors"
	"time"

	"github.com/miebyte/authkit"
)

// Service 提供邮箱验证码发码、登录和显式绑定入口。
// 它只持有邮箱插件依赖；核心账号与会话写入由共享的 authkit.Service 完成。
type Service struct {
	core   *authkit.Service
	store  Store
	sender CodeSender
	policy authkit.RegistrationPolicy
	now    func() time.Time
}

// NewService 组装邮箱插件，要求提供核心服务、邮箱存储与邮件发送器。
// policy 为 nil 时拒绝新账号注册，但已绑定邮箱的账号仍可用验证码登录。
func NewService(
	core *authkit.Service,
	store Store,
	sender CodeSender,
	policy authkit.RegistrationPolicy,
) (*Service, error) {
	if core == nil || store == nil || sender == nil {
		return nil, authkit.ErrInvalidInput
	}
	return &Service{core: core, store: store, sender: sender, policy: policy, now: time.Now}, nil
}

// InTransaction 将已绑定到同一宿主事务的核心事务对象和邮箱仓储组合起来。
// 它不会开启或提交事务；宿主必须在提交成功后才交付返回的明文 Token。
func (s *Service) InTransaction(coreTx *authkit.Transaction, repos Repositories) *Transaction {
	return &Transaction{core: coreTx, repos: repos, now: s.now}
}

// SendCode 分两段事务发码：先保存未激活的验证码和限流计数，在事务外发送邮件，
// 投递成功后再确认记录未被更新并激活。投递失败时验证码不可用，但冷却和限流计数保留。
func (s *Service) SendCode(ctx context.Context, input SendCodeInput) error {
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return err
	}
	code, err := newCode()
	if err != nil {
		return err
	}
	// MySQL 按微秒保存时间；截断后可在重新读取时准确比较本次发码时间。
	now := s.now().UTC().Truncate(time.Microsecond)
	challenge := &Challenge{
		Email: email, Hash: digest(email + code), RegistrationRef: input.RegistrationRef,
		Sent: now, Expires: now.Add(CodeTTL),
	}
	err = s.store.WithTransaction(ctx, func(_ authkit.Repositories, repos Repositories) error {
		old, err := repos.Challenges().Get(ctx, email)
		if err != nil {
			return err
		}
		if !old.Sent.IsZero() && now.Sub(old.Sent) < ResendInterval {
			return ErrResendTooSoon
		}
		if err = repos.Rates().Hit(ctx, digest("email:"+email), now, EmailRateLimit); err != nil {
			return err
		}
		if err = repos.Rates().Hit(ctx, digest("ip:"+input.IP), now, IPRateLimit); err != nil {
			return err
		}
		return repos.Challenges().Save(ctx, challenge)
	})
	if err != nil {
		return err
	}
	if err = s.sender.SendCode(ctx, email, code); err != nil {
		// 供应商错误可能包含邮件内容或凭据，仅返回稳定错误及上下文取消信息。
		return errors.Join(ErrMailFailed, ctx.Err())
	}
	return s.store.WithTransaction(ctx, func(_ authkit.Repositories, repos Repositories) error {
		current, err := repos.Challenges().Find(ctx, email)
		if err != nil {
			return err
		}
		if current.Hash != challenge.Hash || !current.Sent.Equal(challenge.Sent) {
			return ErrChallengeUpdated
		}
		current.Ready = true
		return repos.Challenges().Save(ctx, current)
	})
}

// Login 验证邮箱验证码，并登录已有身份或按插件策略注册新账号。
// 验码、账号及会话写入、验证码消费在同一事务中完成；只有提交成功才返回 Token。
func (s *Service) Login(ctx context.Context, input LoginInput) (*authkit.LoginResult, error) {
	return s.run(ctx, func(tx *Transaction) (authkit.Outcome, error) {
		return tx.Login(ctx, input)
	})
}

// Bind 将已证明归属的邮箱绑定到当前有效会话所属账号，并轮换该会话的 Token。
// 绑定冲突会回滚，保留正确验证码供后续处理。
func (s *Service) Bind(
	ctx context.Context,
	token string,
	input BindInput,
) (*authkit.LoginResult, error) {
	return s.run(ctx, func(tx *Transaction) (authkit.Outcome, error) {
		return tx.Bind(ctx, token, input)
	})
}

// run 以同一事务执行邮箱证明和核心操作，并在提交之后处理验证拒绝或交付结果。
func (s *Service) run(
	ctx context.Context,
	fn func(*Transaction) (authkit.Outcome, error),
) (*authkit.LoginResult, error) {
	var outcome authkit.Outcome
	err := s.store.WithTransaction(
		ctx,
		func(coreRepos authkit.Repositories, repos Repositories) error {
			var err error
			outcome, err = fn(s.InTransaction(s.core.InTransaction(coreRepos, s.policy), repos))
			return err
		},
	)
	if err != nil {
		return nil, err
	}
	// 验证拒绝不是事务错误：错误尝试已提交，随后才把拒绝原因返回调用方。
	if outcome.Rejected != nil {
		return nil, outcome.Rejected
	}
	return outcome.Login, nil
}
