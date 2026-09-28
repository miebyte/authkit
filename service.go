package authkit

import (
	"context"
	"time"
)

// Service 提供各登录插件共用的账号、身份绑定和会话入口。
// 这里的方法自行管理事务；需要与宿主业务写入共同提交时，使用 InTransaction。
type Service struct {
	// store 只要求核心仓储能力，各插件的验证码等专属存储由插件自己持有。
	store Store
	// now 提供当前时间，生产环境使用真实时钟，测试中可替换以验证会话到期边界。
	now func() time.Time
}

// NewService 创建仅依赖核心存储的认证服务；store 为 nil 时返回 ErrInvalidInput。
// 邮件发送器、微信客户端和注册策略由实际启用的插件注入，因此可以独立启用任意插件。
func NewService(store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalidInput
	}
	return &Service{store: store, now: time.Now}, nil
}

// InTransaction 将核心操作绑定到调用方已经开启的事务，本方法不负责开启、提交或回滚。
// repos 与可能写入宿主数据的 policy 必须使用同一事务，策略需显式传入；nil 会拒绝新账号注册。
// 调用方须按 Outcome 的约定处理验证拒绝，并在最终提交成功后才向客户端交付 Token。
func (s *Service) InTransaction(repos Repositories, policy RegistrationPolicy) *Transaction {
	return &Transaction{repos: repos, registration: policy, now: s.now}
}

// LoginVerified 根据可信插件已经验证的身份查找账号，必要时经过准入策略创建账号，再签发会话。
// 它负责事务提交，成功返回时结果已持久化；已有账号登录不会调用 policy。
// verified 必须由后端验证流程产生，宿主不得将此方法直接暴露为接收客户端身份字段的登录接口。
func (s *Service) LoginVerified(
	ctx context.Context,
	verified VerifiedIdentity,
	policy RegistrationPolicy,
) (*LoginResult, error) {
	return s.runLogin(ctx, policy, func(tx *Transaction) (Outcome, error) {
		return tx.LoginVerified(ctx, verified)
	})
}

// BindVerified 将可信插件验证过的新身份绑定到当前会话所属账号，并原子轮换该会话的 Token。
// 绑定不会创建账号、执行注册准入、合并账号或替换其他同范围身份；其他设备会话继续有效。
// 成功返回时事务已经提交，调用方应使用返回的新 Token 替换 currentToken。
func (s *Service) BindVerified(
	ctx context.Context,
	currentToken string,
	verified VerifiedIdentity,
) (*LoginResult, error) {
	return s.runLogin(ctx, nil, func(tx *Transaction) (Outcome, error) {
		return tx.BindVerified(ctx, currentToken, verified)
	})
}

// Authenticate 根据明文 Token 的摘要查找尚未过期的会话，并返回所属账号。
// Token 格式无效、会话缺失或过期、账号缺失均返回 ErrUnauthorized；数据库故障原样返回。
// 该方法不续期会话，业务资源的访问权限仍需由宿主判断。
func (s *Service) Authenticate(ctx context.Context, token string) (*User, error) {
	return authenticate(ctx, s.store, token, s.now().UTC())
}

// ListIdentities 列出目标账号已绑定的登录身份，userID 为空时返回 ErrInvalidInput。
// 此方法不验证访问权限；宿主应先确认调用者有权查询该账号，再传入其账号 ID。
// 需要邮箱等登录标识时，可从返回身份的命名空间、范围和主体字段读取。
func (s *Service) ListIdentities(ctx context.Context, userID string) ([]Identity, error) {
	if userID == "" {
		return nil, ErrInvalidInput
	}
	return s.store.Identities().ListByUser(ctx, userID)
}

// Logout 按明文 Token 的摘要撤销一个会话，其他设备会话不受影响。
// 格式错误或已不存在的 Token 也视为退出成功，调用方可安全地重复提交退出请求。
func (s *Service) Logout(ctx context.Context, token string) error {
	if !validToken(token) {
		return nil
	}
	return s.store.Sessions().Delete(ctx, digest(token))
}

// runLogin 统一执行独立登录和绑定事务，只在提交成功后返回登录结果。
// 回调错误和提交错误都会丢弃临时结果；验证拒绝则在提交其状态后作为普通调用错误返回。
func (s *Service) runLogin(
	ctx context.Context,
	policy RegistrationPolicy,
	fn func(*Transaction) (Outcome, error),
) (*LoginResult, error) {
	var outcome Outcome
	err := s.store.WithTransaction(ctx, func(repos Repositories) error {
		var err error
		outcome, err = fn(s.InTransaction(repos, policy))
		return err
	})
	if err != nil {
		return nil, err
	}
	// Rejected 不作为事务回调错误返回，确保插件需要保留的验证失败状态可以提交。
	if outcome.Rejected != nil {
		return nil, outcome.Rejected
	}
	return outcome.Login, nil
}
