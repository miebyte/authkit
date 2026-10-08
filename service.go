package authkit

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Service 编排独立的身份事务和验证码投递。
// 身份写入必须与宿主业务写入一起提交时，使用 InTransaction。
type Service struct {
	store             Store
	sender            CodeSender
	wechat            WechatExchanger
	registration      RegistrationPolicy
	now               func() time.Time
	passwordAlgorithm PasswordAlgorithm
}

// NewService 校验存储依赖。CodeSender 或 WechatExchanger 为 nil 时关闭对应渠道；RegistrationPolicy 为 nil 时拒绝创建账号，但允许登录。
func NewService(
	store Store,
	sender CodeSender,
	wechat WechatExchanger,
	registration RegistrationPolicy,
	configs ...Config,
) (*Service, error) {
	config, err := normalizeConfig(configs)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("authkit: store is required")
	}
	return &Service{
		store:             store,
		sender:            sender,
		wechat:            wechat,
		registration:      registration,
		now:               time.Now,
		passwordAlgorithm: config.PasswordAlgorithm,
	}, nil
}

// InTransaction 把身份操作绑定到已经处于宿主事务中的仓储。
// 它不会开启或提交事务。传入的策略会替换独立策略，其写入必须使用同一个宿主事务。
func (s *Service) InTransaction(repos Repositories, policy RegistrationPolicy) *Transaction {
	return &Transaction{repos: repos, registration: policy, now: s.now, passwordAlgorithm: s.passwordAlgorithm}
}

// SendCode 先持久化待发送验证码，在事务外发送，再只激活同一条验证码。
// 投递失败会使验证码不可用，并保留限流计数。
func (s *Service) SendCode(ctx context.Context, input SendCodeInput) error {
	if s.sender == nil {
		return ErrEmailUnavailable
	}
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return err
	}
	code, err := newCode()
	if err != nil {
		return err
	}
	// MySQL 以微秒持久化时间；比较签发时间需要经过存储往返。
	now := s.now().UTC().Truncate(time.Microsecond)
	challenge := &Challenge{
		Email: email, Hash: digest(email + code),
		Sent: now, Expires: now.Add(CodeTTL),
	}
	err = s.store.WithTransaction(ctx, func(repos Repositories) error {
		if err := repos.Blacklist().Check(ctx, Credential{Method: MethodEmail, Identifier: email}); err != nil {
			return err
		}
		if err := checkEmailAccount(ctx, repos, email); err != nil {
			return err
		}
		old, err := repos.Challenges().Get(ctx, email)
		if err != nil {
			return err
		}
		if !old.Sent.IsZero() && now.Sub(old.Sent) < ResendInterval {
			return ErrResendTooSoon
		}

		// 校验邮箱和IP的请求频率
		if err = repos.Rates().Hit(ctx, digest("email:"+email), now, EmailRateLimit); err != nil {
			return err
		}
		if err = repos.Rates().Hit(ctx, digest("ip:"+input.IP), now, IPRateLimit); err != nil {
			return err
		}
		// 保存验证码
		return repos.Challenges().Save(ctx, challenge)
	})
	if err != nil {
		return err
	}

	err = s.sender.SendCode(ctx, email, code)
	if err != nil {
		// 服务商错误可能包含报文正文或凭证。
		return errors.Join(ErrMailFailed, ctx.Err())
	}

	return s.store.WithTransaction(ctx, func(repos Repositories) error {
		if err := repos.Blacklist().Check(ctx, Credential{Method: MethodEmail, Identifier: email}); err != nil {
			return err
		}
		if err := checkEmailAccount(ctx, repos, email); err != nil {
			return err
		}
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

// LoginEmail 核验邮箱，并登录或创建已准入的账号。
func (s *Service) LoginEmail(ctx context.Context, input EmailLoginInput) (*LoginResult, error) {
	login, err := emailCodeLogin(input)
	if err != nil {
		return nil, err
	}
	return s.loginCode(ctx, login)
}

// loginCode 核验一个验证码目标，并登录或创建已准入的账号。
func (s *Service) loginCode(ctx context.Context, input codeLogin) (*LoginResult, error) {
	return s.runLogin(ctx, func(tx *Transaction) (Outcome, error) {
		return tx.loginCode(ctx, input)
	})
}

// ExchangeWechat 在不开启数据库事务的情况下核验服务商 code。
// 宿主可以先调用它，再开启自己的事务，然后使用 Transaction.LoginWechat。
func (s *Service) ExchangeWechat(ctx context.Context, code string) (WechatIdentity, error) {
	if s.wechat == nil {
		return WechatIdentity{}, ErrWechatUnavailable
	}
	if !validWechatCode(code) {
		return WechatIdentity{}, ErrWechatCode
	}
	identity, err := s.wechat.ExchangeCode(ctx, code)
	if err != nil {
		return WechatIdentity{}, err
	}
	if !validWechatIdentity(identity) {
		return WechatIdentity{}, ErrWechatLogin
	}
	return identity, nil
}

// LoginWechat 在原子地绑定或注册之前先换取服务商 code。
func (s *Service) LoginWechat(
	ctx context.Context,
	code string,
) (*LoginResult, error) {
	subject, err := s.ExchangeWechat(ctx, code)
	if err != nil {
		return nil, err
	}
	return s.runLogin(
		ctx,
		func(tx *Transaction) (Outcome, error) {
			return tx.LoginWechat(ctx, subject)
		},
	)
}

// Authenticate 解析仍然有效的应用令牌。它不授权宿主资源。
func (s *Service) Authenticate(ctx context.Context, token string) (*Account, error) {
	session, err := s.AuthenticateSession(ctx, token)
	if err != nil {
		return nil, err
	}
	return &session.Account, nil
}

// AuthenticateSession 验证会话及其父会话，返回绑定方式及宿主授权所需的真实发起账号。
func (s *Service) AuthenticateSession(ctx context.Context, token string) (*AuthenticatedSession, error) {
	return authenticateSession(ctx, s.store, token, s.now().UTC())
}

// LoginAs 为可信宿主签发绑定父会话的代登录凭证；宿主负责管理员授权。
func (s *Service) LoginAs(ctx context.Context, parentToken, accountID string) (*LoginResult, error) {
	var login *LoginResult
	err := s.store.WithTransaction(ctx, func(repos Repositories) error {
		var err error
		login, err = s.InTransaction(repos, s.registration).LoginAs(ctx, parentToken, accountID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return login, nil
}

// CreatePasswordAccount 由可信宿主创建已准入的密码账号，不创建会话。
func (s *Service) CreatePasswordAccount(ctx context.Context, input CreatePasswordAccountInput) (*Account, error) {
	var account *Account
	err := s.store.WithTransaction(ctx, func(repos Repositories) error {
		var err error
		account, err = s.InTransaction(repos, s.registration).CreatePasswordAccount(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return account, nil
}

// SetPassword 由可信宿主开通或重置密码，并在同一事务内撤销全部会话。
func (s *Service) SetPassword(ctx context.Context, input SetPasswordInput) error {
	return s.store.WithTransaction(ctx, func(repos Repositories) error {
		return s.InTransaction(repos, s.registration).SetPassword(ctx, input)
	})
}

// LoginPassword 使用密码绑定的用户名或邮箱登录已有密码账号，不自动注册。
func (s *Service) LoginPassword(ctx context.Context, input PasswordLoginInput) (*LoginResult, error) {
	return s.runLogin(ctx, func(tx *Transaction) (Outcome, error) {
		return tx.LoginPassword(ctx, input)
	})
}

// AdminLoginPassword 在创建会话前校验指定管理员，拒绝时提交限流且不留下会话。
func (s *Service) AdminLoginPassword(ctx context.Context, adminAccountID string, input PasswordLoginInput) (*LoginResult, error) {
	if !validToken(adminAccountID) {
		return nil, ErrInvalidInput
	}
	return s.runLogin(ctx, func(tx *Transaction) (Outcome, error) {
		return tx.loginPassword(ctx, input, strings.ToLower(adminAccountID))
	})
}

// Logout 幂等地撤销一个会话；凭证格式错误或缺失时不做任何事。
func (s *Service) Logout(ctx context.Context, token string) error {
	if !validToken(token) {
		return nil
	}
	return s.store.Sessions().Delete(ctx, digest(token))
}

// runLogin 先提交验证拒绝，再把它返回给调用方。
func (s *Service) runLogin(
	ctx context.Context,
	fn func(*Transaction) (Outcome, error),
) (*LoginResult, error) {
	var outcome Outcome
	err := s.store.WithTransaction(ctx, func(repos Repositories) error {
		var err error
		outcome, err = fn(s.InTransaction(repos, s.registration))
		return err
	})
	if err != nil {
		return nil, err
	}
	if outcome.Rejected != nil {
		return nil, outcome.Rejected
	}
	return outcome.Login, nil
}
