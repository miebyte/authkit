package authkit

import (
	"context"
	"errors"
	"time"
)

// Service orchestrates standalone identity transactions and code delivery.
// Use InTransaction when identity and host business writes must commit together.
type Service struct {
	store        Store
	sender       CodeSender
	wechat       WechatExchanger
	registration RegistrationPolicy
	now          func() time.Time
}

// NewService validates required dependencies. A nil WechatExchanger disables
// WeChat exchange; a nil RegistrationPolicy denies creation but permits login.
func NewService(
	store Store,
	sender CodeSender,
	wechat WechatExchanger,
	registration RegistrationPolicy,
) (*Service, error) {
	if store == nil || sender == nil {
		return nil, errors.New("authkit: store and code sender are required")
	}
	return &Service{
		store:        store,
		sender:       sender,
		wechat:       wechat,
		registration: registration,
		now:          time.Now,
	}, nil
}

// InTransaction binds identity operations to repositories already inside a host
// transaction. It never begins or commits a transaction. The supplied policy
// replaces the standalone policy and must use the same host transaction for writes.
func (s *Service) InTransaction(repos Repositories, policy RegistrationPolicy) *Transaction {
	return &Transaction{repos: repos, registration: policy, now: s.now}
}

// SendCode persists a pending code, sends outside the transaction, then activates
// only the same code. Failed delivery leaves the code unusable and retains limits.
func (s *Service) SendCode(ctx context.Context, input SendCodeInput) error {
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return err
	}
	code, err := newCode()
	if err != nil {
		return err
	}
	// MySQL persists microseconds; compare issuance time after the storage round trip.
	now := s.now().UTC().Truncate(time.Microsecond)
	challenge := &Challenge{
		Email: email, Hash: digest(email + code),
		Sent: now, Expires: now.Add(CodeTTL),
	}
	err = s.store.WithTransaction(ctx, func(repos Repositories) error {
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
		// Provider errors can contain message bodies or credentials.
		return errors.Join(ErrMailFailed, ctx.Err())
	}

	return s.store.WithTransaction(ctx, func(repos Repositories) error {
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

// LoginEmail verifies a mailbox and logs in or creates an admitted account.
func (s *Service) LoginEmail(ctx context.Context, input EmailLoginInput) (*LoginResult, error) {
	login, err := emailCodeLogin(input)
	if err != nil {
		return nil, err
	}
	return s.loginCode(ctx, login)
}

// loginCode verifies one code target and logs in or creates an admitted account.
func (s *Service) loginCode(ctx context.Context, input codeLogin) (*LoginResult, error) {
	return s.runLogin(ctx, func(tx *Transaction) (Outcome, error) {
		return tx.loginCode(ctx, input)
	})
}

// ExchangeWechat verifies a provider code without opening a database transaction.
// Hosts may call this before starting their own transaction and then use Transaction.LoginWechat.
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

// LoginWechat exchanges the provider code before atomically binding or registering.
func (s *Service) LoginWechat(
	ctx context.Context,
	code string,
	input WechatLoginInput,
) (*LoginResult, error) {
	if _, err := normalizeWechatInput(input); err != nil {
		return nil, err
	}
	subject, err := s.ExchangeWechat(ctx, code)
	if err != nil {
		return nil, err
	}
	return s.runLogin(
		ctx,
		func(tx *Transaction) (Outcome, error) { return tx.LoginWechat(ctx, subject, input) },
	)
}

// BindEmail adds a verified mailbox and rotates only the supplied live session.
func (s *Service) BindEmail(
	ctx context.Context,
	currentToken string,
	input BindEmailInput,
) (*LoginResult, error) {
	return s.runLogin(
		ctx,
		func(tx *Transaction) (Outcome, error) { return tx.BindEmail(ctx, currentToken, input) },
	)
}

// Authenticate resolves a live application token. It does not authorize host resources.
func (s *Service) Authenticate(ctx context.Context, token string) (*Account, error) {
	return authenticate(ctx, s.store, token, s.now().UTC())
}

// Logout idempotently revokes one session; malformed or missing credentials are a no-op.
func (s *Service) Logout(ctx context.Context, token string) error {
	if !validToken(token) {
		return nil
	}
	return s.store.Sessions().Delete(ctx, digest(token))
}

// runLogin commits verification rejections before exposing them to the caller.
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

func (s *Service) FindAccountByEmail(ctx context.Context, email string) (*Account, error) {
	return s.store.Accounts().GetByEmail(ctx, email)
}
