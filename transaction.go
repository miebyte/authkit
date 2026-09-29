package authkit

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"
)

// Transaction 在调用方拥有的事务内执行身份操作。
// 结果，尤其是明文令牌，在调用方提交之前都只是暂定的。
type Transaction struct {
	repos        Repositories
	registration RegistrationPolicy
	now          func() time.Time
}

// codeLogin 表示一次验证码登录，与投递渠道无关。
type codeLogin struct {
	method string
	target string
	code   string
}

// emailCodeLogin 把邮箱登录规范化为共用的验证码登录输入。
func emailCodeLogin(input EmailLoginInput) (codeLogin, error) {
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return codeLogin{}, err
	}
	return codeLogin{method: MethodEmail, target: email, code: input.Code}, nil
}

// LoginEmail 消费有效的邮箱证明，并为已准入的账号开启会话。
func (t *Transaction) LoginEmail(ctx context.Context, input EmailLoginInput) (Outcome, error) {
	login, err := emailCodeLogin(input)
	if err != nil {
		return Outcome{}, err
	}
	return t.loginCode(ctx, login)
}

// loginCode 消费有效的验证码证明，并为已准入的账号开启会话。
func (t *Transaction) loginCode(ctx context.Context, input codeLogin) (Outcome, error) {
	if !validCode(input.code) {
		return Outcome{}, ErrInvalidInput
	}
	now := t.now().UTC()
	challenge, rejected, err := t.verifyCode(ctx, input.target, input.code, now)
	if err != nil || rejected != nil {
		return Outcome{Rejected: rejected}, err
	}
	user, err := t.findCodeAccount(ctx, input)
	created := errors.Is(err, ErrNotFound)
	if created {
		var account *Account
		account, err = newCodeAccount(input)
		if err == nil {
			user, err = t.createAccount(ctx, account, Credential{
				Method: input.method, Identifier: input.target,
			})
		}
	}
	if err != nil {
		return Outcome{}, err
	}
	return t.finishLogin(ctx, user, challenge, created, now)
}

// findCodeAccount 加载已经绑定到该验证码目标的账号。
func (t *Transaction) findCodeAccount(ctx context.Context, input codeLogin) (*Account, error) {
	switch input.method {
	case MethodEmail:
		return t.repos.Accounts().GetByEmail(ctx, input.target)
	default:
		return nil, ErrInvalidInput
	}
}

// newCodeAccount 为尚无所有者的验证码渠道构造一个未保存的账号。
func newCodeAccount(input codeLogin) (*Account, error) {
	switch input.method {
	case MethodEmail:
		return &Account{Email: input.target}, nil
	default:
		return nil, ErrInvalidInput
	}
}

// LoginWechat 使用经服务端核验的身份登录或创建账号。
func (t *Transaction) LoginWechat(
	ctx context.Context,
	subject WechatIdentity,
) (Outcome, error) {
	if !validWechatIdentity(subject) {
		return Outcome{}, ErrWechatLogin
	}
	now := t.now().UTC()
	openIDHash := digest(subject.OpenID)
	user, err := t.repos.Accounts().GetByWechat(ctx, openIDHash)
	created := errors.Is(err, ErrNotFound)
	if err != nil && !created {
		return Outcome{}, err
	}
	if created {
		user, err = t.createAccount(ctx, &Account{}, Credential{
			Method: MethodWechat, Identifier: openIDHash,
		})
		if err != nil {
			return Outcome{}, err
		}
	}
	return t.finishLogin(ctx, user, nil, created, now)
}

// verifyCode 把预期的证明失败单独返回，以便尝试次数能够提交。
func (t *Transaction) verifyCode(
	ctx context.Context,
	target, code string,
	now time.Time,
) (*Challenge, error, error) {
	challenge, err := t.repos.Challenges().Find(ctx, target)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrChallengeInvalid, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if !challenge.Ready || !now.Before(challenge.Expires) || challenge.Attempts >= MaxAttempts {
		return nil, ErrChallengeInvalid, nil
	}
	challenge.Attempts++
	if subtle.ConstantTimeCompare([]byte(challenge.Hash), []byte(digest(target+code))) != 1 {
		return nil, ErrChallengeMismatch, t.repos.Challenges().Save(ctx, challenge)
	}
	return challenge, nil, nil
}

// createAccount 在持久化账号之前要求明确的准入决定。
func (t *Transaction) createAccount(
	ctx context.Context,
	account *Account,
	credential Credential,
) (*Account, error) {
	if t.registration == nil {
		return nil, ErrRegistrationDenied
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	account.ID = id
	if err = t.registration.Authorize(
		ctx,
		Registration{Account: *account, Method: credential.Method},
	); err != nil {
		return nil, err
	}
	if err = t.repos.Accounts().Create(ctx, account, credential); err != nil {
		return nil, err
	}
	return account, nil
}

// finishLogin 消费可选的邮箱证明，并且只持久化令牌摘要。
func (t *Transaction) finishLogin(
	ctx context.Context,
	account *Account,
	challenge *Challenge,
	created bool,
	now time.Time,
) (Outcome, error) {
	if challenge != nil {
		challenge.Ready = false
		if err := t.repos.Challenges().Save(ctx, challenge); err != nil {
			return Outcome{}, err
		}
	}
	token, err := newID()
	if err != nil {
		return Outcome{}, err
	}
	expires := now.Add(SessionTTL)
	err = t.repos.Sessions().Create(
		ctx,
		&Session{
			Hash:      digest(token),
			AccountID: account.ID,
			Expires:   expires,
		},
	)
	if err != nil {
		return Outcome{}, err
	}

	return Outcome{
		Login: &LoginResult{
			Account: *account,
			Token:   token,
			Expires: expires,
			Created: created,
		},
	}, nil
}

// authenticate 对格式错误的凭证跳过数据库查询，并把缺失会话映射为未授权。
func authenticate(
	ctx context.Context,
	repos Repositories,
	token string,
	now time.Time,
) (*Account, error) {
	if !validToken(token) {
		return nil, ErrUnauthorized
	}
	user, err := repos.Accounts().GetBySessionToken(ctx, digest(token), now)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrUnauthorized
	}
	return user, err
}
