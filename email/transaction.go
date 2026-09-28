package email

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/miebyte/authkit"
)

// Transaction 在宿主事务内组合邮箱证明、核心身份归属和会话写入。
// 返回的登录结果在宿主提交之前均为临时结果，不能提前交付 Token。
type Transaction struct {
	core  *authkit.Transaction
	repos Repositories
	now   func() time.Time
}

// Login 在同一事务中校验邮箱证明、查找或创建身份，并消费正确验证码。
// 错误验证码通过 Outcome.Rejected 返回，以便调用方提交尝试次数；其他错误应回滚。
func (t *Transaction) Login(ctx context.Context, input LoginInput) (authkit.Outcome, error) {
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return authkit.Outcome{}, err
	}
	if !validCode(input.Code) {
		return authkit.Outcome{}, authkit.ErrInvalidInput
	}
	challenge, rejected, err := t.verify(ctx, email, input.Code)
	if err != nil || rejected != nil {
		return authkit.Outcome{Rejected: rejected}, err
	}
	ref := input.RegistrationRef
	if ref == "" {
		ref = challenge.RegistrationRef
	}
	verified := authkit.VerifiedIdentity{
		Identity:        authkit.IdentityKey{Namespace: "email", Subject: email},
		Method:          "email_code",
		RegistrationRef: ref,
	}
	outcome, err := t.core.LoginVerified(ctx, verified)
	if err != nil || outcome.Rejected != nil {
		return outcome, err
	}
	challenge.Ready = false
	if err = t.repos.Challenges().Save(ctx, challenge); err != nil {
		return authkit.Outcome{}, err
	}
	return outcome, nil
}

// Bind 先检查当前会话，再校验邮箱证明并交给核心显式绑定身份。
// 核心会在取得身份、账号和会话锁后重新确认会话有效性；成功时消费验证码并轮换 Token。
func (t *Transaction) Bind(
	ctx context.Context,
	token string,
	input BindInput,
) (authkit.Outcome, error) {
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return authkit.Outcome{}, err
	}
	if !validCode(input.Code) {
		return authkit.Outcome{}, authkit.ErrInvalidInput
	}
	if _, err = t.core.Authenticate(ctx, token); err != nil {
		return authkit.Outcome{}, err
	}
	challenge, rejected, err := t.verify(ctx, email, input.Code)
	if err != nil || rejected != nil {
		return authkit.Outcome{Rejected: rejected}, err
	}
	verified := authkit.VerifiedIdentity{
		Identity: authkit.IdentityKey{Namespace: "email", Subject: email},
		Method:   "email_code",
	}
	outcome, err := t.core.BindVerified(ctx, token, verified)
	if err != nil || outcome.Rejected != nil {
		return outcome, err
	}
	challenge.Ready = false
	if err = t.repos.Challenges().Save(ctx, challenge); err != nil {
		return authkit.Outcome{}, err
	}
	return outcome, nil
}

// verify 锁定已有验证码，并分别返回验证码、可提交的拒绝原因和需要回滚的事务错误。
// 错码立即保存增加后的 Attempts，交由调用方提交；正确码要等核心操作成功后才消费。
func (t *Transaction) verify(ctx context.Context, email, code string) (*Challenge, error, error) {
	challenge, err := t.repos.Challenges().Find(ctx, email)
	if errors.Is(err, authkit.ErrNotFound) {
		return nil, ErrChallengeInvalid, nil
	}
	if err != nil {
		return nil, nil, err
	}
	now := t.now().UTC()
	if !challenge.Ready || !now.Before(challenge.Expires) || challenge.Attempts >= MaxAttempts {
		return nil, ErrChallengeInvalid, nil
	}
	challenge.Attempts++
	if subtle.ConstantTimeCompare([]byte(challenge.Hash), []byte(digest(email+code))) != 1 {
		return nil, ErrChallengeMismatch, t.repos.Challenges().Save(ctx, challenge)
	}
	return challenge, nil, nil
}
