package authkit

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"
)

// Transaction runs identity operations inside a caller-owned transaction.
// Results, especially plaintext tokens, are provisional until the caller commits.
type Transaction struct {
	repos        Repositories
	registration RegistrationPolicy
	now          func() time.Time
}

// codeLogin is one verification-code login, independent of the delivery channel.
type codeLogin struct {
	method string
	target string
	code   string
}

// emailCodeLogin normalizes a mailbox login into the shared code-login input.
func emailCodeLogin(input EmailLoginInput) (codeLogin, error) {
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return codeLogin{}, err
	}
	return codeLogin{method: MethodEmail, target: email, code: input.Code}, nil
}

// LoginEmail consumes valid email proof and opens a session for the admitted account.
func (t *Transaction) LoginEmail(ctx context.Context, input EmailLoginInput) (Outcome, error) {
	login, err := emailCodeLogin(input)
	if err != nil {
		return Outcome{}, err
	}
	return t.loginCode(ctx, login)
}

// loginCode consumes valid code proof and opens a session for the admitted account.
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
			user, err = t.createAccount(ctx, account, input.method)
		}
	}
	if err != nil {
		return Outcome{}, err
	}
	return t.finishLogin(ctx, user, challenge, created, now)
}

// findCodeAccount loads the account already bound to this code target.
func (t *Transaction) findCodeAccount(ctx context.Context, input codeLogin) (*Account, error) {
	switch input.method {
	case MethodEmail:
		return t.repos.Accounts().GetByEmail(ctx, input.target)
	default:
		return nil, ErrInvalidInput
	}
}

// newCodeAccount builds an unsaved account for a code channel that has no owner yet.
func newCodeAccount(input codeLogin) (*Account, error) {
	switch input.method {
	case MethodEmail:
		return &Account{Email: input.target}, nil
	default:
		return nil, ErrInvalidInput
	}
}

// LoginWechat uses only a server-verified identity. A first binding can reuse a
// proven email account; already independent accounts are never merged.
func (t *Transaction) LoginWechat(
	ctx context.Context,
	subject WechatIdentity,
	input WechatLoginInput,
) (Outcome, error) {
	if !validWechatIdentity(subject) {
		return Outcome{}, ErrWechatLogin
	}
	email, err := normalizeWechatInput(input)
	if err != nil {
		return Outcome{}, err
	}
	now := t.now().UTC()
	var challenge *Challenge
	if email != "" {
		var rejected error
		challenge, rejected, err = t.verifyCode(ctx, email, input.EmailCode, now)
		if err != nil || rejected != nil {
			return Outcome{Rejected: rejected}, err
		}
	}
	openIDHash := digest(subject.OpenID)
	user, err := t.repos.Accounts().GetByWechat(ctx, openIDHash)
	newBinding := errors.Is(err, ErrNotFound)
	if err != nil && !newBinding {
		return Outcome{}, err
	}
	created := false
	if newBinding {
		user = nil
		if email != "" {
			user, err = t.repos.Accounts().GetByEmail(ctx, email)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return Outcome{}, err
			}
			if errors.Is(err, ErrNotFound) {
				user = nil
			}
		}
		if user == nil {
			user, err = t.createAccount(ctx, &Account{Email: email}, MethodWechat)
			if err != nil {
				return Outcome{}, err
			}
			created = true
		}
		if err = t.repos.Accounts().BindWechat(ctx, openIDHash, user.ID); err != nil {
			return Outcome{}, err
		}
	} else if email != "" {
		if err = t.bindEmail(ctx, user, email); err != nil {
			return Outcome{}, err
		}
	}
	return t.finishLogin(ctx, user, challenge, created, now)
}

// BindEmail verifies a mailbox for the live session owner and rotates the token
// in the same transaction. A binding conflict leaves a correct code available.
func (t *Transaction) BindEmail(
	ctx context.Context,
	currentToken string,
	input BindEmailInput,
) (Outcome, error) {
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return Outcome{}, err
	}
	if !validCode(input.Code) {
		return Outcome{}, ErrInvalidInput
	}
	now := t.now().UTC()
	current, err := authenticate(ctx, t.repos, currentToken, now)
	if err != nil {
		return Outcome{}, err
	}
	challenge, rejected, err := t.verifyCode(ctx, email, input.Code, now)
	if err != nil || rejected != nil {
		return Outcome{Rejected: rejected}, err
	}
	user, err := t.repos.Accounts().GetByID(ctx, current.ID)
	if err != nil {
		return Outcome{}, err
	}
	bound, err := t.repos.Accounts().HasWechat(ctx, user.ID)
	if err != nil {
		return Outcome{}, err
	}
	if !bound {
		return Outcome{}, ErrWechatRequired
	}
	if err = t.bindEmail(ctx, user, email); err != nil {
		return Outcome{}, err
	}
	outcome, err := t.finishLogin(ctx, user, challenge, false, now)
	if err != nil {
		return Outcome{}, err
	}
	if err = t.repos.Sessions().Delete(ctx, digest(currentToken)); err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

// verifyCode returns expected proof failures separately so the attempt counter commits.
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

// createAccount requires an explicit admission decision before persisting the account.
func (t *Transaction) createAccount(
	ctx context.Context,
	account *Account,
	method string,
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
		Registration{Account: *account, Method: method},
	); err != nil {
		return nil, err
	}
	if err = t.repos.Accounts().Create(ctx, account); err != nil {
		return nil, err
	}
	return account, nil
}

// bindEmail preserves IDs and rejects mailbox replacement or cross-account merging.
func (t *Transaction) bindEmail(ctx context.Context, user *Account, email string) error {
	existing, err := t.repos.Accounts().GetByEmail(ctx, email)
	if err == nil && existing.ID != user.ID {
		return ErrEmailAccountConflict
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if user.Email == email {
		return nil
	}
	if user.Email != "" {
		return ErrEmailBound
	}
	if err = t.repos.Accounts().BindEmail(ctx, user.ID, email); err != nil {
		return err
	}
	user.Email = email
	return nil
}

// finishLogin consumes optional mailbox proof and persists only the token digest.
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

// authenticate avoids database lookups for malformed credentials and maps missing sessions.
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
