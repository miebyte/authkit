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

// LoginEmail consumes valid email proof and opens a session for the admitted account.
func (t *Transaction) LoginEmail(ctx context.Context, input EmailLoginInput) (Outcome, error) {
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return Outcome{}, err
	}
	if !validEmailCode(input.Code) {
		return Outcome{}, ErrInvalidInput
	}
	now := t.now().UTC()
	challenge, rejected, err := t.verifyEmail(ctx, email, input.Code, now)
	if err != nil || rejected != nil {
		return Outcome{Rejected: rejected}, err
	}
	user, err := t.repos.Users().GetByEmail(ctx, email)
	created := errors.Is(err, ErrNotFound)
	if created {
		user, err = t.createUser(
			ctx,
			email,
			"email",
			registrationRef(input.RegistrationRef, challenge),
		)
	}
	if err != nil {
		return Outcome{}, err
	}
	return t.finishLogin(ctx, user, challenge, created, now)
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
		challenge, rejected, err = t.verifyEmail(ctx, email, input.EmailCode, now)
		if err != nil || rejected != nil {
			return Outcome{Rejected: rejected}, err
		}
	}
	openIDHash := digest(subject.OpenID)
	user, err := t.repos.Users().GetByWechat(ctx, subject.AppID, openIDHash)
	newBinding := errors.Is(err, ErrNotFound)
	if err != nil && !newBinding {
		return Outcome{}, err
	}
	created := false
	if newBinding {
		user = nil
		if email != "" {
			user, err = t.repos.Users().GetByEmail(ctx, email)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return Outcome{}, err
			}
			if errors.Is(err, ErrNotFound) {
				user = nil
			}
		}
		if user == nil {
			user, err = t.createUser(
				ctx,
				email,
				"wechat",
				registrationRef(input.RegistrationRef, challenge),
			)
			if err != nil {
				return Outcome{}, err
			}
			created = true
		}
		if err = t.repos.Users().BindWechat(ctx, subject.AppID, openIDHash, user.ID); err != nil {
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
	if !validEmailCode(input.Code) {
		return Outcome{}, ErrInvalidInput
	}
	now := t.now().UTC()
	current, err := authenticate(ctx, t.repos, currentToken, now)
	if err != nil {
		return Outcome{}, err
	}
	challenge, rejected, err := t.verifyEmail(ctx, email, input.Code, now)
	if err != nil || rejected != nil {
		return Outcome{Rejected: rejected}, err
	}
	user, err := t.repos.Users().GetByID(ctx, current.ID)
	if err != nil {
		return Outcome{}, err
	}
	bound, err := t.repos.Users().HasWechat(ctx, user.ID)
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

// verifyEmail returns expected proof failures separately so the attempt counter commits.
func (t *Transaction) verifyEmail(
	ctx context.Context,
	email, code string,
	now time.Time,
) (*Challenge, error, error) {
	challenge, err := t.repos.Challenges().Find(ctx, email)
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
	if subtle.ConstantTimeCompare([]byte(challenge.Hash), []byte(digest(email+code))) != 1 {
		return nil, ErrChallengeMismatch, t.repos.Challenges().Save(ctx, challenge)
	}
	return challenge, nil, nil
}

// createUser requires an explicit admission decision before persisting the account.
func (t *Transaction) createUser(
	ctx context.Context,
	email, method, reference string,
) (*User, error) {
	if t.registration == nil {
		return nil, ErrRegistrationDenied
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	user := &User{ID: id, Email: email}
	if err = t.registration.Authorize(
		ctx,
		Registration{User: *user, Method: method, Reference: reference},
	); err != nil {
		return nil, err
	}
	if err = t.repos.Users().Create(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// bindEmail preserves IDs and rejects mailbox replacement or cross-account merging.
func (t *Transaction) bindEmail(ctx context.Context, user *User, email string) error {
	existing, err := t.repos.Users().GetByEmail(ctx, email)
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
	if err = t.repos.Users().BindEmail(ctx, user.ID, email); err != nil {
		return err
	}
	user.Email = email
	return nil
}

// finishLogin consumes optional mailbox proof and persists only the token digest.
func (t *Transaction) finishLogin(
	ctx context.Context,
	user *User,
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
	if err = t.repos.Sessions().
		Create(ctx, &Session{Hash: digest(token), UserID: user.ID, Expires: expires}); err != nil {
		return Outcome{}, err
	}
	return Outcome{
		Login: &LoginResult{User: *user, Token: token, Expires: expires, Created: created},
	}, nil
}

// authenticate avoids database lookups for malformed credentials and maps missing sessions.
func authenticate(
	ctx context.Context,
	repos Repositories,
	token string,
	now time.Time,
) (*User, error) {
	if !validToken(token) {
		return nil, ErrUnauthorized
	}
	user, err := repos.Users().GetBySessionToken(ctx, digest(token), now)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrUnauthorized
	}
	return user, err
}

// registrationRef prefers an explicitly supplied reference over the saved mail reference.
func registrationRef(explicit string, challenge *Challenge) string {
	if explicit != "" {
		return explicit
	}
	if challenge != nil {
		return challenge.RegistrationRef
	}
	return ""
}
