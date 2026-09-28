package authkit

import (
	"context"
	"time"
)

// UserRepository persists identities. Locking methods require a transaction.
type UserRepository interface {
	GetByEmail(context.Context, string) (*User, error)
	GetByID(context.Context, string) (*User, error)
	// GetByWechat exclusively locks the identity even before it has an owner.
	GetByWechat(ctx context.Context, appID, openIDHash string) (*User, error)
	BindWechat(ctx context.Context, appID, openIDHash, userID string) error
	HasWechat(context.Context, string) (bool, error)
	BindEmail(ctx context.Context, userID, email string) error
	Create(context.Context, *User) error
	GetBySessionToken(ctx context.Context, hash string, now time.Time) (*User, error)
}

// ChallengeRepository serializes code issuance and consumption per mailbox.
type ChallengeRepository interface {
	// Get locks the mailbox and returns an empty placeholder when no code exists.
	Get(context.Context, string) (*Challenge, error)
	// Find locks an existing challenge, returning ErrNotFound without inserting.
	Find(context.Context, string) (*Challenge, error)
	Save(context.Context, *Challenge) error
}

// RateRepository atomically enforces a fixed hourly window per hashed identifier.
type RateRepository interface {
	Hit(ctx context.Context, id string, now time.Time, limit int) error
}

// SessionRepository stores and revokes token digests.
type SessionRepository interface {
	Create(context.Context, *Session) error
	Delete(context.Context, string) error
}

// Repositories provides identities bound to one database handle or transaction.
type Repositories interface {
	Users() UserRepository
	Challenges() ChallengeRepository
	Rates() RateRepository
	Sessions() SessionRepository
}

// Store runs a callback on one transaction, rolling back only for its returned error.
type Store interface {
	Repositories
	WithTransaction(context.Context, func(Repositories) error) error
}

// CodeSender delivers a code. Templates, branding and provider credentials belong to the host.
type CodeSender interface {
	SendCode(ctx context.Context, email, code string) error
}

// WechatExchanger verifies wx.login codes on the server, before a database transaction.
type WechatExchanger interface {
	ExchangeCode(context.Context, string) (WechatIdentity, error)
}

// RegistrationPolicy authorizes a new account inside the identity transaction.
// Nil denies registration. For host-owned transactional writes, bind the policy
// to the same host transaction and use Service.InTransaction.
type RegistrationPolicy interface {
	Authorize(context.Context, Registration) error
}

// RegistrationPolicyFunc adapts a function to the admission policy.
type RegistrationPolicyFunc func(context.Context, Registration) error

// Authorize delegates to the host function; a nil function denies admission.
func (f RegistrationPolicyFunc) Authorize(ctx context.Context, input Registration) error {
	if f == nil {
		return ErrRegistrationDenied
	}
	return f(ctx, input)
}
