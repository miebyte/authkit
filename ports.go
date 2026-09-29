package authkit

import (
	"context"
	"time"
)

// AccountRepository persists accounts and credential bindings.
// Locking methods require a transaction.
type AccountRepository interface {
	GetByEmail(context.Context, string) (*Account, error)
	GetByID(context.Context, string) (*Account, error)
	// GetByWechat exclusively locks the OpenID even before it has an owner.
	GetByWechat(ctx context.Context, openIDHash string) (*Account, error)
	BindWechat(ctx context.Context, openIDHash, accountID string) error
	HasWechat(context.Context, string) (bool, error)
	BindEmail(ctx context.Context, accountID, email string) error
	Create(context.Context, *Account) error
	GetBySessionToken(ctx context.Context, hash string, now time.Time) (*Account, error)
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
	Accounts() AccountRepository
	Challenges() ChallengeRepository
	Rates() RateRepository
	Sessions() SessionRepository
}

// AdminRepository is an optional capability of the existing Store. Callers do
// not construct a second store; custom stores may implement this on the same value.
type AdminRepository interface {
	AdminOverview(context.Context, time.Time) (AdminOverview, error)
	AdminListAccounts(context.Context, string, int, int, time.Time) (AdminAccountPage, error)
	AdminGetAccount(context.Context, string, time.Time) (AdminAccountDetail, error)
	AdminDeleteBinding(context.Context, string, string) error
	AdminRevokeSession(context.Context, string, string) error
	AdminRevokeAllSessions(context.Context, string) error
}

// Store runs a callback on one transaction, rolling back only for its returned error.
type Store interface {
	Repositories
	AdminRepository
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
