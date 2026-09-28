// Package authkit provides email-code and WeChat mini-program authentication.
// Hosts own HTTP transport, registration admission and business authorization.
package authkit

import "time"

const (
	CodeTTL        = 10 * time.Minute
	ResendInterval = time.Minute
	MaxAttempts    = 5
	SessionTTL     = 30 * 24 * time.Hour
	EmailRateLimit = 10
	IPRateLimit    = 30
	// MethodEmail identifies a mailbox credential.
	MethodEmail = "email"
	// MethodWechat identifies an OpenID credential.
	MethodWechat = "wechat"
)

// Account is the login subject. Email is empty until a mailbox credential is bound.
// Username is empty until assigned.
type Account struct {
	ID       string
	Username string
	Email    string
}

// Challenge stores a code digest.
type Challenge struct {
	Email    string
	Hash     string
	Expires  time.Time
	Sent     time.Time
	Attempts int
	Ready    bool
}

// Session stores only the digest of an application credential.
type Session struct {
	Hash      string
	AccountID string
	Expires   time.Time
}

// WechatIdentity is a server-verified OpenID. AppID names the application that
// performed the exchange and is not stored; OpenID is the unique credential.
type WechatIdentity struct {
	AppID  string
	OpenID string
}

// SendCodeInput identifies the mailbox and the client address used for rate limits.
type SendCodeInput struct {
	Email string
	IP    string
}

// EmailLoginInput proves a mailbox with a verification code.
type EmailLoginInput struct {
	Email string
	Code  string
}

// WechatLoginInput optionally proves a mailbox before an identity is registered.
type WechatLoginInput struct {
	Email     string
	EmailCode string
}

// BindEmailInput proves an unused mailbox for an authenticated WeChat account.
type BindEmailInput struct {
	Email string
	Code  string
}

// Registration is passed to the policy only when a new account would be created.
// The policy may consume host-owned admission data within the enclosing transaction.
type Registration struct {
	Account Account
	Method  string
}

// LoginResult contains a plaintext token to deliver only after transaction commit.
type LoginResult struct {
	Account Account
	Token   string
	Expires time.Time
	Created bool
}

// Outcome distinguishes a committed verification rejection from a rollback error.
// A caller-owned transaction must commit on Rejected, skip further business writes,
// and return Rejected to its client after commit. Non-nil method errors roll back.
type Outcome struct {
	Login    *LoginResult
	Rejected error
}
