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
)

// User is an account. Email is empty until a WeChat-only account binds a mailbox.
type User struct {
	ID    string
	Email string
}

// Challenge stores a code digest and host-owned, non-secret registration reference.
type Challenge struct {
	Email           string
	Hash            string
	RegistrationRef string
	Expires         time.Time
	Sent            time.Time
	Attempts        int
	Ready           bool
}

// Session stores only the digest of an application credential.
type Session struct {
	Hash    string
	UserID  string
	Expires time.Time
}

// WechatIdentity is a server-verified identity scoped to one WeChat application.
// Never populate it from an untrusted client's OpenID.
type WechatIdentity struct {
	AppID  string
	OpenID string
}

// SendCodeInput carries a non-secret reference (for example an invitation digest).
// The reference is persisted verbatim and interpreted only by the host policy.
type SendCodeInput struct {
	Email           string
	IP              string
	RegistrationRef string
}

// EmailLoginInput optionally replaces the reference saved when the code was sent.
type EmailLoginInput struct {
	Email           string
	Code            string
	RegistrationRef string
}

// WechatLoginInput optionally proves a mailbox before an identity is registered.
type WechatLoginInput struct {
	Email           string
	EmailCode       string
	RegistrationRef string
}

// BindEmailInput proves an unused mailbox for an authenticated WeChat account.
type BindEmailInput struct {
	Email string
	Code  string
}

// Registration is passed to the policy only when a new account would be created.
// The policy may consume host-owned admission data within the enclosing transaction.
type Registration struct {
	User      User
	Method    string
	Reference string
}

// LoginResult contains a plaintext token to deliver only after transaction commit.
type LoginResult struct {
	User    User
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
