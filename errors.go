package authkit

import "errors"

// 这些稳定错误可用 errors.Is 匹配，并映射到宿主的 HTTP 约定。
var (
	ErrInvalidInput       = errors.New("authkit: invalid input")
	ErrInvalidEmail       = errors.New("authkit: invalid email")
	ErrNotFound           = errors.New("authkit: not found")
	ErrConflict           = errors.New("authkit: identity conflict")
	ErrUnauthorized       = errors.New("authkit: unauthorized")
	ErrInvalidCredentials = errors.New("authkit: invalid credentials")
	ErrRegistrationDenied = errors.New("authkit: registration denied")
	ErrTooManyRequests    = errors.New("authkit: too many requests")
	ErrResendTooSoon      = errors.New("authkit: code requested too soon")
	ErrChallengeUpdated   = errors.New("authkit: code has been replaced")
	ErrChallengeInvalid   = errors.New("authkit: code unavailable, expired or attempts exhausted")
	ErrChallengeMismatch  = errors.New("authkit: incorrect code")
	ErrMailFailed         = errors.New("authkit: code delivery failed")
	ErrEmailUnavailable   = errors.New("authkit: email login is not configured")
	ErrWechatUnavailable  = errors.New("authkit: WeChat login is not configured")
	ErrWechatLogin        = errors.New("authkit: WeChat exchange failed")
	ErrWechatCode         = errors.New("authkit: invalid WeChat code")

	// ErrBlacklisted 表示凭证或账号的某个绑定已被拉黑。
	ErrBlacklisted = errors.New("authkit: blacklisted")
	// ErrProtectedAccount 防止管理接口拉黑配置的管理员账号。
	ErrProtectedAccount = errors.New("authkit: protected account")
)
