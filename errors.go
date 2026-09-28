package authkit

import "errors"

// Stable errors can be matched with errors.Is and mapped to the host's HTTP contract.
var (
	ErrInvalidInput       = errors.New("authkit: invalid input")
	ErrInvalidEmail       = errors.New("authkit: invalid email")
	ErrNotFound           = errors.New("authkit: not found")
	ErrConflict           = errors.New("authkit: identity conflict")
	ErrUnauthorized       = errors.New("authkit: unauthorized")
	ErrRegistrationDenied = errors.New("authkit: registration denied")
	ErrTooManyRequests    = errors.New("authkit: too many code requests")
	ErrResendTooSoon      = errors.New("authkit: code requested too soon")
	ErrChallengeUpdated   = errors.New("authkit: code has been replaced")
	ErrChallengeInvalid   = errors.New("authkit: code unavailable, expired or attempts exhausted")
	ErrChallengeMismatch  = errors.New("authkit: incorrect code")
	ErrMailFailed         = errors.New("authkit: code delivery failed")
	ErrWechatUnavailable  = errors.New("authkit: WeChat login is not configured")
	ErrWechatLogin        = errors.New("authkit: WeChat exchange failed")
	ErrWechatCode         = errors.New("authkit: invalid WeChat code")
	ErrWechatBound        = errors.New(
		"authkit: account already has a WeChat identity for this application",
	)
	ErrEmailAccountConflict = errors.New("authkit: email belongs to another account")
	ErrEmailBound           = errors.New("authkit: account already has an email")
	ErrWechatRequired       = errors.New("authkit: account requires a WeChat identity")
)
