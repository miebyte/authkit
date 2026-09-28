package email

import "errors"

var (
	// ErrInvalidEmail 表示输入不是可接受的纯邮箱地址。
	ErrInvalidEmail = errors.New("email: invalid email")
	// ErrTooManyRequests 表示邮箱或 IP 已达到固定一小时窗口的发码上限。
	ErrTooManyRequests = errors.New("email: too many code requests")
	// ErrResendTooSoon 表示同一邮箱距离上次发码不足最短间隔。
	ErrResendTooSoon = errors.New("email: code requested too soon")
	// ErrChallengeUpdated 表示投递期间已有较新的验证码替换当前验证码。
	ErrChallengeUpdated = errors.New("email: code has been replaced")
	// ErrChallengeInvalid 表示验证码不存在、未激活、已过期、已消费或错误次数耗尽。
	ErrChallengeInvalid = errors.New("email: code unavailable, expired or attempts exhausted")
	// ErrChallengeMismatch 表示验证码错误；该次尝试仍须提交到存储。
	ErrChallengeMismatch = errors.New("email: incorrect code")
	// ErrMailFailed 表示邮件发送失败；底层供应商错误不会直接返回给调用方。
	ErrMailFailed = errors.New("email: code delivery failed")
)
