// Package authkit 提供邮箱验证码与微信小程序登录。
// 宿主负责 HTTP 传输、注册准入和业务授权。
package authkit

import "time"

const (
	CodeTTL        = 10 * time.Minute
	ResendInterval = time.Minute
	MaxAttempts    = 5
	SessionTTL     = 30 * 24 * time.Hour
	EmailRateLimit = 10
	IPRateLimit    = 30
	// MethodEmail 标识邮箱凭证。
	MethodEmail = "email"
	// MethodWechat 标识 OpenID 凭证。
	MethodWechat = "wechat"
)

// Account 是登录主体。尚未绑定邮箱凭证时 Email 为空，尚未分配用户名时 Username 为空。
type Account struct {
	ID       string
	Username string
	Email    string
}

// Challenge 保存验证码摘要。
type Challenge struct {
	Email    string
	Hash     string
	Expires  time.Time
	Sent     time.Time
	Attempts int
	Ready    bool
}

// Session 只保存应用凭证的摘要。
type Session struct {
	Hash      string
	AccountID string
	Expires   time.Time
}

// WechatIdentity 是经服务端核验的 OpenID。AppID 标明执行换取的应用且不落库；OpenID 是唯一凭证。
type WechatIdentity struct {
	AppID  string
	OpenID string
}

// Credential 是创建账号时写入的初始登录凭证。
type Credential struct {
	Method     string
	Identifier string
}

// SendCodeInput 标识用于限流的邮箱和客户端地址。
type SendCodeInput struct {
	Email string
	IP    string
}

// EmailLoginInput 用验证码证明邮箱所有权。
type EmailLoginInput struct {
	Email string
	Code  string
}

// Registration 只在即将创建新账号时交给策略。
// 策略可以在外层事务内消耗宿主拥有的准入数据。
type Registration struct {
	Account Account
	Method  string
}

// LoginResult 包含明文令牌，只应在事务提交后交给调用方。
type LoginResult struct {
	Account Account
	Token   string
	Expires time.Time
	Created bool
}

// Outcome 区分已提交的验证拒绝和需要回滚的错误。
// 调用方拥有的事务在 Rejected 非空时必须提交、跳过后续业务写入，并在提交后把 Rejected 返回给客户端。方法返回的非空错误会回滚。
type Outcome struct {
	Login    *LoginResult
	Rejected error
}
