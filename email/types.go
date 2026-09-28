// Package email 为 authkit 账号提供邮箱验证码登录与显式绑定能力。
package email

import "time"

const (
	// CodeTTL 是验证码从发码时间起的有效期，到期瞬间即不可使用。
	CodeTTL = 10 * time.Minute
	// ResendInterval 是同一邮箱两次发码之间的最短间隔。
	ResendInterval = time.Minute
	// MaxAttempts 是一枚验证码允许的错误尝试次数。
	MaxAttempts = 5
	// EmailRateLimit 是同一邮箱在固定一小时窗口内的最大发码次数。
	EmailRateLimit = 10
	// IPRateLimit 是同一 IP 在固定一小时窗口内的最大发码次数。
	IPRateLimit = 30
)

// Challenge 保存一个规范化邮箱当前的验证码状态，不保存验证码明文。
// 发码先写入 Ready=false 的待投递状态，投递成功后才激活；登录或绑定成功会将其消费。
type Challenge struct {
	// Email 是规范化后的邮箱，也是验证码记录的唯一键。
	Email string
	// Hash 是邮箱与验证码组合后的摘要，用于校验而不暴露明文。
	Hash string
	// RegistrationRef 是宿主提供的非秘密注册引用，可由登录输入覆盖。
	RegistrationRef string
	// Expires 是验证码失效时间；校验要求当前时间严格早于它。
	Expires time.Time
	// Sent 是本次发码时间，也用于防止旧投递回调激活较新的验证码。
	Sent time.Time
	// Attempts 记录已持久化的校验次数；错误尝试需要提交，成功消费时也会计入本次校验。
	Attempts int
	// Ready 表示验证码已激活且尚未消费；过期时间和尝试次数仍需另外检查。
	Ready bool
}

// SendCodeInput 是发码输入；宿主负责提供可信客户端 IP 和非秘密注册引用。
type SendCodeInput struct {
	// Email 是待验证的邮箱地址，发码前会统一规范化。
	Email string
	// IP 用于发码限流；空值会让这些请求共用同一个限流桶。
	IP string
	// RegistrationRef 会随验证码保存，仅由宿主注册策略解释。
	RegistrationRef string
}

// LoginInput 是邮箱验证码登录输入，可覆盖发码时保存的注册引用。
type LoginInput struct {
	// Email 必须与收码邮箱对应，校验前会规范化。
	Email string
	// Code 是邮箱收到的验证码，只能成功使用一次。
	Code string
	// RegistrationRef 非空时优先于发码时保存的引用。
	RegistrationRef string
}

// BindInput 用验证码证明邮箱归属，以便绑定到当前有效会话的账号。
type BindInput struct {
	// Email 是待绑定邮箱，会在校验前规范化。
	Email string
	// Code 是该邮箱收到的当前验证码。
	Code string
}
