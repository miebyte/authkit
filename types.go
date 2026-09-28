// Package authkit 提供登录插件共用的账号、身份归属和会话管理能力。
// 邮箱验证码、微信授权等凭证由插件验证；HTTP 接口、注册准入和业务权限由宿主应用负责。
package authkit

import "time"

// SessionTTL 是每次签发会话后的固定有效期；认证请求不会自动延长该时间。
const SessionTTL = 30 * 24 * time.Hour

// User 表示系统内的账号，同一账号可以通过多个已绑定身份登录。
// 邮箱、手机号或外部平台标识保存在身份记录中，不作为账号自身的字段。
type User struct {
	// ID 由核心在注册时生成；后续绑定新的登录身份不会改变该值。
	ID string
}

// IdentityKey 由三个字段共同确定一个登录身份，与使用哪种方式验证该身份无关。
// 插件负责规范化，核心按区分大小写的原值比较；字段须为合法 UTF-8，且不能有首尾空白。
// 例如邮箱验证码与将来的邮箱密码验证可以使用相同的身份键，复用同一个账号。
type IdentityKey struct {
	// Namespace 是身份命名空间，如 email 或 wechat；必填，最多 64 字节。
	Namespace string
	// Scope 是命名空间内的隔离范围，如微信 AppID；最多 255 字节，邮箱使用空字符串。
	Scope string
	// Subject 是范围内的稳定主体标识；必填，最多 254 字节。
	// 邮箱插件使用规范化邮箱，微信插件使用 OpenID 摘要，避免保存原始 OpenID。
	Subject string
}

// Identity 保存身份与账号的归属关系。
// 一个身份只能归属一个账号；同一账号在一个 Namespace + Scope 内只能绑定一个身份。
type Identity struct {
	// Key 是插件规范化后的身份键，不包含验证码或授权 code 等登录凭证。
	Key IdentityKey
	// UserID 为空表示事务中尚未分配归属的占位记录，用于串行化同一身份的首次注册。
	UserID string
}

// VerifiedIdentity 是可信后端插件在验证凭证后传给核心的身份结果。
// 此结构本身没有签名，也不会触发二次凭证验证，调用方不得直接从 HTTP 请求解码或构造它。
// 客户端提供的邮箱或 OpenID 必须先经过相应插件验证，才能进入核心登录和绑定流程。
type VerifiedIdentity struct {
	// Identity 表示已经由插件验证过归属的身份。
	Identity IdentityKey
	// Method 标识本次实际验证方式，如 email_code；必填，最多 64 字节。
	// 它用于注册准入判断，不参与身份唯一性匹配。
	Method string
	// RegistrationRef 是宿主提供的非敏感注册引用，例如邀请摘要；核心仅向准入策略传递它。
	RegistrationRef string
}

// Session 是持久化的应用会话记录，仅保存 Token 摘要，不保存客户端使用的明文 Token。
type Session struct {
	// Hash 是明文 Token 的 SHA-256 十六进制摘要，也是会话的查询和撤销键。
	Hash string
	// UserID 是会话所属账号；多个设备可以持有同一账号的不同会话。
	UserID string
	// Expires 是绝对过期时间；到达该时刻即视为失效，认证时按 UTC 比较。
	Expires time.Time
}

// Registration 是创建新账号前传给宿主准入策略的上下文；已有账号登录不会触发该策略。
// 策略可在当前事务中校验或消费邀请等业务数据，拒绝时账号、身份和会话写入一并回滚。
type Registration struct {
	// User 已分配账号 ID，但调用策略时尚未写入账号仓储。
	User User
	// Identity 是本次注册使用的已验证身份，策略可据此检查邮箱或身份范围。
	Identity IdentityKey
	// Method 区分同一身份的不同验证方式，不能仅用 Identity.Namespace 代替它。
	Method string
	// Reference 是插件确定的注册引用；其有效性和使用次数由宿主重新校验。
	Reference string
}

// LoginResult 是登录或绑定成功后的结果，包含本次签发的明文会话凭证。
// 通过宿主事务获得的结果在提交前只是临时结果，提交成功后才能把 Token 交给客户端。
type LoginResult struct {
	// User 是本次认证或绑定归属的账号。
	User User
	// Token 是客户端后续认证和退出时提交的明文凭证，不应写入数据库或日志。
	Token string
	// Expires 是该 Token 的过期时间，认证请求不会自动续期。
	Expires time.Time
	// Created 仅在本次登录新建账号时为 true；已有账号登录和绑定均为 false。
	Created bool
}

// Outcome 区分需要提交验证失败计数的拒绝结果与正常登录结果。
// 调用方应先检查方法返回的 error：非 nil 时回滚；否则再判断 Rejected。
// Rejected 非 nil 时跳过后续业务写入并提交事务，以保留错误验证码的尝试次数，提交后再返回拒绝原因。
// Rejected 为 nil 时才使用 Login；其中的 Token 仍需等待整个宿主事务提交成功后才能交付。
type Outcome struct {
	// Login 保存成功结果；验证被拒绝时为空。
	Login *LoginResult
	// Rejected 是允许提交当前验证状态的业务拒绝，不应直接作为事务回调错误返回。
	Rejected error
}
