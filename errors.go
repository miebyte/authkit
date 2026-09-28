package authkit

import "errors"

// 核心错误用于稳定表达认证和存储语义，宿主应通过 errors.Is 判断并映射为自己的 HTTP 响应。
// 凭证验证方式特有的错误由邮箱、微信等插件各自定义。
var (
	// ErrInvalidInput 表示必需依赖缺失，或身份字段不符合格式与长度限制。
	ErrInvalidInput = errors.New("authkit: invalid input")
	// ErrNotFound 表示仓储中没有目标记录；认证入口会将缺失账号或会话转为 ErrUnauthorized。
	ErrNotFound = errors.New("authkit: not found")
	// ErrConflict 表示未被更具体身份错误覆盖的持久化唯一约束冲突。
	ErrConflict = errors.New("authkit: persistence conflict")
	// ErrUnauthorized 表示 Token 格式无效、会话不存在或已过期，或所属账号不存在。
	ErrUnauthorized = errors.New("authkit: unauthorized")
	// ErrRegistrationDenied 表示未配置可用的准入策略；宿主策略也可返回此错误明确拒绝注册。
	ErrRegistrationDenied = errors.New("authkit: registration denied")
	// ErrIdentityConflict 表示待绑定身份已属于另一个账号；核心不会自动合并两个账号。
	ErrIdentityConflict = errors.New("authkit: identity belongs to another account")
	// ErrIdentityBound 表示当前账号已拥有不同的同命名空间、同范围身份，不能直接替换。
	ErrIdentityBound = errors.New("authkit: account already has an identity in this scope")
)
