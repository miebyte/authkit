package authkit

import "context"

// UserRepository 保存独立于登录方式的账号数据。
// 普通读取与加锁读取分开，避免认证预检查先锁账号、后锁身份而破坏统一的加锁顺序。
type UserRepository interface {
	// GetByID 无锁读取账号；账号不存在时返回 ErrNotFound。
	GetByID(context.Context, string) (*User, error)
	// Lock 在事务内独占锁定账号，使同一账号上的身份绑定操作依次执行。
	// 调用前应先锁定待处理身份；账号不存在时返回 ErrNotFound。
	Lock(context.Context, string) (*User, error)
	// Create 在当前事务内插入账号，不负责验证凭证或执行注册准入。
	Create(context.Context, *User) error
}

// IdentityRepository 保证身份唯一归属，以及每个账号在同一命名空间和范围内只能绑定一个身份。
// 加锁和写入必须在事务内执行，统一按身份、账号、会话的顺序加锁。
type IdentityRepository interface {
	// Lock 独占锁定身份；记录不存在时先创建未归属的占位行，并返回 UserID 为空的 Identity。
	// 即使尚无账号归属，也必须串行化同一身份的首次登录，不能直接返回 ErrNotFound。
	Lock(context.Context, IdentityKey) (*Identity, error)
	// Bind 将已锁定的占位身份分配给账号，不能覆盖其他账号的归属。
	// 归属其他账号时返回 ErrIdentityConflict；账号已有不同的同范围身份时返回 ErrIdentityBound。
	// 将同一身份重复绑定到原账号可成功返回，不创建重复记录。
	Bind(ctx context.Context, key IdentityKey, userID string) error
	// ListByUser 无锁列出账号的已绑定身份；访问权限由宿主校验。
	ListByUser(context.Context, string) ([]Identity, error)
}

// SessionRepository 按 Token 摘要读取、创建和撤销会话，不能接收或保存明文 Token。
// 仓储只返回持久化记录，会话是否过期由核心判断。
type SessionRepository interface {
	// Get 无锁读取会话，不存在时返回 ErrNotFound；适用于普通认证和绑定前的预检查。
	Get(context.Context, string) (*Session, error)
	// GetForUpdate 在事务内独占锁定会话，用于绑定时复核会话并原子轮换 Token。
	// 必须在取得身份锁和账号锁之后调用；会话不存在时返回 ErrNotFound。
	GetForUpdate(context.Context, string) (*Session, error)
	// Create 插入新会话，调用方负责生成 Token 摘要、账号 ID 和过期时间。
	Create(context.Context, *Session) error
	// Delete 按摘要撤销会话；目标不存在时仍视为成功，便于安全重试退出请求。
	Delete(context.Context, string) error
}

// Repositories 提供绑定到同一数据库连接或事务的核心仓储。
// 在事务流程中返回的各仓储必须共享同一事务，保证账号、身份和会话一起提交或回滚。
type Repositories interface {
	Users() UserRepository
	Identities() IdentityRepository
	Sessions() SessionRepository
}

// Store 在同一个事务中运行回调，并根据回调返回的错误决定提交或回滚。
// 回调返回 nil 后尝试提交，提交失败也必须返回错误；回调返回错误则回滚。
// 插件若需要保留验证失败次数，应将拒绝放在 Outcome.Rejected 中，并让回调返回 nil。
type Store interface {
	Repositories
	WithTransaction(context.Context, func(Repositories) error) error
}

// RegistrationPolicy 在身份事务内决定是否允许创建新账号，已有账号登录和绑定不会调用它。
// 未配置策略时拒绝新注册；策略如需消费邀请等宿主数据，必须使用当前身份事务。
type RegistrationPolicy interface {
	Authorize(context.Context, Registration) error
}

// RegistrationPolicyFunc 将普通函数适配为注册准入策略，便于宿主注入自己的校验逻辑。
type RegistrationPolicyFunc func(context.Context, Registration) error

// Authorize 执行宿主提供的准入函数并原样返回其错误。
// 即使接口本身非 nil，内部函数为 nil 时也会明确拒绝注册，避免绕过默认拒绝规则。
func (f RegistrationPolicyFunc) Authorize(ctx context.Context, input Registration) error {
	if f == nil {
		return ErrRegistrationDenied
	}
	return f(ctx, input)
}
