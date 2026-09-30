package authkit

import (
	"context"
	"time"
)

// AccountRepository 持久化账号和凭证绑定。
// 加锁方法必须在事务中调用。
type AccountRepository interface {
	GetByID(ctx context.Context, id string) (*Account, error)
	GetByUsername(ctx context.Context, username string) (*Account, error)
	// SetUsername 在已锁定的账号上首次赋值，已有值只允许保持不变。
	SetUsername(ctx context.Context, accountID, username string) error
	GetByEmail(ctx context.Context, email string) (*Account, error)
	// GetByWechat 即使 OpenID 尚无所有者，也会对其加排他锁。
	GetByWechat(ctx context.Context, openIDHash string) (*Account, error)
	GetBySessionToken(ctx context.Context, hash string, now time.Time) (*Account, error)
	// GetPasswordHash 获取密码摘要
	GetPasswordHash(ctx context.Context, accountID string) (string, error)
	// SetPasswordHash 设置密码摘要
	SetPasswordHash(ctx context.Context, accountID, username, hash string) error
	// Create 创建账号和凭证绑定，并授权准入。
	Create(context.Context, *Account, Credential) error
}

// ChallengeRepository 按邮箱串行化验证码的签发与消费。
type ChallengeRepository interface {
	// Get 锁定邮箱；尚无验证码时返回空占位。
	Get(context.Context, string) (*Challenge, error)
	// Find 锁定已有验证挑战；不存在时返回 ErrNotFound，且不插入记录。
	Find(context.Context, string) (*Challenge, error)
	Save(context.Context, *Challenge) error
}

// RateRepository 按哈希标识原子地执行固定的小时窗口限流。
type RateRepository interface {
	Hit(ctx context.Context, id string, now time.Time, limit int) error
}

// SessionRepository 存储并撤销令牌摘要。
type SessionRepository interface {
	Create(context.Context, *Session) error
	Delete(context.Context, string) error
	DeleteByAccount(context.Context, string) error
}

// BlacklistRepository 持久化邮箱、密码用户名和 OpenID 摘要的黑名单。
type BlacklistRepository interface {
	// Check 在事务内锁定凭证，即使尚无黑名单记录；被拉黑时返回 ErrBlacklisted。
	Check(context.Context, Credential) error
	// CheckAccount 锁定账号并检查全部绑定及保留的用户名；被拉黑时返回 ErrBlacklisted。
	CheckAccount(context.Context, string) error
	// Add 在同一事务中加入黑名单、清除邮箱验证码并撤销关联账号的全部会话。
	Add(context.Context, BlacklistEntry) error
	// Remove 幂等解除限制，保留用于串行化检查的占位记录。
	Remove(context.Context, string) error
	// List 只返回已拉黑的条目，隐藏微信 OpenID 摘要。
	List(context.Context, int, int) (BlacklistPage, error)
}

// Repositories 提供绑定到同一个数据库句柄或事务的身份仓储。
type Repositories interface {
	Accounts() AccountRepository
	Challenges() ChallengeRepository
	Rates() RateRepository
	Sessions() SessionRepository
	Blacklist() BlacklistRepository
}

// AdminRepository 是 Store 必须实现的管理能力，调用方不另行构造第二个存储。
type AdminRepository interface {
	AdminOverview(context.Context, time.Time) (AdminOverview, error)
	AdminListAccounts(context.Context, string, int, int, time.Time) (AdminAccountPage, error)
	AdminGetAccount(context.Context, string, time.Time) (AdminAccountDetail, error)
	AdminDeleteBinding(context.Context, string, string) error
	AdminRevokeSession(context.Context, string, string) error
	AdminRevokeAllSessions(context.Context, string) error
}

// Store 在一个事务上运行回调，仅在回调返回错误时回滚。
type Store interface {
	Repositories
	AdminRepository
	WithTransaction(context.Context, func(Repositories) error) error
}

// CodeSender 投递验证码。模板、品牌和服务商凭证由宿主持有。
type CodeSender interface {
	SendCode(ctx context.Context, email, code string) error
}

// WechatExchanger 在数据库事务之前，于服务端核验 wx.login 的 code。
type WechatExchanger interface {
	ExchangeCode(context.Context, string) (WechatIdentity, error)
}

// RegistrationPolicy 在身份事务内授权新账号。
// 为 nil 时拒绝注册。宿主若要在事务内写入，应将策略绑定到同一个宿主事务，并使用 Service.InTransaction。
type RegistrationPolicy interface {
	Authorize(context.Context, Registration) error
}

// RegistrationPolicyFunc 把函数适配为准入策略。
type RegistrationPolicyFunc func(context.Context, Registration) error

// Authorize 委托给宿主函数；函数为 nil 时拒绝准入。
func (f RegistrationPolicyFunc) Authorize(ctx context.Context, input Registration) error {
	if f == nil {
		return ErrRegistrationDenied
	}
	return f(ctx, input)
}
