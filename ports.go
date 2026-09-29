package authkit

import (
	"context"
	"time"
)

// AccountRepository 持久化账号和凭证绑定。
// 加锁方法必须在事务中调用。
type AccountRepository interface {
	GetByEmail(context.Context, string) (*Account, error)
	// GetByWechat 即使 OpenID 尚无所有者，也会对其加排他锁。
	GetByWechat(ctx context.Context, openIDHash string) (*Account, error)
	Create(context.Context, *Account, Credential) error
	GetBySessionToken(ctx context.Context, hash string, now time.Time) (*Account, error)
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
}

// Repositories 提供绑定到同一个数据库句柄或事务的身份仓储。
type Repositories interface {
	Accounts() AccountRepository
	Challenges() ChallengeRepository
	Rates() RateRepository
	Sessions() SessionRepository
}

// AdminRepository 是现有 Store 的可选能力。调用方不另行构造第二个存储；自定义存储可以在同一值上实现它。
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
