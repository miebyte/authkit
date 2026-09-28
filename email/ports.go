package email

import (
	"context"
	"time"

	"github.com/miebyte/authkit"
)

// ChallengeRepository 管理单个邮箱的验证码，并通过事务内加锁串行化发码与消费。
type ChallengeRepository interface {
	// Get 锁定邮箱记录；首次发码时先创建未激活的占位记录。
	Get(context.Context, string) (*Challenge, error)
	// Find 只锁定已有记录；未知邮箱返回 authkit.ErrNotFound，不创建持久状态。
	Find(context.Context, string) (*Challenge, error)
	// Save 写入验证码的完整状态，包括零值和 Ready=false。
	Save(context.Context, *Challenge) error
}

// RateRepository 按摘要键原子维护从首次请求开始的固定一小时限流窗口。
type RateRepository interface {
	// Hit 检查并增加一次发码计数，达到上限时返回 ErrTooManyRequests。
	Hit(ctx context.Context, id string, now time.Time, limit int) error
}

// Repositories 提供绑定到同一个数据库句柄或事务的邮箱仓储。
type Repositories interface {
	// Challenges 返回验证码仓储。
	Challenges() ChallengeRepository
	// Rates 返回发码限流仓储。
	Rates() RateRepository
}

// Store 在同一事务中提供核心与邮箱仓储，使验码、账号变更和会话写入原子提交。
type Store interface {
	// WithTransaction 在回调成功时提交，返回错误时回滚；回调返回拒绝结果时应返回 nil，
	// 以保留已写入的错误验证码尝试次数。
	WithTransaction(context.Context, func(authkit.Repositories, Repositories) error) error
}

// CodeSender 由宿主实现验证码投递，邮件模板和供应商凭据不属于本插件。
type CodeSender interface {
	// SendCode 将明文验证码送达目标邮箱；验证码明文不得写入持久仓储。
	SendCode(ctx context.Context, email, code string) error
}
