package emailmysql

import (
	"context"
	"database/sql"
	"errors"

	driver "github.com/go-sql-driver/mysql"
	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/email"
	coremysql "github.com/miebyte/authkit/mysql"
	"gorm.io/gorm"
)

// Store 将核心与邮箱仓储绑定到同一个 READ COMMITTED 事务。
// 它包装宿主提供的连接，不负责连接生命周期和自动迁移。
type Store struct{ db *gorm.DB }

var _ email.Store = (*Store)(nil)

// NewStore 校验并包装宿主已有的 MySQL GORM 连接，不建立连接或执行迁移。
func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil || db.Config == nil || db.Dialector == nil || db.Dialector.Name() != "mysql" {
		return nil, authkit.ErrInvalidInput
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return &Store{db: db}, nil
}

// Bind 将邮箱仓储绑定到宿主已开启的事务；调用方需另用核心 Bind 绑定同一 tx。
func Bind(tx *gorm.DB) email.Repositories { return &Store{db: tx} }

// WithTransaction 只开启一个 READ COMMITTED 事务，再用同一 tx 构造核心与邮箱仓储。
// 回调返回错误则全部回滚；验证码错误尝试通过拒绝结果返回、回调返回 nil 才会提交。
func (s *Store) WithTransaction(
	ctx context.Context,
	fn func(authkit.Repositories, email.Repositories) error,
) error {
	return mapError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(coremysql.Bind(tx), Bind(tx))
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted}))
}

// Challenges 返回当前句柄绑定的验证码仓储。
func (s *Store) Challenges() email.ChallengeRepository { return &challengeRepository{db: s.db} }

// Rates 返回当前句柄绑定的限流仓储。
func (s *Store) Rates() email.RateRepository { return &rateRepository{db: s.db} }

// mapError 将 GORM 和 MySQL 的记录不存在、唯一键冲突转换为核心稳定错误。
func mapError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return authkit.ErrNotFound
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return authkit.ErrConflict
	}
	var duplicate *driver.MySQLError
	if errors.As(err, &duplicate) && duplicate.Number == 1062 {
		return authkit.ErrConflict
	}
	return err
}
