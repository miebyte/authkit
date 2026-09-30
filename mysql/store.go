// Package authmysql 把 authkit 仓储适配到宿主拥有的 MySQL GORM 连接。
// 宿主负责迁移、连接生命周期和 HTTP 行为。
package authmysql

import (
	"context"
	"database/sql"
	"errors"

	driver "github.com/go-sql-driver/mysql"
	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
	"gorm.io/gorm"
)

// Store 提供 MySQL 仓储和读已提交的身份事务。
type Store struct {
	db *gorm.DB
}

var _ authkit.Store = (*Store)(nil)

// NewStore 包装宿主已有的连接，不负责建连或迁移。
func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil || db.Config == nil || db.Dialector == nil || db.Dialector.Name() != "mysql" {
		return nil, authkit.ErrInvalidInput
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return &Store{db: db}, nil
}

// Bind 把仓储挂到有效的宿主事务上。宿主必须使用读已提交隔离级别，提交验证拒绝，并在出错时回滚。
func Bind(tx *gorm.DB) authkit.Store {
	return &Store{db: tx}
}

// Models 返回表结构，供宿主显式调用 db.AutoMigrate(Models()...)。
func Models() []any { return models.AllModels() }

// WithTransaction 把全部仓储绑定到同一个读已提交事务。
func (s *Store) WithTransaction(ctx context.Context, fn func(authkit.Repositories) error) error {
	return mapError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(Bind(tx))
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted}))
}

// Accounts 返回账号与凭证绑定仓储。
func (s *Store) Accounts() authkit.AccountRepository { return &accountRepository{db: s.db} }

// Challenges 返回邮箱验证挑战仓储。
func (s *Store) Challenges() authkit.ChallengeRepository { return &challengeRepository{db: s.db} }

// Rates 返回验证码发送频率仓储。
func (s *Store) Rates() authkit.RateRepository { return &rateRepository{db: s.db} }

// Sessions 返回应用会话仓储。
func (s *Store) Sessions() authkit.SessionRepository { return &sessionRepository{db: s.db} }

// Blacklist 返回凭证黑名单仓储。
func (s *Store) Blacklist() authkit.BlacklistRepository { return &blacklistRepository{db: s.db} }

// mapError 保留宿主错误，并把可移植的查找失败和唯一约束失败映射为模块错误。
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
