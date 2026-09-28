// Package authmysql 将 authkit 核心仓储接入宿主提供的 MySQL GORM 连接。
// 数据库连接、显式迁移和 HTTP 行为均由宿主管理；本包只提供账号、身份和会话存储。
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

// Store 提供核心仓储，并以读已提交隔离级别运行独立身份事务。
type Store struct {
	db *gorm.DB
}

var _ authkit.Store = (*Store)(nil)

// NewStore 包装宿主已有的 MySQL 连接，只校验连接句柄，不建立连接或自动迁移。
func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil || db.Config == nil || db.Dialector == nil || db.Dialector.Name() != "mysql" {
		return nil, authkit.ErrInvalidInput
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return &Store{db: db}, nil
}

// Bind 将核心仓储附着到宿主已开启的事务，不负责开启或提交事务。
// 宿主需使用读已提交隔离级别；验证码等预期拒绝应提交计数，方法错误应回滚。
func Bind(tx *gorm.DB) authkit.Repositories {
	return &Store{db: tx}
}

// Models 仅返回账号、身份、会话三个核心模型，供宿主显式迁移。
// 邮箱等插件自行提供其挑战和限流表，未启用插件时无需创建这些表。
func Models() []any { return models.AllModels() }

// WithTransaction 在同一个读已提交事务内提供全部核心仓储。
// 回调返回错误时回滚；返回 nil 时提交，因此调用方可持久化预期拒绝的尝试次数。
func (s *Store) WithTransaction(ctx context.Context, fn func(authkit.Repositories) error) error {
	return mapError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(Bind(tx))
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted}))
}

// Users 返回只保存账号 ID 的仓储；登录身份由 Identities 单独管理。
func (s *Store) Users() authkit.UserRepository { return &userRepository{db: s.db} }

// Identities 返回已验证主体的归属仓储，负责身份键与账号的双向唯一性。
func (s *Store) Identities() authkit.IdentityRepository { return &identityRepository{db: s.db} }

// Sessions 返回应用会话仓储；持久层只保存 Token 摘要。
func (s *Store) Sessions() authkit.SessionRepository { return &sessionRepository{db: s.db} }

// mapError 将未找到记录和 MySQL 1062 唯一键冲突映射为核心稳定错误。
// 其他数据库或宿主错误原样返回，避免丢失故障原因。
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
