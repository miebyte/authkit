// Package authmysql adapts authkit repositories to a host-owned MySQL GORM connection.
// The host owns migrations, connection lifecycle and HTTP behavior.
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

// Store provides MySQL repositories and read-committed identity transactions.
type Store struct {
	db *gorm.DB
}

var _ authkit.Store = (*Store)(nil)

// NewStore wraps an existing host connection without connecting or migrating.
func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil || db.Config == nil || db.Dialector == nil || db.Dialector.Name() != "mysql" {
		return nil, authkit.ErrInvalidInput
	}
	if db.Error != nil {
		return nil, db.Error
	}
	return &Store{db: db}, nil
}

// Bind attaches repositories to a valid host-owned transaction. The host must use
// read-committed isolation, commit verification rejections and roll back errors.
func Bind(tx *gorm.DB) authkit.Repositories {
	return &Store{db: tx}
}

// Models returns the schema for an explicit host db.AutoMigrate(Models()...) call.
func Models() []any { return models.AllModels() }

// WithTransaction binds every repository to the same read-committed transaction.
func (s *Store) WithTransaction(ctx context.Context, fn func(authkit.Repositories) error) error {
	return mapError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(Bind(tx))
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted}))
}

// Accounts returns the account and credential-binding repository.
func (s *Store) Accounts() authkit.AccountRepository { return &accountRepository{db: s.db} }

// Challenges returns the mailbox challenge repository.
func (s *Store) Challenges() authkit.ChallengeRepository { return &challengeRepository{db: s.db} }

// Rates returns the code send-rate repository.
func (s *Store) Rates() authkit.RateRepository { return &rateRepository{db: s.db} }

// Sessions returns the application session repository.
func (s *Store) Sessions() authkit.SessionRepository { return &sessionRepository{db: s.db} }

// mapError preserves host errors and maps portable lookup and uniqueness failures.
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
