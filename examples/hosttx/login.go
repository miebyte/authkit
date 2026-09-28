// Package hosttx demonstrates composing identity with host business writes.
package hosttx

import (
	"context"
	"database/sql"

	"github.com/miebyte/authkit"
	authmysql "github.com/miebyte/authkit/mysql"
	"gorm.io/gorm"
)

// Hooks are implemented by host repositories using the supplied transaction.
type Hooks interface {
	// Authorize may consume an invitation; it is called only for new accounts.
	Authorize(context.Context, *gorm.DB, authkit.Registration) error
	// AfterLogin validates business access and applies writes such as joining a group.
	AfterLogin(context.Context, *gorm.DB, authkit.Account) error
}

// LoginEmail commits account/session and host writes together, while preserving
// failed-code attempt counts. The host returns tokens only after this succeeds.
func LoginEmail(
	ctx context.Context,
	db *gorm.DB,
	service *authkit.Service,
	input authkit.EmailLoginInput,
	hooks Hooks,
) (*authkit.LoginResult, error) {
	var outcome authkit.Outcome
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		policy := authkit.RegistrationPolicyFunc(
			func(ctx context.Context, registration authkit.Registration) error {
				return hooks.Authorize(ctx, tx, registration)
			},
		)
		var err error
		outcome, err = service.InTransaction(authmysql.Bind(tx), policy).LoginEmail(ctx, input)
		if err != nil || outcome.Rejected != nil {
			return err
		}
		return hooks.AfterLogin(ctx, tx, outcome.Login.Account)
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	if outcome.Rejected != nil {
		return nil, outcome.Rejected
	}
	return outcome.Login, nil
}

// LoginWechat exchanges the provider code before holding database locks.
func LoginWechat(
	ctx context.Context,
	db *gorm.DB,
	service *authkit.Service,
	code string,
	input authkit.WechatLoginInput,
	hooks Hooks,
) (*authkit.LoginResult, error) {
	subject, err := service.ExchangeWechat(ctx, code)
	if err != nil {
		return nil, err
	}
	var outcome authkit.Outcome
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		policy := authkit.RegistrationPolicyFunc(
			func(ctx context.Context, registration authkit.Registration) error {
				return hooks.Authorize(ctx, tx, registration)
			},
		)
		var err error
		outcome, err = service.InTransaction(authmysql.Bind(tx), policy).
			LoginWechat(ctx, subject, input)
		if err != nil || outcome.Rejected != nil {
			return err
		}
		return hooks.AfterLogin(ctx, tx, outcome.Login.Account)
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	if outcome.Rejected != nil {
		return nil, outcome.Rejected
	}
	return outcome.Login, nil
}
