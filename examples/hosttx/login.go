// Package hosttx 演示如何把身份操作与宿主业务写入组合在一起。
package hosttx

import (
	"context"
	"database/sql"

	"github.com/miebyte/authkit"
	authmysql "github.com/miebyte/authkit/mysql"
	"gorm.io/gorm"
)

// Hooks 由宿主仓储实现，并使用传入的事务。
type Hooks interface {
	// Authorize 可以消费邀请；仅在创建新账号时调用。
	Authorize(context.Context, *gorm.DB, authkit.Registration) error
	// AfterLogin 校验业务访问权限，并执行入组等写入。
	AfterLogin(context.Context, *gorm.DB, authkit.Account) error
}

// LoginEmail 把账号、会话和宿主写入一起提交，同时保留验证码失败的尝试次数。
// 宿主只在它成功后返回令牌。
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

// LoginWechat 在持有数据库锁之前先换取服务商 code。
func LoginWechat(
	ctx context.Context,
	db *gorm.DB,
	service *authkit.Service,
	code string,
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
			LoginWechat(ctx, subject)
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

// LoginPassword 把已有账号的密码登录与宿主写入一起提交，拒绝时仍提交限流计数。
// 宿主只在它成功后返回令牌。
func LoginPassword(
	ctx context.Context,
	db *gorm.DB,
	service *authkit.Service,
	input authkit.PasswordLoginInput,
	hooks Hooks,
) (*authkit.LoginResult, error) {
	var outcome authkit.Outcome
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		outcome, err = service.InTransaction(authmysql.Bind(tx), nil).LoginPassword(ctx, input)
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

// CreatePasswordAccount 在可信宿主流程中创建账号，并在同一事务中执行注册准入。
func CreatePasswordAccount(
	ctx context.Context,
	db *gorm.DB,
	service *authkit.Service,
	input authkit.CreatePasswordAccountInput,
	hooks Hooks,
) (*authkit.Account, error) {
	var account *authkit.Account
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		policy := authkit.RegistrationPolicyFunc(
			func(ctx context.Context, registration authkit.Registration) error {
				return hooks.Authorize(ctx, tx, registration)
			},
		)
		var err error
		account, err = service.InTransaction(authmysql.Bind(tx), policy).
			CreatePasswordAccount(ctx, input)
		return err
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	return account, nil
}

// SetPassword 在已完成授权的宿主流程中设置密码，可与其他业务写入共用事务。
func SetPassword(
	ctx context.Context,
	db *gorm.DB,
	service *authkit.Service,
	input authkit.SetPasswordInput,
) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return service.InTransaction(authmysql.Bind(tx), nil).SetPassword(ctx, input)
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
}
