// Package hosttx 演示如何将身份认证与宿主业务写入放在同一个数据库事务中。
package hosttx

import (
	"context"
	"database/sql"

	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/email"
	emailmysql "github.com/miebyte/authkit/email/mysql"
	authmysql "github.com/miebyte/authkit/mysql"
	"github.com/miebyte/authkit/wechat"
	"gorm.io/gorm"
)

// Hooks 由宿主业务仓储实现；所有数据库写入都必须使用参数中的同一个 tx。
type Hooks interface {
	// Authorize 仅在创建新账号时调用，可在当前事务中校验并消费邀请。
	Authorize(context.Context, *gorm.DB, authkit.Registration) error
	// AfterLogin 检查登录后的业务权限并执行入组等写入；返回错误会回滚账号与会话。
	AfterLogin(context.Context, *gorm.DB, authkit.User) error
}

// LoginEmail 将验证码消费、账号、会话和宿主业务写入原子提交。
// 错误验证码通过 Outcome.Rejected 表达：提交失败次数但不继续业务写入。
// 普通错误会回滚整个事务，宿主只有在本函数成功返回后才能向客户端发送 Token。
func LoginEmail(
	ctx context.Context,
	db *gorm.DB,
	core *authkit.Service,
	plugin *email.Service,
	input email.LoginInput,
	hooks Hooks,
) (*authkit.LoginResult, error) {
	var outcome authkit.Outcome
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 注册策略与账号、验证码使用同一事务，邀请消费等副作用才能一起回滚。
		policy := authkit.RegistrationPolicyFunc(
			func(ctx context.Context, registration authkit.Registration) error {
				return hooks.Authorize(ctx, tx, registration)
			},
		)
		coreTx := core.InTransaction(authmysql.Bind(tx), policy)
		var err error
		// 两套仓储都绑定 tx，避免正确验证码被消费后账号或业务写入却未提交。
		outcome, err = plugin.InTransaction(coreTx, emailmysql.Bind(tx)).Login(ctx, input)
		if err != nil || outcome.Rejected != nil {
			// 普通错误返回给 GORM 以触发回滚；验证码拒绝时 err 为 nil，
			// 提交失败次数并跳过 AfterLogin，稍后再将 Rejected 返回给客户端。
			return err
		}
		return hooks.AfterLogin(ctx, tx, outcome.Login.User)
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	if outcome.Rejected != nil {
		return nil, outcome.Rejected
	}
	// Transaction 已成功提交，至此才可把本次会话的明文 Token 交给外部调用者。
	return outcome.Login, nil
}

// LoginWechat 在持有数据库锁之前交换微信 code，再原子提交账号与业务写入。
// LoginVerified 只能接收服务端交换出的可信身份，禁止直接解析客户端提交的
// VerifiedIdentity 或把 OpenID 当作已验证凭据；事务回滚后需重新获取微信 code。
func LoginWechat(
	ctx context.Context,
	db *gorm.DB,
	core *authkit.Service,
	plugin *wechat.Service,
	input wechat.LoginInput,
	hooks Hooks,
) (*authkit.LoginResult, error) {
	verified, err := plugin.ExchangeCode(ctx, input.Code)
	if err != nil {
		return nil, err
	}
	verified.RegistrationRef = input.RegistrationRef
	var outcome authkit.Outcome
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 事务内策略显式绑定 tx，不会继承插件独立 Login 时持有的注册策略。
		policy := authkit.RegistrationPolicyFunc(
			func(ctx context.Context, registration authkit.Registration) error {
				return hooks.Authorize(ctx, tx, registration)
			},
		)
		var err error
		outcome, err = core.InTransaction(authmysql.Bind(tx), policy).
			LoginVerified(ctx, verified)
		if err != nil || outcome.Rejected != nil {
			// 保留统一的 Outcome 契约：普通错误回滚，拒绝结果提交且跳过业务写入。
			return err
		}
		return hooks.AfterLogin(ctx, tx, outcome.Login.User)
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	if outcome.Rejected != nil {
		return nil, outcome.Rejected
	}
	// 账号、会话和 AfterLogin 的写入已全部提交，才向调用者返回可使用的 Token。
	return outcome.Login, nil
}
