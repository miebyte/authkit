package authmysql

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
)

func TestPasswordEmailBindingLifecycle(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	mail := &blacklistMail{}
	service, err := authkit.NewService(
		f.store,
		mail,
		nil,
		authkit.RegistrationPolicyFunc(
			func(context.Context, authkit.Registration) error { return nil },
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SendCode(
		ctx,
		authkit.SendCodeInput{Email: " Alice@Example.COM "},
	); err != nil {
		t.Fatal(err)
	}
	emailLogin, err := service.LoginEmail(
		ctx,
		authkit.EmailLoginInput{Email: "alice@example.com", Code: mail.code},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetPassword(ctx, authkit.SetPasswordInput{
		AccountID:  emailLogin.Account.ID,
		Identifier: " ALICE@EXAMPLE.COM ",
		Password:   "initial-password",
	}); err != nil {
		t.Fatal(err)
	}
	byPassword, err := f.store.Accounts().GetByPasswordIdentifier(ctx, "alice@example.com")
	if err != nil || byPassword.ID != emailLogin.Account.ID {
		t.Fatalf("同邮箱的两种登录方式未绑定同账号: %v", err)
	}
	requireRows(t, f.db, &models.Binding{}, 2)
	login, err := service.LoginPassword(
		ctx,
		authkit.PasswordLoginInput{Identifier: " ALICE@EXAMPLE.COM ", Password: "initial-password"},
	)
	if err != nil || login.Account.ID != emailLogin.Account.ID {
		t.Fatalf("规范化邮箱密码登录失败: %v", err)
	}
	if err := service.AddBlacklist(
		ctx,
		authkit.Credential{Method: authkit.MethodPassword, Identifier: " ALICE@EXAMPLE.COM "},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, login.Token); !errors.Is(err, authkit.ErrUnauthorized) {
		t.Fatalf("邮箱密码拉黑未撤销会话: %v", err)
	}
	if err := service.SendCode(
		ctx,
		authkit.SendCodeInput{Email: "alice@example.com"},
	); !errors.Is(
		err,
		authkit.ErrBlacklisted,
	) {
		t.Fatalf("密码绑定拉黑未封禁整个账号: %v", err)
	}
	page, err := service.ListBlacklist(ctx, 1, 10)
	if err != nil || page.Total != 1 {
		t.Fatalf("邮箱密码黑名单未规范化: %v", err)
	}
	if err := service.RemoveBlacklist(ctx, page.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := service.AdminDeleteBinding(
		ctx,
		emailLogin.Account.ID,
		authkit.MethodEmail,
	); err != nil {
		t.Fatal(err)
	}
	login, err = service.LoginPassword(
		ctx,
		authkit.PasswordLoginInput{Identifier: "alice@example.com", Password: "initial-password"},
	)
	if err != nil || login.Account.Email != "" {
		t.Fatalf("独立邮箱密码绑定依赖已删除的 email 绑定: %v", err)
	}
	if err := service.AdminDeleteBinding(
		ctx,
		emailLogin.Account.ID,
		authkit.MethodPassword,
	); !errors.Is(
		err,
		authkit.ErrLastBinding,
	) {
		t.Fatalf("独立邮箱密码绑定未计入最后登录方式: %v", err)
	}
}

func TestPasswordEmailCannotUseEmailAlias(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	service, err := authkit.NewService(
		f.store,
		nil,
		nil,
		authkit.RegistrationPolicyFunc(
			func(context.Context, authkit.Registration) error { return nil },
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	account, err := service.CreatePasswordAccount(
		ctx,
		authkit.CreatePasswordAccountInput{Identifier: "alice", Password: "initial-password"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(
		&models.Binding{
			Method:     authkit.MethodEmail,
			Identifier: "alice@example.com",
			AccountID:  &account.ID,
		},
	).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := service.LoginPassword(
		ctx,
		authkit.PasswordLoginInput{Identifier: "alice@example.com", Password: "initial-password"},
	); !errors.Is(
		err,
		authkit.ErrInvalidCredentials,
	) {
		t.Fatalf("密码登录借用了 email 绑定: %v", err)
	}
	if _, err := service.LoginPassword(
		ctx,
		authkit.PasswordLoginInput{Identifier: "alice", Password: "initial-password"},
	); err != nil {
		t.Fatalf("普通用户名密码登录失效: %v", err)
	}
}

func TestPasswordEmailOwnershipConflictsRollback(t *testing.T) {
	for _, initialMethod := range []string{authkit.MethodEmail, authkit.MethodPassword} {
		t.Run(initialMethod, func(t *testing.T) {
			f := newMySQLFixture(t)
			ctx := context.Background()
			mail := &blacklistMail{}
			service, err := authkit.NewService(
				f.store,
				mail,
				nil,
				authkit.RegistrationPolicyFunc(
					func(context.Context, authkit.Registration) error { return nil },
				),
			)
			if err != nil {
				t.Fatal(err)
			}
			if initialMethod == authkit.MethodEmail {
				if err := service.SendCode(
					ctx,
					authkit.SendCodeInput{Email: "alice@example.com"},
				); err != nil {
					t.Fatal(err)
				}
				if _, err := service.LoginEmail(
					ctx,
					authkit.EmailLoginInput{Email: "alice@example.com", Code: mail.code},
				); err != nil {
					t.Fatal(err)
				}
				if _, err := service.CreatePasswordAccount(ctx, authkit.CreatePasswordAccountInput{
					Identifier: " ALICE@EXAMPLE.COM ", Password: "initial-password",
				}); !errors.Is(err, authkit.ErrConflict) {
					t.Fatalf("创建密码账号未拒绝已有邮箱所有者: %v", err)
				}
				other, err := service.CreatePasswordAccount(
					ctx,
					authkit.CreatePasswordAccountInput{
						Identifier: "other",
						Password:   "other-password",
					},
				)
				if err != nil {
					t.Fatal(err)
				}
				if err := service.SetPassword(ctx, authkit.SetPasswordInput{
					AccountID:  other.ID,
					Identifier: "alice@example.com",
					Password:   "rejected-password",
				}); !errors.Is(err, authkit.ErrConflict) {
					t.Fatalf("设密未拒绝其他账号的邮箱: %v", err)
				}
				if _, err := service.LoginPassword(
					ctx,
					authkit.PasswordLoginInput{Identifier: "other", Password: "other-password"},
				); err != nil {
					t.Fatalf("冲突设密修改了原密码: %v", err)
				}
				requireRows(t, f.db, &models.Account{}, 2)
				requireRows(t, f.db, &models.Binding{}, 2)
			} else {
				if _, err := service.CreatePasswordAccount(ctx, authkit.CreatePasswordAccountInput{
					Identifier: "alice@example.com", Password: "initial-password",
				}); err != nil {
					t.Fatal(err)
				}
				if err := service.SendCode(
					ctx,
					authkit.SendCodeInput{Email: "alice@example.com"},
				); err != nil {
					t.Fatal(err)
				}
				if _, err := service.LoginEmail(
					ctx,
					authkit.EmailLoginInput{Email: "alice@example.com", Code: mail.code},
				); !errors.Is(
					err,
					authkit.ErrConflict,
				) {
					t.Fatalf("邮箱验证码创建了不同账号: %v", err)
				}
				var challenge models.Challenge
				if err := f.db.Where("email = ?", "alice@example.com").
					Take(&challenge).
					Error; err != nil || !challenge.Ready ||
					challenge.Attempts != 0 {
					t.Fatalf("邮箱所有权冲突消费了验证码: %v", err)
				}
				requireRows(t, f.db, &models.Account{}, 1)
				requireRows(t, f.db, &models.Binding{}, 1)
			}
		})
	}
}

func TestPasswordEmailConcurrentRegistrationDoesNotSplitAccount(t *testing.T) {
	f := newMySQLFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mail := &blacklistMail{}
	entered, release := make(chan struct{}), make(chan struct{})
	policy := authkit.RegistrationPolicyFunc(
		func(_ context.Context, registration authkit.Registration) error {
			if registration.Method == authkit.MethodEmail {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	)
	service, err := authkit.NewService(f.store, mail, nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SendCode(ctx, authkit.SendCodeInput{Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	registered, competing := make(chan error, 1), make(chan error, 1)
	go func() {
		registered <- f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
			identity := service.InTransaction(repos, policy)
			outcome, err := identity.LoginEmail(ctx, authkit.EmailLoginInput{Email: "alice@example.com", Code: mail.code})
			if err != nil {
				return err
			}
			if outcome.Rejected != nil {
				return outcome.Rejected
			}
			return identity.SetPassword(ctx, authkit.SetPasswordInput{
				AccountID: outcome.Login.Account.ID, Identifier: "alice@example.com", Password: "initial-password",
			})
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("邮箱注册未进入持锁状态")
	}
	go func() {
		_, err := service.CreatePasswordAccount(ctx, authkit.CreatePasswordAccountInput{
			Identifier: " ALICE@EXAMPLE.COM ", Password: "other-password",
		})
		competing <- err
	}()
	select {
	case err := <-competing:
		t.Fatalf("并发密码注册没有等待同邮箱的事务: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-registered:
		if err != nil {
			t.Fatalf("邮箱注册与设密产生锁冲突: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("邮箱注册与设密未完成")
	}
	select {
	case err := <-competing:
		if !errors.Is(err, authkit.ErrConflict) {
			t.Fatalf("并发密码注册未拒绝现有邮箱所有者: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("并发密码注册未完成")
	}
	requireRows(t, f.db, &models.Account{}, 1)
	requireRows(t, f.db, &models.Binding{}, 2)
}
