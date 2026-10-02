package authkit

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPasswordEmailBindingIsIndependent(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	account := f.loginEmail(t, "alice@example.com").Account
	if err := f.service.SetPassword(ctx, SetPasswordInput{
		AccountID: account.ID, Identifier: " Alice@Example.COM ", Password: "original-password",
	}); err != nil {
		t.Fatalf("同账号的邮箱与密码绑定应可共存: %v", err)
	}
	for _, method := range []string{MethodEmail, MethodPassword} {
		if owner := f.store.bindings[blacklistCredentialKey(Credential{Method: method, Identifier: account.Email})]; owner != account.ID {
			t.Fatalf("%s 绑定没有指向同一账号", method)
		}
	}
	for _, identifier := range []string{account.Email, " ALICE@EXAMPLE.COM "} {
		login, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: identifier, Password: "original-password"})
		if err != nil || login.Account.ID != account.ID {
			t.Fatalf("邮箱密码登录未规范化: %v", err)
		}
	}
	if err := f.service.AdminDeleteBinding(ctx, account.ID, MethodEmail); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: account.Email, Password: "original-password"}); err != nil {
		t.Fatalf("解绑 email 不应影响独立的 password 绑定: %v", err)
	}
	if err := f.service.SetPassword(ctx, SetPasswordInput{AccountID: account.ID, Password: "replacement-password"}); err != nil {
		t.Fatalf("邮箱密码绑定应支持省略标识的重置: %v", err)
	}
	if _, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: account.Email, Password: "replacement-password"}); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordEmailDoesNotBorrowEmailBinding(t *testing.T) {
	f, account := passwordDisplayFixture(t)
	_, err := f.service.LoginPassword(context.Background(), PasswordLoginInput{
		Identifier: account.Email, Password: "original-password",
	})
	requireBlacklistError(t, err, ErrInvalidCredentials)
}

func TestCreatePasswordAccountAcceptsEmailIdentifier(t *testing.T) {
	for _, identifier := range []string{" ALICE@EXAMPLE.COM ", strings.Repeat("a", 64) + "@example.com", "Alice"} {
		t.Run(identifier, func(t *testing.T) {
			f := newBlacklistFixture(t)
			ctx := context.Background()
			account, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{
				Username: "显示名", Identifier: identifier, Password: "original-password",
			})
			if err != nil {
				t.Fatalf("应接受邮箱或普通用户名密码标识: %v", err)
			}
			login, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: identifier, Password: "original-password"})
			if err != nil || login.Account.ID != account.ID || login.Account.Username != "显示名" {
				t.Fatalf("密码绑定未保留展示名或登录失败: %v", err)
			}
			if len(f.store.bindings) != 1 || account.Email != "" {
				t.Fatal("创建密码账号不应自动添加邮箱验证码绑定")
			}
		})
	}
}

func TestPasswordEmailBlacklistUsesPasswordBinding(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	account, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{
		Identifier: "alice@example.com", Password: "original-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	login, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: "alice@example.com", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.service.AddBlacklist(ctx, Credential{Method: MethodPassword, Identifier: " ALICE@EXAMPLE.COM "}); err != nil {
		t.Fatalf("密码邮箱黑名单未规范化: %v", err)
	}
	if _, err := f.service.Authenticate(ctx, login.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("拉黑密码绑定未撤销会话: %v", err)
	}
	if _, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: "alice@example.com", Password: "original-password"}); !errors.Is(err, ErrBlacklisted) {
		t.Fatalf("password=email 黑名单未生效: %v", err)
	}
	if err := f.service.SetPassword(ctx, SetPasswordInput{AccountID: account.ID, Password: "replacement-password"}); !errors.Is(err, ErrBlacklisted) {
		t.Fatalf("被拉黑账号仍可重设密码: %v", err)
	}
}

func TestPasswordEmailRejectsDifferentEmailOwner(t *testing.T) {
	for _, operation := range []string{"create", "set"} {
		t.Run(operation, func(t *testing.T) {
			f := newBlacklistFixture(t)
			ctx := context.Background()
			f.loginEmail(t, "alice@example.com")
			var err error
			if operation == "create" {
				_, err = f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{
					Identifier: " ALICE@EXAMPLE.COM ", Password: "original-password",
				})
			} else {
				other := f.loginEmail(t, "other@example.com").Account
				err = f.service.SetPassword(ctx, SetPasswordInput{
					AccountID: other.ID, Identifier: " ALICE@EXAMPLE.COM ", Password: "original-password",
				})
			}
			requireBlacklistError(t, err, ErrConflict)
			if len(f.store.passwords) != 0 || len(f.store.accounts) != len(f.store.bindings) {
				t.Fatal("所有权冲突留下密码绑定或额外账号")
			}
		})
	}
}

func TestEmailAccountRejectsDifferentPasswordEmailOwner(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	account, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{
		Identifier: "alice", Password: "original-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	delete(f.store.bindings, blacklistCredentialKey(Credential{Method: MethodPassword, Identifier: "alice"}))
	f.store.bindings[blacklistCredentialKey(Credential{Method: MethodPassword, Identifier: "alice@example.com"})] = account.ID
	code := f.sendCode(t, "alice@example.com")
	_, err = f.service.LoginEmail(ctx, EmailLoginInput{Email: "alice@example.com", Code: code})
	requireBlacklistError(t, err, ErrConflict)
	if len(f.store.accounts) != 1 || len(f.store.bindings) != 1 || !f.store.challenges["alice@example.com"].Ready {
		t.Fatal("邮箱所有权冲突创建了另一个账号或消费了验证码")
	}
}
