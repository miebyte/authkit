package authmysql

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
)

func TestAuthenticateSessionPreservesLoginMethod(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	mail := &blacklistMail{}
	const openID = "session-method-open-id"
	policy := authkit.RegistrationPolicyFunc(func(context.Context, authkit.Registration) error { return nil })
	service, err := authkit.NewService(f.store, mail, blacklistWechat{openID: openID}, policy)
	if err != nil {
		t.Fatal(err)
	}
	account := authkit.Account{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := f.store.Accounts().Create(ctx, &account, authkit.Credential{Method: authkit.MethodEmail, Identifier: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := service.SetPassword(ctx, authkit.SetPasswordInput{
		AccountID: account.ID, Identifier: "alice@example.com", Password: "valid-password",
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&models.Binding{
		Method: authkit.MethodWechat, Identifier: fmt.Sprintf("%x", sha256.Sum256([]byte(openID))), AccountID: &account.ID,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := service.SendCode(ctx, authkit.SendCodeInput{Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	emailLogin, err := service.LoginEmail(ctx, authkit.EmailLoginInput{Email: "alice@example.com", Code: mail.code})
	if err != nil {
		t.Fatal(err)
	}
	passwordLogin, err := service.LoginPassword(ctx, authkit.PasswordLoginInput{Identifier: "alice@example.com", Password: "valid-password"})
	if err != nil {
		t.Fatal(err)
	}
	wechatLogin, err := service.LoginWechat(ctx, "wechat-login-code")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method string
		login  *authkit.LoginResult
	}{
		{authkit.MethodEmail, emailLogin},
		{authkit.MethodPassword, passwordLogin},
		{authkit.MethodWechat, wechatLogin},
	} {
		t.Run(test.method, func(t *testing.T) {
			if test.login.Account.ID != emailLogin.Account.ID {
				t.Fatalf("login account = %s, want %s", test.login.Account.ID, emailLogin.Account.ID)
			}
			hash := fmt.Sprintf("%x", sha256.Sum256([]byte(test.login.Token)))
			var stored models.Session
			if err := f.db.Where("hash = ?", hash).Take(&stored).Error; err != nil || stored.Method != test.method {
				t.Fatalf("stored session = %+v, %v", stored, err)
			}
			info, err := service.AuthenticateSession(ctx, test.login.Token)
			if err != nil || info.Method != test.method || info.Account.ID != emailLogin.Account.ID {
				t.Fatalf("service authentication = %+v, %v", info, err)
			}
			if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
				info, err := service.InTransaction(repos, policy).AuthenticateSession(ctx, test.login.Token)
				if err != nil {
					return err
				}
				if info.Method != test.method || info.Account.ID != emailLogin.Account.ID {
					return fmt.Errorf("transaction authentication = %+v", info)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSessionMethodMigrationPreservesLegacySession(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	if err := f.db.Migrator().DropColumn(&models.Session{}, "Method"); err != nil {
		t.Fatal(err)
	}
	account := authkit.Account{ID: "legacy-account"}
	if err := f.store.Accounts().Create(ctx, &account, authkit.Credential{Method: authkit.MethodEmail, Identifier: "legacy@example.com"}); err != nil {
		t.Fatal(err)
	}
	const token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	if err := f.db.Exec("INSERT INTO auth_sessions (hash, account_id, expires) VALUES (?, ?, ?)", hash, account.ID, time.Now().UTC().Add(time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.AutoMigrate(Models()...); err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.Sessions().Get(ctx, hash)
	if err != nil || stored.Method != "" {
		t.Fatalf("migrated legacy session = %+v, %v", stored, err)
	}
	service, err := authkit.NewService(f.store, nil, nil, authkit.RegistrationPolicyFunc(func(context.Context, authkit.Registration) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	info, err := service.AuthenticateSession(ctx, token)
	if err != nil || info.Method != "" || info.Account.ID != account.ID {
		t.Fatalf("legacy authentication = %+v, %v", info, err)
	}
}

func TestDerivedSessionPersistsParentAndFollowsRevocation(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	service, err := authkit.NewService(f.store, nil, nil, authkit.RegistrationPolicyFunc(func(context.Context, authkit.Registration) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	var accounts []*authkit.Account
	for _, name := range []string{"actor", "target"} {
		account, err := service.CreatePasswordAccount(ctx, authkit.CreatePasswordAccountInput{Identifier: name, Password: "valid-password"})
		if err != nil {
			t.Fatal(err)
		}
		accounts = append(accounts, account)
	}
	parent, err := service.LoginPassword(ctx, authkit.PasswordLoginInput{Identifier: "actor", Password: "valid-password", IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := service.LoginAs(ctx, parent.Token, accounts[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.Sessions().Get(ctx, fmt.Sprintf("%x", sha256.Sum256([]byte(child.Token))))
	if err != nil || stored.ParentHash != fmt.Sprintf("%x", sha256.Sum256([]byte(parent.Token))) || stored.Method != authkit.MethodPassword {
		t.Fatalf("stored derived session = %+v, %v", stored, err)
	}
	info, err := service.AuthenticateSession(ctx, child.Token)
	if err != nil || info.Actor == nil || info.Actor.ID != accounts[0].ID || info.Account.ID != accounts[1].ID || info.Method != authkit.MethodPassword {
		t.Fatalf("derived authentication = %+v, %v", info, err)
	}
	before, err := service.AdminOverview(ctx)
	if err != nil || before.ActiveSessions != 2 {
		t.Fatalf("active sessions before logout = %+v, %v", before, err)
	}
	if err := service.Logout(ctx, parent.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, child.Token); !errors.Is(err, authkit.ErrUnauthorized) {
		t.Fatalf("revoked parent retained child access: %v", err)
	}
}

func TestDerivedSessionsExcludedFromAdminViewsAfterParentLogout(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	account := authkit.Account{ID: "target"}
	if err := f.store.Accounts().Create(ctx, &account, authkit.Credential{Method: authkit.MethodEmail, Identifier: "target@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Sessions().Create(ctx, &authkit.Session{Hash: "child", AccountID: account.ID, Expires: now.Add(time.Hour), ParentHash: "missing-parent"}); err != nil {
		t.Fatal(err)
	}
	overview, err := f.store.AdminOverview(ctx, now)
	if err != nil || overview.ActiveSessions != 0 {
		t.Fatalf("orphan included in overview: %+v, %v", overview, err)
	}
	page, err := f.store.AdminListAccounts(ctx, "", 1, 10, now)
	if err != nil || len(page.Items) != 1 || page.Items[0].ActiveSessions != 0 {
		t.Fatalf("orphan included in account list: %+v, %v", page, err)
	}
	detail, err := f.store.AdminGetAccount(ctx, account.ID, now)
	if err != nil || len(detail.Sessions) != 0 {
		t.Fatalf("orphan included in account detail: %+v, %v", detail, err)
	}
}
