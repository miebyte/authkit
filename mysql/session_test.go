package authmysql

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/miebyte/authkit"
)

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
	if err != nil || stored.ParentHash != fmt.Sprintf("%x", sha256.Sum256([]byte(parent.Token))) {
		t.Fatalf("stored derived session = %+v, %v", stored, err)
	}
	info, err := service.AuthenticateSession(ctx, child.Token)
	if err != nil || info.Actor == nil || info.Actor.ID != accounts[0].ID || info.Account.ID != accounts[1].ID {
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
