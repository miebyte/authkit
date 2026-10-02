package authkit

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func passwordDisplayFixture(t *testing.T) (*blacklistFixture, *Account) {
	t.Helper()
	f := newBlacklistFixture(t)
	account, err := f.service.CreatePasswordAccount(context.Background(), CreatePasswordAccountInput{
		Username: "alice", Identifier: "alice", Password: "original-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	account.Username = "shown-name"
	account.Email = "alice@example.com"
	f.store.accounts[account.ID] = *account
	f.store.bindings[blacklistCredentialKey(Credential{Method: MethodEmail, Identifier: account.Email})] = account.ID
	return f, account
}

func TestPasswordLoginUsesBindingAfterDisplayNameChange(t *testing.T) {
	f, account := passwordDisplayFixture(t)
	for _, identifier := range []string{"alice"} {
		result, err := f.service.LoginPassword(context.Background(), PasswordLoginInput{
			Identifier: identifier, Password: "original-password",
		})
		if err != nil {
			t.Fatalf("login with %q: %v", identifier, err)
		}
		if result.Account.ID != account.ID || result.Account.Username != "shown-name" {
			t.Fatalf("login account = %+v", result.Account)
		}
	}
	_, err := f.service.LoginPassword(context.Background(), PasswordLoginInput{
		Identifier: account.Username, Password: "original-password",
	})
	requireBlacklistError(t, err, ErrInvalidCredentials)
}

func TestSetPasswordUsesBindingAfterDisplayNameChange(t *testing.T) {
	f, account := passwordDisplayFixture(t)
	login, err := f.service.LoginPassword(context.Background(), PasswordLoginInput{
		Identifier: "alice", Password: "original-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.service.SetPassword(context.Background(), SetPasswordInput{
		AccountID: account.ID, Password: "replacement-password",
	}); err != nil {
		t.Fatalf("reset after display name change: %v", err)
	}
	if f.store.accounts[account.ID].Username != "shown-name" {
		t.Fatal("password reset changed the display name")
	}
	if _, err := f.service.Authenticate(context.Background(), login.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old session error = %v", err)
	}
	for _, identifier := range []string{"alice"} {
		if _, err := f.service.LoginPassword(context.Background(), PasswordLoginInput{
			Identifier: identifier, Password: "replacement-password",
		}); err != nil {
			t.Fatalf("login with reset password and %q: %v", identifier, err)
		}
	}
}

func TestPasswordBlacklistIgnoresDisplayName(t *testing.T) {
	f, account := passwordDisplayFixture(t)
	if err := f.service.AddBlacklist(context.Background(), Credential{
		Method: MethodPassword, Identifier: account.Username,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.LoginPassword(context.Background(), PasswordLoginInput{
		Identifier: "alice", Password: "original-password",
	}); err != nil {
		t.Fatalf("display name blacklist affected the account: %v", err)
	}
	if err := f.service.AddBlacklist(context.Background(), Credential{
		Method: MethodPassword, Identifier: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	if len(f.store.sessions) != 0 {
		t.Fatal("blacklisting the password binding did not revoke sessions")
	}
	for _, identifier := range []string{"alice"} {
		_, err := f.service.LoginPassword(context.Background(), PasswordLoginInput{
			Identifier: identifier, Password: "original-password",
		})
		requireBlacklistError(t, err, ErrBlacklisted)
	}
}

func TestCreatePasswordAccountSeparatesDisplayNameFromIdentifier(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	for _, identifier := range []string{"alice", "bob"} {
		account, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{
			Username: "共同展示名 @团队", Identifier: " " + identifier + " ", Password: "original-password",
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := f.service.LoginPassword(ctx, PasswordLoginInput{
			Identifier: identifier, Password: "original-password",
		})
		if err != nil || result.Account.ID != account.ID || result.Account.Username != "共同展示名 @团队" {
			t.Fatalf("login %q = %+v, %v", identifier, result, err)
		}
	}
	if _, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{
		Identifier: "empty-display", Password: "original-password",
	}); err != nil {
		t.Fatalf("empty display name = %v", err)
	}
	_, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{
		Username: "different-display", Identifier: "alice", Password: "original-password",
	})
	requireBlacklistError(t, err, ErrConflict)
	if len(f.store.accounts) != 3 {
		t.Fatal("conflicting password identifier left an account")
	}
}

func TestCreatePasswordAccountRejectsInvalidInput(t *testing.T) {
	for _, input := range []CreatePasswordAccountInput{
		{Username: "display", Password: "original-password"},
		{Identifier: "ab", Password: "original-password"},
		{Identifier: "a b", Password: "original-password"},
		{Identifier: "alice@@example.com", Password: "original-password"},
		{Identifier: "alice", Password: "short"},
		{Username: strings.Repeat("名", 65), Identifier: "alice", Password: "original-password"},
		{Username: "name\n", Identifier: "alice", Password: "original-password"},
		{Username: "name\x00", Identifier: "alice", Password: "original-password"},
		{Username: "\xff", Identifier: "alice", Password: "original-password"},
	} {
		f := newBlacklistFixture(t)
		_, err := f.service.CreatePasswordAccount(context.Background(), input)
		requireBlacklistError(t, err, ErrInvalidInput)
		if f.authorized != 0 || len(f.store.accounts) != 0 || len(f.store.bindings) != 0 {
			t.Fatal("invalid password account reached registration or storage")
		}
	}
}

func TestSetPasswordUsesExplicitIdentifierForFirstBinding(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	account := f.loginEmail(t, "alice@example.com").Account
	account.Username = "shown-name"
	f.store.accounts[account.ID] = account
	err := f.service.SetPassword(ctx, SetPasswordInput{AccountID: account.ID, Password: "original-password"})
	requireBlacklistError(t, err, ErrInvalidInput)
	if err := f.service.SetPassword(ctx, SetPasswordInput{
		AccountID: account.ID, Identifier: " alice ", Password: "original-password",
	}); err != nil {
		t.Fatal(err)
	}
	if f.store.accounts[account.ID].Username != "shown-name" {
		t.Fatal("first password binding changed the display name")
	}
	login, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: "alice", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	err = f.service.SetPassword(ctx, SetPasswordInput{
		AccountID: account.ID, Identifier: "other-login", Password: "rejected-password",
	})
	requireBlacklistError(t, err, ErrConflict)
	if _, err := f.service.Authenticate(ctx, login.Token); err != nil {
		t.Fatalf("rejected identifier change revoked a session: %v", err)
	}
	if _, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: "alice", Password: "original-password"}); err != nil {
		t.Fatalf("rejected identifier change modified password: %v", err)
	}
}

func TestSetPasswordRechecksInferredIdentifierAfterAccountLock(t *testing.T) {
	for _, replacement := range []string{"", "replacement-login"} {
		t.Run(replacement, func(t *testing.T) {
			f, account := passwordDisplayFixture(t)
			f.store.accountCheckHook = func(accountID string) {
				delete(f.store.bindings, blacklistCredentialKey(Credential{Method: MethodPassword, Identifier: "alice"}))
				delete(f.store.passwords, accountID)
				if replacement != "" {
					f.store.bindings[blacklistCredentialKey(Credential{Method: MethodPassword, Identifier: replacement})] = accountID
				}
			}
			err := f.service.SetPassword(context.Background(), SetPasswordInput{
				AccountID: account.ID, Password: "replacement-password",
			})
			want := ErrInvalidInput
			if replacement != "" {
				want = ErrConflict
			}
			requireBlacklistError(t, err, want)
		})
	}
}
