package authmysql

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
)

func TestPasswordBindingKeepsDisplayUsername(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	account := authkit.Account{ID: "account", Username: "Display Name"}
	credential := authkit.Credential{Method: authkit.MethodPassword, Identifier: "alice"}
	if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
		if err := repos.Accounts().Create(ctx, &account, authkit.Credential{
			Method: authkit.MethodEmail, Identifier: "user@example.com",
		}); err != nil {
			return err
		}
		if err := repos.Blacklist().CheckAccount(ctx, account.ID); err != nil {
			return err
		}
		return repos.Accounts().SetPasswordHash(ctx, account.ID, credential.Identifier, "initial-hash")
	}); err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.Accounts().GetByID(ctx, account.ID)
	if err != nil || stored.Username != account.Username {
		t.Fatalf("display username = %+v, %v", stored, err)
	}
	if err := f.db.Model(&models.Account{}).Where("id = ?", account.ID).Update("username", "Renamed Display").Error; err != nil {
		t.Fatal(err)
	}
	if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
		if err := repos.Blacklist().CheckAccount(ctx, account.ID); err != nil {
			return err
		}
		return repos.Accounts().SetPasswordHash(ctx, account.ID, credential.Identifier, "updated-hash")
	}); err != nil {
		t.Fatalf("reset after changing display username = %v", err)
	}
	err = f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
		if err := repos.Blacklist().CheckAccount(ctx, account.ID); err != nil {
			return err
		}
		return repos.Accounts().SetPasswordHash(ctx, account.ID, "renamed-login", "rejected-hash")
	})
	if !errors.Is(err, authkit.ErrConflict) {
		t.Fatalf("changing password identifier = %v", err)
	}
	hash, err := f.store.Accounts().GetPasswordHash(ctx, account.ID)
	if err != nil || hash != "updated-hash" {
		t.Fatalf("password hash = %q, %v", hash, err)
	}
	stored, err = f.store.Accounts().GetByID(ctx, account.ID)
	if err != nil || stored.Username != "Renamed Display" {
		t.Fatalf("renamed display username = %+v, %v", stored, err)
	}
}

func TestPasswordDisplayUsernameNotUnique(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	for _, identifier := range []string{"alice", "bob"} {
		account := authkit.Account{ID: identifier, Username: "Same Display"}
		if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
			return repos.Accounts().Create(ctx, &account, authkit.Credential{
				Method: authkit.MethodPassword, Identifier: identifier,
			})
		}); err != nil {
			t.Fatalf("create %s with repeated display username = %v", identifier, err)
		}
	}
	err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
		return repos.Accounts().Create(ctx, &authkit.Account{ID: "conflict", Username: "Other Display"}, authkit.Credential{
			Method: authkit.MethodPassword, Identifier: "alice",
		})
	})
	if !errors.Is(err, authkit.ErrConflict) {
		t.Fatalf("duplicate password identifier = %v", err)
	}
	requireRows(t, f.db, &models.Account{}, 2)
	requireRows(t, f.db, &models.Binding{}, 2)
}

func TestPasswordLookupUsesBindingIdentifier(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	for _, account := range []authkit.Account{
		{ID: "first", Username: "alice"},
		{ID: "second", Username: "Other Display"},
	} {
		identifier := "first-login"
		if account.ID == "second" {
			identifier = "alice"
		}
		if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
			return repos.Accounts().Create(ctx, &account, authkit.Credential{
				Method: authkit.MethodPassword, Identifier: identifier,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	secondID := "second"
	if err := f.db.Create(&models.Binding{
		Method: authkit.MethodEmail, Identifier: "user@example.com", AccountID: &secondID,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&models.Binding{Method: authkit.MethodPassword, Identifier: "unowned"}).Error; err != nil {
		t.Fatal(err)
	}
	account, err := f.store.Accounts().GetByPasswordIdentifier(ctx, "alice")
	if err != nil || account.ID != secondID || account.Username != "Other Display" || account.Email != "user@example.com" {
		t.Fatalf("password identifier lookup = %+v, %v", account, err)
	}
	identifier, err := f.store.Accounts().GetPasswordIdentifier(ctx, secondID)
	if err != nil || identifier != "alice" {
		t.Fatalf("account password identifier = %q, %v", identifier, err)
	}
	for _, identifier := range []string{"Alice", "Other Display", "missing", "unowned"} {
		if _, err := f.store.Accounts().GetByPasswordIdentifier(ctx, identifier); !errors.Is(err, authkit.ErrNotFound) {
			t.Fatalf("lookup %q = %v", identifier, err)
		}
	}
	if _, err := f.store.Accounts().GetPasswordIdentifier(ctx, "missing"); !errors.Is(err, authkit.ErrNotFound) {
		t.Fatalf("missing account password identifier = %v", err)
	}
	requireRows(t, f.db, &models.Binding{}, 4)
}

func TestPasswordServiceAfterDisplayUsernameChange(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	service, err := authkit.NewService(f.store, nil, nil,
		authkit.RegistrationPolicyFunc(func(context.Context, authkit.Registration) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	account, err := service.CreatePasswordAccount(ctx, authkit.CreatePasswordAccountInput{
		Username: "display-name", Identifier: "alice", Password: "initial-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(&models.Account{}).Where("id = ?", account.ID).Update("username", "changed-display").Error; err != nil {
		t.Fatal(err)
	}
	login, err := service.LoginPassword(ctx, authkit.PasswordLoginInput{Identifier: "alice", Password: "initial-password"})
	if err != nil || login.Account.ID != account.ID || login.Account.Username != "changed-display" {
		t.Fatalf("login after changing display username = %+v, %v", login, err)
	}
	for _, display := range []string{"display-name", "changed-display"} {
		if _, err := service.LoginPassword(ctx, authkit.PasswordLoginInput{
			Identifier: display, Password: "initial-password",
		}); !errors.Is(err, authkit.ErrInvalidCredentials) {
			t.Fatalf("display username %q login = %v", display, err)
		}
	}
	if err := service.SetPassword(ctx, authkit.SetPasswordInput{AccountID: account.ID, Password: "updated-password"}); err != nil {
		t.Fatalf("reset after changing display username = %v", err)
	}
	if _, err := service.Authenticate(ctx, login.Token); !errors.Is(err, authkit.ErrUnauthorized) {
		t.Fatalf("session after resetting password = %v", err)
	}
	if _, err := service.LoginPassword(ctx, authkit.PasswordLoginInput{Identifier: "alice", Password: "initial-password"}); !errors.Is(err, authkit.ErrInvalidCredentials) {
		t.Fatalf("old password after reset = %v", err)
	}
	if _, err := service.LoginPassword(ctx, authkit.PasswordLoginInput{Identifier: "alice", Password: "updated-password"}); err != nil {
		t.Fatalf("updated password login = %v", err)
	}
}

func TestPasswordBlacklistUsesBinding(t *testing.T) {
	for _, identifier := range []string{"alice", "display-name"} {
		t.Run(identifier, func(t *testing.T) {
			f := newMySQLFixture(t)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Microsecond)
			account := authkit.Account{ID: "account", Username: "display-name"}
			credential := authkit.Credential{Method: authkit.MethodPassword, Identifier: "alice"}
			if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
				if err := repos.Accounts().Create(ctx, &account, credential); err != nil {
					return err
				}
				return repos.Sessions().Create(ctx, &authkit.Session{
					Hash: "session", AccountID: account.ID, Expires: now.Add(time.Hour),
				})
			}); err != nil {
				t.Fatal(err)
			}
			entry := testBlacklistEntry(authkit.Credential{Method: authkit.MethodPassword, Identifier: identifier}, now)
			if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
				return repos.Blacklist().Add(ctx, entry)
			}); err != nil {
				t.Fatal(err)
			}
			err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
				return repos.Blacklist().CheckAccount(ctx, account.ID)
			})
			if identifier == credential.Identifier {
				requireRows(t, f.db, &models.Session{}, 0)
				if !errors.Is(err, authkit.ErrBlacklisted) {
					t.Fatalf("blocked password binding = %v", err)
				}
			} else {
				requireRows(t, f.db, &models.Session{}, 1)
				if err != nil {
					t.Fatalf("display username affected blacklist = %v", err)
				}
			}
		})
	}
}
