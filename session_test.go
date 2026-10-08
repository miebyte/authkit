package authkit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAuthenticateSessionReturnsLoginMethod(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	accountID := strings.Repeat("a", 64)
	f.store.bind(accountID, "user@example.com", f.wechat.identity.OpenID)
	if err := f.service.SetPassword(ctx, SetPasswordInput{
		AccountID: accountID, Identifier: "user@example.com", Password: "valid-password",
	}); err != nil {
		t.Fatal(err)
	}
	logins := make(map[string]*LoginResult)
	logins[MethodEmail] = f.loginEmail(t, "user@example.com")
	var err error
	logins[MethodWechat], err = f.service.LoginWechat(ctx, "provider-code")
	if err != nil {
		t.Fatal(err)
	}
	logins[MethodPassword], err = f.service.LoginPassword(ctx, PasswordLoginInput{
		Identifier: "user@example.com", Password: "valid-password", IP: "192.0.2.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	for method, login := range logins {
		t.Run(method, func(t *testing.T) {
			stored := f.store.sessions[digest(login.Token)]
			if stored.Method != method || stored.AccountID != accountID {
				t.Fatalf("stored session = %+v, want method %q", stored, method)
			}
			for name, authenticate := range map[string]func(context.Context, string) (*AuthenticatedSession, error){
				"service":     f.service.AuthenticateSession,
				"transaction": f.service.InTransaction(f.store, nil).AuthenticateSession,
			} {
				t.Run(name, func(t *testing.T) {
					session, err := authenticate(ctx, login.Token)
					if err != nil || session.Method != method || session.Account.ID != accountID ||
						session.Actor != nil {
						t.Fatalf(
							"authenticated session = %+v, %v; want method %q",
							session,
							err,
							method,
						)
					}
				})
			}
		})
	}
}

func TestAuthenticateSessionKeepsLegacyMethodUnknown(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	login := f.loginEmail(t, "user@example.com")
	stored := f.store.sessions[digest(login.Token)]
	stored.Method = ""
	f.store.sessions[stored.Hash] = stored
	for name, authenticate := range map[string]func(context.Context, string) (*AuthenticatedSession, error){
		"service":     f.service.AuthenticateSession,
		"transaction": f.service.InTransaction(f.store, nil).AuthenticateSession,
	} {
		t.Run(name, func(t *testing.T) {
			session, err := authenticate(ctx, login.Token)
			if err != nil || session.Method != "" || session.Account.ID != login.Account.ID {
				t.Fatalf("legacy session = %+v, %v", session, err)
			}
		})
	}
}

func TestLoginAsInheritsParentLoginMethod(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	if _, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{
		Identifier: "admin", Password: "valid-password",
	}); err != nil {
		t.Fatal(err)
	}
	parent, err := f.service.LoginPassword(ctx, PasswordLoginInput{
		Identifier: "admin", Password: "valid-password", IP: "192.0.2.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	target := f.loginEmail(t, "target@example.com")
	child, err := f.service.LoginAs(ctx, parent.Token, target.Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored := f.store.sessions[digest(child.Token)]
	if stored.Method != MethodPassword {
		t.Fatalf("derived session method = %q, want %q", stored.Method, MethodPassword)
	}
	for name, authenticate := range map[string]func(context.Context, string) (*AuthenticatedSession, error){
		"service":     f.service.AuthenticateSession,
		"transaction": f.service.InTransaction(f.store, nil).AuthenticateSession,
	} {
		t.Run(name, func(t *testing.T) {
			session, err := authenticate(ctx, child.Token)
			if err != nil || session.Method != MethodPassword ||
				session.Account.ID != target.Account.ID ||
				session.Actor == nil ||
				session.Actor.ID != parent.Account.ID {
				t.Fatalf("derived session = %+v, %v", session, err)
			}
		})
	}
}

func TestLoginAsUsesRevocableSessionAndReturnsActor(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	parent := f.loginEmail(t, "admin@example.com")
	target := f.loginEmail(t, "target@example.com")
	f.now = f.now.Add(time.Hour)
	child, err := f.service.LoginAs(ctx, parent.Token, target.Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !validToken(child.Token) || child.Token == parent.Token || child.Created ||
		child.Account.ID != target.Account.ID {
		t.Fatalf("invalid derived login: %+v", child)
	}
	stored := f.store.sessions[digest(child.Token)]
	if stored.Hash == child.Token || stored.ParentHash != digest(parent.Token) ||
		stored.AccountID != target.Account.ID {
		t.Fatalf("stored session does not contain only token digests: %+v", stored)
	}
	if !child.Expires.Equal(parent.Expires) {
		t.Fatalf("derived expiry = %v, parent expiry = %v", child.Expires, parent.Expires)
	}
	if !parent.Expires.Equal(f.now.Add(-time.Hour).Add(SessionTTL)) {
		t.Fatal("ordinary session TTL changed")
	}
	session, err := f.service.AuthenticateSession(ctx, child.Token)
	if err != nil || session.Account.ID != target.Account.ID || session.Actor == nil ||
		session.Actor.ID != parent.Account.ID {
		t.Fatalf("derived session = %+v, err = %v", session, err)
	}
	ordinary, err := f.service.AuthenticateSession(ctx, parent.Token)
	if err != nil || ordinary.Actor != nil || ordinary.Account.ID != parent.Account.ID {
		t.Fatalf("ordinary session = %+v, err = %v", ordinary, err)
	}
	account, err := f.service.Authenticate(ctx, child.Token)
	if err != nil || account.ID != target.Account.ID {
		t.Fatalf("compatible Authenticate = %+v, err = %v", account, err)
	}
	if err := f.service.Logout(ctx, child.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Authenticate(ctx, child.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("logged out child = %v", err)
	}
	if _, err := f.service.Authenticate(ctx, parent.Token); err != nil {
		t.Fatalf("child logout revoked parent: %v", err)
	}
}

func TestLoginAsRejectsInvalidInputsAndNestedSessions(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	parent := f.loginEmail(t, "admin@example.com")
	target := f.loginEmail(t, "target@example.com")
	child, err := f.service.LoginAs(ctx, parent.Token, target.Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, token, target string
		want                error
	}{
		{"malformed parent", "not-a-token", target.Account.ID, ErrUnauthorized},
		{"missing parent", strings.Repeat("f", 64), target.Account.ID, ErrUnauthorized},
		{"malformed target", parent.Token, "not-an-account", ErrInvalidInput},
		{"missing target", parent.Token, strings.Repeat("f", 64), ErrNotFound},
		{"nested session", child.Token, parent.Account.ID, ErrUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := len(f.store.sessions)
			login, err := f.service.LoginAs(ctx, test.token, test.target)
			if !errors.Is(err, test.want) || login != nil || len(f.store.sessions) != before {
				t.Fatalf(
					"rejected login = %+v, %v; sessions = %d",
					login,
					err,
					len(f.store.sessions),
				)
			}
		})
	}
}

func TestDerivedSessionFollowsParentAndTargetRevocation(t *testing.T) {
	for _, test := range []struct {
		name   string
		revoke func(*blacklistFixture, *LoginResult, *LoginResult) error
	}{
		{"parent logout", func(f *blacklistFixture, parent, target *LoginResult) error {
			return f.service.Logout(context.Background(), parent.Token)
		}},
		{"parent expires", func(f *blacklistFixture, parent, target *LoginResult) error {
			stored := f.store.sessions[digest(parent.Token)]
			stored.Expires = f.now
			f.store.sessions[stored.Hash] = stored
			return nil
		}},
		{"parent password reset", func(f *blacklistFixture, parent, target *LoginResult) error {
			return f.service.SetPassword(context.Background(), SetPasswordInput{AccountID: parent.Account.ID, Identifier: parent.Account.Email, Password: "new-password"})
		}},
		{"target password reset", func(f *blacklistFixture, parent, target *LoginResult) error {
			return f.service.SetPassword(context.Background(), SetPasswordInput{AccountID: target.Account.ID, Identifier: target.Account.Email, Password: "new-password"})
		}},
		{"parent blacklisted", func(f *blacklistFixture, parent, target *LoginResult) error {
			return f.service.AddBlacklist(context.Background(), Credential{Method: MethodEmail, Identifier: parent.Account.Email})
		}},
		{"target blacklisted", func(f *blacklistFixture, parent, target *LoginResult) error {
			return f.service.AddBlacklist(context.Background(), Credential{Method: MethodEmail, Identifier: target.Account.Email})
		}},
		{"parent account removed", func(f *blacklistFixture, parent, target *LoginResult) error {
			delete(f.store.accounts, parent.Account.ID)
			return nil
		}},
		{"invalid nested parent in storage", func(f *blacklistFixture, parent, target *LoginResult) error {
			stored := f.store.sessions[digest(parent.Token)]
			stored.ParentHash = digest(target.Token)
			f.store.sessions[stored.Hash] = stored
			return nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newBlacklistFixture(t)
			ctx := context.Background()
			parent := f.loginEmail(t, "admin@example.com")
			target := f.loginEmail(t, "target@example.com")
			child, err := f.service.LoginAs(ctx, parent.Token, target.Account.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.revoke(f, parent, target); err != nil {
				t.Fatal(err)
			}
			if session, err := f.service.AuthenticateSession(
				ctx,
				child.Token,
			); err == nil ||
				session != nil {
				t.Fatalf("revoked derived session = %+v, %v", session, err)
			}
			if account, err := f.service.Authenticate(
				ctx,
				child.Token,
			); err == nil ||
				account != nil {
				t.Fatalf("Authenticate bypassed parent validation: %+v, %v", account, err)
			}
		})
	}
}

func TestLoginAsWithinHostTransactionRollsBack(t *testing.T) {
	f := newBlacklistFixture(t)
	ctx := context.Background()
	parent := f.loginEmail(t, "admin@example.com")
	target := f.loginEmail(t, "target@example.com")
	denied := errors.New("host authorization denied")
	var child *LoginResult
	err := f.store.WithTransaction(ctx, func(repos Repositories) error {
		tx := f.service.InTransaction(repos, nil)
		session, err := tx.AuthenticateSession(ctx, parent.Token)
		if err != nil || session.Account.ID != parent.Account.ID || session.Actor != nil {
			t.Fatalf("transaction authentication = %+v, %v", session, err)
		}
		child, err = tx.LoginAs(ctx, parent.Token, target.Account.ID)
		if err != nil {
			return err
		}
		return denied
	})
	if !errors.Is(err, denied) || child == nil {
		t.Fatalf("host transaction = %v, child = %+v", err, child)
	}
	if _, err := f.service.Authenticate(ctx, child.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("rollback retained child session: %v", err)
	}
	if len(f.store.sessions) != 2 {
		t.Fatalf("rollback changed original sessions: %d", len(f.store.sessions))
	}
}

func TestLoginAsRejectsExpiredParentAndBlacklistedTarget(t *testing.T) {
	for _, targetBlocked := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "expired parent", true: "blacklisted target"}[targetBlocked],
			func(t *testing.T) {
				f := newBlacklistFixture(t)
				ctx := context.Background()
				parent := f.loginEmail(t, "admin@example.com")
				target := f.loginEmail(t, "target@example.com")
				want := ErrUnauthorized
				if targetBlocked {
					if err := f.service.AddBlacklist(
						ctx,
						Credential{Method: MethodEmail, Identifier: target.Account.Email},
					); err != nil {
						t.Fatal(err)
					}
					want = ErrBlacklisted
				} else {
					f.now = parent.Expires
				}
				before := len(f.store.sessions)
				login, err := f.service.LoginAs(ctx, parent.Token, target.Account.ID)
				if !errors.Is(err, want) || login != nil || len(f.store.sessions) != before {
					t.Fatalf(
						"invalid login = %+v, %v; sessions = %d",
						login,
						err,
						len(f.store.sessions),
					)
				}
			},
		)
	}
}
