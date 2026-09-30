package authmysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	driver "github.com/go-sql-driver/mysql"
	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// mysqlFixture 为真实 MySQL 测试创建独立数据库，结束时删除。
type mysqlFixture struct {
	db    *gorm.DB
	store *Store
}

func newMySQLFixture(t *testing.T) mysqlFixture {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_MYSQL_DSN")
	if dsn == "" {
		t.Skip("AUTHKIT_MYSQL_DSN is not set")
	}
	config, err := driver.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.DBName, config.ParseTime, config.Loc = "", true, time.UTC
	admin, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	database := fmt.Sprintf("authkit_blacklist_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE DATABASE `" + database + "`"); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE `" + database + "`"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	config.DBName = database
	conn, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	db, err := gorm.Open(gormmysql.New(gormmysql.Config{Conn: conn}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(Models()...); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return mysqlFixture{db: db, store: store}
}

func testBlacklistEntry(credential authkit.Credential, now time.Time) authkit.BlacklistEntry {
	return authkit.BlacklistEntry{
		ID: blacklistID(credential), Method: credential.Method,
		Identifier: credential.Identifier, CreatedAt: now,
	}
}

func requireRows(t *testing.T, db *gorm.DB, model any, want int64) {
	t.Helper()
	var count int64
	if err := db.Model(model).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%T rows = %d, want %d", model, count, want)
	}
}

// blacklistMail 保存端到端测试发出的验证码。
type blacklistMail struct{ code string }

func (m *blacklistMail) SendCode(_ context.Context, _, code string) error {
	m.code = code
	return nil
}

// blacklistWechat 在端到端测试中返回固定的服务端已验证身份。
type blacklistWechat struct{ openID string }

func (w blacklistWechat) ExchangeCode(context.Context, string) (authkit.WechatIdentity, error) {
	return authkit.WechatIdentity{AppID: "test-app", OpenID: w.openID}, nil
}

func TestBlacklistServiceLifecycle(t *testing.T) {
	for _, credential := range []authkit.Credential{
		{Method: authkit.MethodEmail, Identifier: " USER@Example.com "},
		{Method: authkit.MethodWechat, Identifier: "wechat-open-id"},
	} {
		t.Run(credential.Method, func(t *testing.T) {
			f := newMySQLFixture(t)
			ctx := context.Background()
			mail := &blacklistMail{}
			service, err := authkit.NewService(f.store, mail, blacklistWechat{openID: credential.Identifier},
				authkit.RegistrationPolicyFunc(func(context.Context, authkit.Registration) error { return nil }))
			if err != nil {
				t.Fatal(err)
			}
			if credential.Method == authkit.MethodEmail {
				if _, err := service.LoginEmail(ctx, authkit.EmailLoginInput{
					Email: credential.Identifier, Code: "123456",
				}); !errors.Is(err, authkit.ErrChallengeInvalid) {
					t.Fatalf("unknown email login = %v", err)
				}
				requireRows(t, f.db, &models.Blacklist{}, 0)
				requireRows(t, f.db, &models.Challenge{}, 0)
			}
			login := func(sendCode bool) (*authkit.LoginResult, error) {
				if credential.Method == authkit.MethodWechat {
					return service.LoginWechat(ctx, "wechat-login-code")
				}
				if sendCode {
					if err := service.SendCode(ctx, authkit.SendCodeInput{Email: credential.Identifier, IP: "192.0.2.1"}); err != nil {
						return nil, err
					}
				}
				return service.LoginEmail(ctx, authkit.EmailLoginInput{Email: credential.Identifier, Code: mail.code})
			}
			first, err := login(true)
			if err != nil || !first.Created {
				t.Fatalf("initial registration = %+v, %v", first, err)
			}
			if account, err := service.Authenticate(ctx, first.Token); err != nil || account.ID != first.Account.ID {
				t.Fatalf("initial authenticate = %+v, %v", account, err)
			}
			if err := service.AddBlacklist(ctx, credential); err != nil {
				t.Fatal(err)
			}
			if _, err := service.Authenticate(ctx, first.Token); !errors.Is(err, authkit.ErrUnauthorized) {
				t.Fatalf("blocked token = %v", err)
			}
			if _, err := login(false); !errors.Is(err, authkit.ErrBlacklisted) {
				t.Fatalf("blocked login = %v", err)
			}
			if credential.Method == authkit.MethodEmail {
				if err := service.SendCode(ctx, authkit.SendCodeInput{Email: credential.Identifier}); !errors.Is(err, authkit.ErrBlacklisted) {
					t.Fatalf("blocked code delivery = %v", err)
				}
			}
			page, err := service.ListBlacklist(ctx, 1, 10)
			if err != nil || page.Total != 1 || len(page.Items) != 1 {
				t.Fatalf("service list = %+v, %v", page, err)
			}
			if credential.Method == authkit.MethodEmail && page.Items[0].Identifier != "user@example.com" {
				t.Fatalf("stored email = %q", page.Items[0].Identifier)
			}
			if credential.Method == authkit.MethodWechat && page.Items[0].Identifier != "" {
				t.Fatal("service list exposed OpenID")
			}
			if err := service.RemoveBlacklist(ctx, page.Items[0].ID); err != nil {
				t.Fatal(err)
			}
			if _, err := service.Authenticate(ctx, first.Token); !errors.Is(err, authkit.ErrUnauthorized) {
				t.Fatalf("old token after removal = %v", err)
			}
			second, err := login(true)
			if err != nil || second.Created || second.Account.ID != first.Account.ID || second.Token == first.Token {
				t.Fatalf("login after removal = %+v, %v", second, err)
			}
			if account, err := service.Authenticate(ctx, second.Token); err != nil || account.ID != first.Account.ID {
				t.Fatalf("new token after removal = %+v, %v", account, err)
			}
		})
	}
}

func TestBlacklistPersistsCleanupAndRemoval(t *testing.T) {
	for _, method := range []string{authkit.MethodEmail, authkit.MethodWechat} {
		t.Run(method, func(t *testing.T) {
			f := newMySQLFixture(t)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Microsecond)
			credential := authkit.Credential{Method: method, Identifier: "user@example.com"}
			if method == authkit.MethodWechat {
				credential.Identifier = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
			entry := testBlacklistEntry(credential, now)
			account := authkit.Account{ID: "account"}
			if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
				if err := repos.Blacklist().Check(ctx, credential); err != nil {
					return err
				}
				if err := repos.Accounts().Create(ctx, &account, credential); err != nil {
					return err
				}
				return repos.Sessions().Create(ctx, &authkit.Session{Hash: "session", AccountID: account.ID, Expires: now.Add(time.Hour)})
			}); err != nil {
				t.Fatal(err)
			}
			if method == authkit.MethodEmail {
				if err := f.db.Create(&models.Challenge{Email: credential.Identifier, Hash: "code", Sent: now, Expires: now.Add(time.Minute), Ready: true}).Error; err != nil {
					t.Fatal(err)
				}
			}
			page, err := f.store.Blacklist().List(ctx, 1, 10)
			if err != nil || page.Total != 0 || len(page.Items) != 0 {
				t.Fatalf("placeholder list = %+v, %v", page, err)
			}
			for range 2 {
				if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
					return repos.Blacklist().Add(ctx, entry)
				}); err != nil {
					t.Fatal(err)
				}
			}
			requireRows(t, f.db, &models.Challenge{}, 0)
			requireRows(t, f.db, &models.Session{}, 0)
			err = f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
				return repos.Blacklist().Check(ctx, credential)
			})
			if !errors.Is(err, authkit.ErrBlacklisted) {
				t.Fatalf("blocked credential check = %v", err)
			}
			if err := f.store.Blacklist().CheckAccount(ctx, account.ID); !errors.Is(err, authkit.ErrBlacklisted) {
				t.Fatalf("blocked account check = %v", err)
			}
			page, err = f.store.Blacklist().List(ctx, 1, 10)
			if err != nil || page.Total != 1 || len(page.Items) != 1 || !page.Items[0].CreatedAt.Equal(now) {
				t.Fatalf("blocked list = %+v, %v", page, err)
			}
			if method == authkit.MethodWechat && page.Items[0].Identifier != "" {
				t.Fatal("blacklist list exposed OpenID hash")
			}
			if method == authkit.MethodEmail && page.Items[0].Identifier != credential.Identifier {
				t.Fatal("blacklist list lost the normalized email")
			}
			for range 2 {
				if err := f.store.Blacklist().Remove(ctx, entry.ID); err != nil {
					t.Fatal(err)
				}
			}
			requireRows(t, f.db, &models.Blacklist{}, 1)
			requireRows(t, f.db, &models.Session{}, 0)
			requireRows(t, f.db, &models.Challenge{}, 0)
			if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
				return repos.Blacklist().Check(ctx, credential)
			}); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Blacklist().CheckAccount(ctx, account.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBlacklistRollbackAndPagination(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	credentials := []authkit.Credential{
		{Method: authkit.MethodEmail, Identifier: "first@example.com"},
		{Method: authkit.MethodEmail, Identifier: "second@example.com"},
		{Method: authkit.MethodEmail, Identifier: "third@example.com"},
	}
	rollback := errors.New("rollback")
	err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
		if err := repos.Blacklist().Add(ctx, testBlacklistEntry(credentials[0], now)); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("rollback = %v", err)
	}
	requireRows(t, f.db, &models.Blacklist{}, 0)
	for _, credential := range credentials {
		if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
			return repos.Blacklist().Add(ctx, testBlacklistEntry(credential, now))
		}); err != nil {
			t.Fatal(err)
		}
	}
	var lastID string
	for pageNumber := 1; pageNumber <= len(credentials); pageNumber++ {
		page, err := f.store.Blacklist().List(ctx, pageNumber, 1)
		if err != nil || page.Total != 3 || len(page.Items) != 1 || page.Page != pageNumber || page.Limit != 1 {
			t.Fatalf("page %d = %+v, %v", pageNumber, page, err)
		}
		if page.Items[0].ID <= lastID {
			t.Fatalf("unstable tie ordering: %q after %q", page.Items[0].ID, lastID)
		}
		lastID = page.Items[0].ID
	}
	for _, input := range [][2]int{{0, 1}, {1, 0}, {int(^uint(0) >> 1), 2}} {
		if _, err := f.store.Blacklist().List(ctx, input[0], input[1]); !errors.Is(err, authkit.ErrInvalidInput) {
			t.Fatalf("invalid pagination %v = %v", input, err)
		}
	}
}

func TestBlacklistSerializesSessionIssuance(t *testing.T) {
	for _, sibling := range []bool{false, true} {
		t.Run(fmt.Sprintf("sibling=%t", sibling), func(t *testing.T) {
			f := newMySQLFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			now := time.Now().UTC().Truncate(time.Microsecond)
			blocked := authkit.Credential{Method: authkit.MethodEmail, Identifier: "user@example.com"}
			login := blocked
			account := authkit.Account{ID: "account"}
			if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
				return repos.Accounts().Create(ctx, &account, blocked)
			}); err != nil {
				t.Fatal(err)
			}
			if sibling {
				login = authkit.Credential{Method: authkit.MethodWechat, Identifier: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
				if err := f.db.Create(&models.Binding{Method: login.Method, Identifier: login.Identifier, AccountID: &account.ID}).Error; err != nil {
					t.Fatal(err)
				}
			}
			checked := make(chan struct{})
			release := make(chan struct{})
			loginDone := make(chan error, 1)
			go func() {
				loginDone <- f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
					if err := repos.Blacklist().Check(ctx, login); err != nil {
						return err
					}
					if err := repos.Blacklist().CheckAccount(ctx, account.ID); err != nil {
						return err
					}
					close(checked)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					return repos.Sessions().Create(ctx, &authkit.Session{Hash: "racing_session", AccountID: account.ID, Expires: now.Add(time.Hour)})
				})
			}()
			select {
			case <-checked:
			case err := <-loginDone:
				t.Fatalf("session transaction failed before locking: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			addStarted := make(chan struct{})
			addDone := make(chan error, 1)
			entry := testBlacklistEntry(blocked, now)
			go func() {
				addDone <- f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
					close(addStarted)
					return repos.Blacklist().Add(ctx, entry)
				})
			}()
			<-addStarted
			select {
			case err := <-addDone:
				close(release)
				t.Fatalf("blacklist add completed before session transaction released its lock: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			if err := <-loginDone; err != nil {
				t.Fatal(err)
			}
			if err := <-addDone; err != nil {
				t.Fatal(err)
			}
			requireRows(t, f.db, &models.Session{}, 0)
			if err := f.store.Blacklist().Remove(ctx, entry.ID); err != nil {
				t.Fatal(err)
			}
			requireRows(t, f.db, &models.Session{}, 0)
		})
	}
}

func TestBlacklistDoesNotDeadlockBindingRemoval(t *testing.T) {
	f := newMySQLFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	credential := authkit.Credential{Method: authkit.MethodEmail, Identifier: "user@example.com"}
	account := authkit.Account{ID: "account"}
	if err := f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
		return repos.Accounts().Create(ctx, &account, credential)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&models.Binding{
		Method: authkit.MethodWechat, Identifier: "wechat-hash", AccountID: &account.ID,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&models.Challenge{
		Email: credential.Identifier, Hash: "code", Sent: now, Expires: now.Add(time.Minute), Ready: true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	remove := make(chan struct{})
	removeDone := make(chan error, 1)
	go func() {
		removeDone <- f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
			if err := repos.Blacklist().CheckAccount(ctx, account.ID); err != nil {
				return err
			}
			close(locked)
			select {
			case <-remove:
			case <-ctx.Done():
				return ctx.Err()
			}
			return repos.(*Store).AdminDeleteBinding(ctx, account.ID, authkit.MethodEmail)
		})
	}()
	select {
	case <-locked:
	case err := <-removeDone:
		t.Fatalf("removal transaction failed before locking account: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	addStarted := make(chan struct{})
	addDone := make(chan error, 1)
	go func() {
		addDone <- f.store.WithTransaction(ctx, func(repos authkit.Repositories) error {
			close(addStarted)
			return repos.Blacklist().Add(ctx, testBlacklistEntry(credential, now))
		})
	}()
	select {
	case <-addStarted:
	case err := <-addDone:
		t.Fatalf("blacklist transaction failed before adding entry: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-addDone:
		close(remove)
		t.Fatalf("blacklist add completed while account remained locked: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(remove)
	if err := <-removeDone; err != nil {
		t.Fatalf("binding removal deadlocked with blacklist add: %v", err)
	}
	if err := <-addDone; err != nil {
		t.Fatal(err)
	}
	requireRows(t, f.db, &models.Challenge{}, 0)
	requireRows(t, f.db, &models.Binding{}, 1)
}
