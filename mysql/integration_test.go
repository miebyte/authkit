package authmysql_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	driver "github.com/go-sql-driver/mysql"
	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql"
	"github.com/miebyte/authkit/mysql/models"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testDatabase creates a unique disposable database, regardless of the DSN database.
func testDatabase(t *testing.T) (*gorm.DB, *authmysql.Store) {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set AUTHKIT_MYSQL_DSN to run isolated MySQL integration tests")
	}
	cfg, err := driver.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DBName, cfg.ParseTime, cfg.Loc = "", true, time.UTC
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	id := make([]byte, 10)
	if _, err = rand.Read(id); err != nil {
		t.Fatal(err)
	}
	name := "authkit_test_" + hex.EncodeToString(id)
	// Database DDL is intentionally explicit; tests never drop a caller's database.
	if _, err = admin.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE `" + name + "`"); err != nil {
			t.Error(err)
		}
	})
	cfg.DBName = name
	db, err := gorm.Open(gormmysql.Open(cfg.FormatDSN()), &gorm.Config{
		Logger:                                   logger.Default.LogMode(logger.Silent),
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(20)
	t.Cleanup(func() { _ = pool.Close() })
	store, err := authmysql.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if db.Migrator().HasTable(&models.User{}) {
		t.Fatal("NewStore unexpectedly migrated the schema")
	}
	if err = db.AutoMigrate(authmysql.Models()...); err != nil {
		t.Fatal(err)
	}
	return db, store
}

// memorySender captures codes only inside the test process.
type memorySender struct {
	mu    sync.Mutex
	codes map[string]string
}

// SendCode records the latest delivered challenge for the test mailbox.
func (m *memorySender) SendCode(_ context.Context, email, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.codes == nil {
		m.codes = make(map[string]string)
	}
	m.codes[email] = code
	return nil
}

// code returns the latest code delivered to an address.
func (m *memorySender) code(email string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.codes[email]
}

// testWechat returns a stable identity for each test code without network calls.
type testWechat struct{}

// ExchangeCode converts a test login code to an application-scoped identity.
func (testWechat) ExchangeCode(_ context.Context, code string) (authkit.WechatIdentity, error) {
	return authkit.WechatIdentity{AppID: "test-app", OpenID: code}, nil
}

// allowRegistration explicitly enables registration for isolated test fixtures.
func allowRegistration(context.Context, authkit.Registration) error { return nil }

// newService assembles real MySQL repositories with test delivery providers.
func newService(
	t *testing.T,
	store *authmysql.Store,
	sender *memorySender,
	policy authkit.RegistrationPolicy,
) *authkit.Service {
	t.Helper()
	svc, err := authkit.NewService(store, sender, testWechat{}, policy)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// countRows reads exact persisted counts for transaction assertions.
func countRows(t *testing.T, db *gorm.DB, model any) int64 {
	t.Helper()
	var count int64
	if err := db.Model(model).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}

// TestNewStoreRejectsMissingConnection verifies setup fails before any operation.
func TestNewStoreRejectsMissingConnection(t *testing.T) {
	if _, err := authmysql.NewStore(nil); !errors.Is(err, authkit.ErrInvalidInput) {
		t.Fatalf("got %v", err)
	}
}

// TestConcurrentSendCodeSameMailbox verifies issuance locks one mailbox at a time.
func TestConcurrentSendCodeSameMailbox(t *testing.T) {
	db, store := testDatabase(t)
	svc := newService(t, store, &memorySender{}, nil)
	const email = "concurrent@example.com"
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			results <- svc.SendCode(context.Background(), authkit.SendCodeInput{
				Email: email, IP: "127.0.0.1",
			})
		}()
	}
	close(start)
	var succeeded, tooSoon int
	for i := 0; i < 2; i++ {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, authkit.ErrResendTooSoon):
			tooSoon++
		default:
			t.Errorf("unexpected send error: %v", err)
		}
	}
	if succeeded != 1 || tooSoon != 1 {
		t.Fatalf("succeeded=%d tooSoon=%d", succeeded, tooSoon)
	}
	var challenge models.Challenge
	if err := db.Where("email = ?", email).Take(&challenge).Error; err != nil {
		t.Fatal(err)
	}
	if countRows(t, db, &models.Challenge{}) != 1 || !challenge.Ready {
		t.Fatal("expected one ready challenge")
	}
}

// TestConcurrentWechatRegistration verifies exclusive identity creation and sessions.
func TestConcurrentWechatRegistration(t *testing.T) {
	db, store := testDatabase(t)
	var authorized atomic.Int32
	svc := newService(
		t,
		store,
		&memorySender{},
		authkit.RegistrationPolicyFunc(func(context.Context, authkit.Registration) error {
			authorized.Add(1)
			return nil
		}),
	)
	const workers = 12
	results := make(chan *authkit.LoginResult, workers)
	errorsCh := make(chan error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := svc.LoginWechat(
				context.Background(),
				"same-openid",
				authkit.WechatLoginInput{},
			)
			if err != nil {
				errorsCh <- err
				return
			}
			results <- result
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	var userID string
	var created int
	tokens := map[string]bool{}
	for result := range results {
		if userID == "" {
			userID = result.User.ID
		}
		if result.User.ID != userID {
			t.Error("concurrent registration created separate accounts")
		}
		if result.Created {
			created++
		}
		if tokens[result.Token] {
			t.Error("session token was reused")
		}
		tokens[result.Token] = true
		if _, err := svc.Authenticate(context.Background(), result.Token); err != nil {
			t.Error(err)
		}
	}
	if len(tokens) != workers || created != 1 || authorized.Load() != 1 {
		t.Fatalf("sessions=%d created=%d authorized=%d", len(tokens), created, authorized.Load())
	}
	if countRows(t, db, &models.User{}) != 1 || countRows(t, db, &models.WechatAccount{}) != 1 ||
		countRows(t, db, &models.Session{}) != workers {
		t.Fatal("unexpected persisted identity/session counts")
	}
	var sessions []models.Session
	if err := db.Find(&sessions).Error; err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		if tokens[session.Hash] || len(session.Hash) != 64 {
			t.Fatal("session credential was not persisted as a digest")
		}
	}
}

// TestUniqueBindings verifies nullable emails and both directions of uniqueness.
func TestUniqueBindings(t *testing.T) {
	db, store := testDatabase(t)
	ctx := context.Background()
	if err := store.WithTransaction(ctx, func(r authkit.Repositories) error {
		for _, id := range []string{"one", "two"} {
			if err := r.Users().Create(ctx, &authkit.User{ID: id}); err != nil {
				return err
			}
		}
		if _, err := r.Users().
			GetByWechat(ctx, "app-one", strings.Repeat("a", 64)); !errors.Is(
			err,
			authkit.ErrNotFound,
		) {
			return err
		}
		return r.Users().BindWechat(ctx, "app-one", strings.Repeat("a", 64), "one")
	}); err != nil {
		t.Fatal(err)
	}
	if countRows(t, db, &models.User{}) != 2 {
		t.Fatal("nullable email prevented separate WeChat accounts")
	}
	err := store.WithTransaction(ctx, func(r authkit.Repositories) error {
		if _, err := r.Users().
			GetByWechat(ctx, "app-one", strings.Repeat("b", 64)); !errors.Is(
			err,
			authkit.ErrNotFound,
		) {
			return err
		}
		return r.Users().BindWechat(ctx, "app-one", strings.Repeat("b", 64), "one")
	})
	if !errors.Is(err, authkit.ErrWechatBound) {
		t.Fatalf("duplicate application binding: %v", err)
	}
	err = store.WithTransaction(ctx, func(r authkit.Repositories) error {
		return r.Users().BindWechat(ctx, "app-one", strings.Repeat("a", 64), "two")
	})
	if !errors.Is(err, authkit.ErrWechatBound) {
		t.Fatalf("identity reassignment: %v", err)
	}
	if err := store.WithTransaction(ctx, func(r authkit.Repositories) error {
		if _, err := r.Users().
			GetByWechat(ctx, "app-two", strings.Repeat("b", 64)); !errors.Is(
			err,
			authkit.ErrNotFound,
		) {
			return err
		}
		return r.Users().BindWechat(ctx, "app-two", strings.Repeat("b", 64), "one")
	}); err != nil {
		t.Fatalf("same account in different application: %v", err)
	}
	if err := store.WithTransaction(
		ctx,
		func(r authkit.Repositories) error { return r.Users().BindEmail(ctx, "one", "unique@example.com") },
	); err != nil {
		t.Fatal(err)
	}
	err = store.WithTransaction(
		ctx,
		func(r authkit.Repositories) error { return r.Users().BindEmail(ctx, "two", "unique@example.com") },
	)
	if !errors.Is(err, authkit.ErrEmailAccountConflict) {
		t.Fatalf("email uniqueness: %v", err)
	}
}

// hostAdmission represents a business write performed by a host admission policy.
type hostAdmission struct {
	ID string `gorm:"primaryKey"`
}

// TestHostTransactionRollback verifies host and authkit writes share one commit.
func TestHostTransactionRollback(t *testing.T) {
	db, store := testDatabase(t)
	if err := db.AutoMigrate(&hostAdmission{}); err != nil {
		t.Fatal(err)
	}
	svc := newService(t, store, &memorySender{}, nil)
	ctx := context.Background()
	subject, err := svc.ExchangeWechat(ctx, "host-rollback-openid")
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("host membership write failed")
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		policy := authkit.RegistrationPolicyFunc(
			func(ctx context.Context, registration authkit.Registration) error {
				return tx.WithContext(ctx).Create(&hostAdmission{ID: registration.User.ID}).Error
			},
		)
		outcome, err := svc.InTransaction(authmysql.Bind(tx), policy).
			LoginWechat(ctx, subject, authkit.WechatLoginInput{})
		if err != nil {
			return err
		}
		if outcome.Rejected != nil {
			t.Fatalf("unexpected rejection: %v", outcome.Rejected)
		}
		if outcome.Login == nil {
			t.Fatal("missing provisional login")
		}
		return failure
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if !errors.Is(err, failure) {
		t.Fatalf("got %v", err)
	}
	for _, model := range []any{&models.User{}, &models.WechatAccount{}, &models.Session{}, &hostAdmission{}} {
		if countRows(t, db, model) != 0 {
			t.Fatalf("rollback left persisted %T", model)
		}
	}
}

// TestWrongCodeCommitsAttempts verifies both owned and host transactions reject durably.
func TestWrongCodeCommitsAttempts(t *testing.T) {
	db, store := testDatabase(t)
	sender := &memorySender{}
	svc := newService(t, store, sender, authkit.RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	email := "attempts@example.com"
	if err := svc.SendCode(
		ctx,
		authkit.SendCodeInput{Email: email, IP: "127.0.0.1", RegistrationRef: "host-ref:中文"},
	); err != nil {
		t.Fatal(err)
	}
	wrong := "000000"
	if sender.code(email) == wrong {
		wrong = "000001"
	}
	if _, err := svc.LoginEmail(
		ctx,
		authkit.EmailLoginInput{Email: email, Code: wrong},
	); !errors.Is(
		err,
		authkit.ErrChallengeMismatch,
	) {
		t.Fatalf("got %v", err)
	}
	var rejection error
	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		outcome, err := svc.InTransaction(authmysql.Bind(tx), nil).
			LoginEmail(ctx, authkit.EmailLoginInput{Email: email, Code: wrong})
		rejection = outcome.Rejected
		return err
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(rejection, authkit.ErrChallengeMismatch) {
		t.Fatalf("got %v", rejection)
	}
	var challenge models.Challenge
	if err := db.First(&challenge, "email = ?", email).Error; err != nil {
		t.Fatal(err)
	}
	if challenge.Attempts != 2 || !challenge.Ready || challenge.RegistrationRef != "host-ref:中文" {
		t.Fatalf("unexpected challenge: attempts=%d ready=%t", challenge.Attempts, challenge.Ready)
	}
	denied := newService(t, store, sender, nil)
	if _, err := denied.LoginEmail(
		ctx,
		authkit.EmailLoginInput{Email: email, Code: sender.code(email)},
	); !errors.Is(
		err,
		authkit.ErrRegistrationDenied,
	) {
		t.Fatalf("got %v", err)
	}
	if err := db.First(&challenge, "email = ?", email).Error; err != nil {
		t.Fatal(err)
	}
	if !challenge.Ready || challenge.Attempts != 2 {
		t.Fatal("admission failure consumed the challenge")
	}
	login, err := svc.LoginEmail(
		ctx,
		authkit.EmailLoginInput{Email: email, Code: sender.code(email)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LoginEmail(
		ctx,
		authkit.EmailLoginInput{Email: email, Code: sender.code(email)},
	); !errors.Is(
		err,
		authkit.ErrChallengeInvalid,
	) {
		t.Fatalf("code reuse: %v", err)
	}
	if err := svc.Logout(ctx, login.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, login.Token); !errors.Is(err, authkit.ErrUnauthorized) {
		t.Fatalf("logout: %v", err)
	}
}

// TestConcurrentRateLimit verifies exact limits without lost increments or lock upgrades.
func TestConcurrentRateLimit(t *testing.T) {
	_, store := testDatabase(t)
	const workers, limit = 20, 7
	var accepted atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	now := time.Now().UTC()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := store.WithTransaction(context.Background(), func(r authkit.Repositories) error {
				return r.Rates().Hit(context.Background(), strings.Repeat("a", 64), now, limit)
			})
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, authkit.ErrTooManyRequests) {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if accepted.Load() != limit {
		t.Fatalf("accepted=%d, want=%d", accepted.Load(), limit)
	}
	if err := store.WithTransaction(context.Background(), func(r authkit.Repositories) error {
		return r.Rates().
			Hit(context.Background(), strings.Repeat("a", 64), now.Add(time.Hour), limit)
	}); err != nil {
		t.Fatalf("hourly reset: %v", err)
	}
}

// TestSessionExpirationAndChallengeZeroValues verifies precision and explicit zero writes.
func TestSessionExpirationAndChallengeZeroValues(t *testing.T) {
	_, store := testDatabase(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	hash := strings.Repeat("f", 64)
	if err := store.WithTransaction(ctx, func(r authkit.Repositories) error {
		if err := r.Users().Create(ctx, &authkit.User{ID: "expiry-user"}); err != nil {
			return err
		}
		if err := r.Sessions().
			Create(ctx, &authkit.Session{Hash: hash, UserID: "expiry-user", Expires: now}); err != nil {
			return err
		}
		challenge, err := r.Challenges().Get(ctx, "zero@example.com")
		if err != nil {
			return err
		}
		challenge.Hash, challenge.RegistrationRef, challenge.Attempts, challenge.Ready = hash, "ref", 4, true
		if err := r.Challenges().Save(ctx, challenge); err != nil {
			return err
		}
		challenge.Hash, challenge.RegistrationRef, challenge.Attempts, challenge.Ready = "", "", 0, false
		return r.Challenges().Save(ctx, challenge)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Users().
		GetBySessionToken(ctx, hash, now.Add(-time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Users().
		GetBySessionToken(ctx, hash, now); !errors.Is(
		err,
		authkit.ErrNotFound,
	) {
		t.Fatalf("expiry boundary: %v", err)
	}
	if err := store.WithTransaction(ctx, func(r authkit.Repositories) error {
		challenge, err := r.Challenges().Get(ctx, "zero@example.com")
		if err != nil {
			return err
		}
		if challenge.Hash != "" || challenge.RegistrationRef != "" || challenge.Attempts != 0 ||
			challenge.Ready {
			t.Fatal("challenge failed to persist false/zero/empty values")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestMailboxCollationPreventsCrossAccountLogin keeps accent-distinct inboxes separate.
func TestMailboxCollationPreventsCrossAccountLogin(t *testing.T) {
	db, store := testDatabase(t)
	sender := &memorySender{}
	svc := newService(t, store, sender, authkit.RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	var accounts []string
	for _, email := range []string{"elise@example.com", "élise@example.com"} {
		if err := svc.SendCode(
			ctx,
			authkit.SendCodeInput{Email: email, IP: "127.0.0.1"},
		); err != nil {
			t.Fatal(err)
		}
		login, err := svc.LoginEmail(
			ctx,
			authkit.EmailLoginInput{Email: email, Code: sender.code(email)},
		)
		if err != nil {
			t.Fatal(err)
		}
		if !login.Created || login.User.Email != email {
			t.Fatal("mailbox resolved to an existing different account")
		}
		accounts = append(accounts, login.User.ID)
	}
	if accounts[0] == accounts[1] || countRows(t, db, &models.User{}) != 2 ||
		countRows(t, db, &models.Challenge{}) != 2 {
		t.Fatal("accent-distinct inboxes shared a challenge or account")
	}
	// App IDs and user IDs are also exact identifiers, independent of host collation.
	if err := store.WithTransaction(ctx, func(r authkit.Repositories) error {
		for _, id := range []string{"CaseID", "caseid"} {
			if err := r.Users().Create(ctx, &authkit.User{ID: id}); err != nil {
				return err
			}
		}
		for _, app := range []string{"CaseApp", "caseapp"} {
			if _, err := r.Users().
				GetByWechat(ctx, app, strings.Repeat("c", 64)); !errors.Is(
				err,
				authkit.ErrNotFound,
			) {
				return err
			}
			if err := r.Users().
				BindWechat(ctx, app, strings.Repeat("c", 64), "CaseID"); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("exact identifier columns: %v", err)
	}
	if countRows(t, db, &models.WechatAccount{}) != 2 {
		t.Fatal("application IDs compared case-insensitively")
	}
}

// TestUnknownMailboxVerificationDoesNotAllocateRows keeps login misses read-only.
func TestUnknownMailboxVerificationDoesNotAllocateRows(t *testing.T) {
	db, store := testDatabase(t)
	svc := newService(t, store, &memorySender{}, authkit.RegistrationPolicyFunc(allowRegistration))
	_, err := svc.LoginEmail(
		context.Background(),
		authkit.EmailLoginInput{Email: "unknown@example.com", Code: "123456"},
	)
	if !errors.Is(err, authkit.ErrChallengeInvalid) {
		t.Fatalf("got %v", err)
	}
	if countRows(t, db, &models.Challenge{}) != 0 {
		t.Fatal("invalid login allocated a challenge row")
	}
}
