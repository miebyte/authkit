package authmysql_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	driver "github.com/go-sql-driver/mysql"
	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/email"
	emailmysql "github.com/miebyte/authkit/email/mysql"
	authmysql "github.com/miebyte/authkit/mysql"
	"github.com/miebyte/authkit/mysql/models"
	"github.com/miebyte/authkit/wechat"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testDatabase 为每个用例创建随机命名的临时数据库，并仅在其中迁移核心表。
// DSN 只用于连接同一 MySQL 实例；即使指定了库名，也不会删除或修改该原有数据库。
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
	// 只创建和清理本次生成的随机库；绝不删除 DSN 原有的数据库。
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

// countRows 在当前临时库中查询模型的持久化行数，供事务和唯一性断言使用。
func countRows(t *testing.T, db *gorm.DB, model any) int64 {
	t.Helper()
	var count int64
	if err := db.Model(model).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}

// allowRegistration 仅供测试显式放行新账号，不承担宿主业务准入逻辑。
func allowRegistration(context.Context, authkit.Registration) error { return nil }

// memorySender 在进程内记录最近发送的验证码，并用互斥锁支持并发发码测试。
type memorySender struct {
	mu    sync.Mutex
	codes map[string]string
}

// SendCode 记录指定邮箱收到的验证码，不调用外部邮件服务。
func (m *memorySender) SendCode(_ context.Context, address, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.codes == nil {
		m.codes = make(map[string]string)
	}
	m.codes[address] = code
	return nil
}

// code 读取测试邮箱最近收到的验证码。
func (m *memorySender) code(address string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.codes[address]
}

// testWechat 为测试 code 返回固定应用下的服务端身份，不访问微信接口。
type testWechat struct{}

// ExchangeCode 将测试 code 映射为同应用内的 OpenID。
func (testWechat) ExchangeCode(_ context.Context, code string) (wechat.Identity, error) {
	return wechat.Identity{AppID: "test-app", OpenID: code}, nil
}

var errInvalidTicket = errors.New("invalid test ticket")

// ticketPlugin 位于 authkit 包之外，只依赖公开的已验证身份入口。
// 它用于证明增加登录方式不需要修改核心分支或数据库表结构。
type ticketPlugin struct {
	core   *authkit.Service
	policy authkit.RegistrationPolicy
}

// ticketInput 模拟自定义插件的强类型凭证输入和宿主注册引用。
type ticketInput struct {
	Ticket    string
	Scope     string
	Subject   string
	Reference string
}

// verified 仅将测试凭证转换为可信身份，错误凭证不进入核心事务。
func (p ticketPlugin) verified(input ticketInput) (authkit.VerifiedIdentity, error) {
	if input.Ticket != "verified-test-ticket" {
		return authkit.VerifiedIdentity{}, errInvalidTicket
	}
	return authkit.VerifiedIdentity{
		Identity: authkit.IdentityKey{
			Namespace: "ticket", Scope: input.Scope, Subject: input.Subject,
		},
		Method: "ticket", RegistrationRef: input.Reference,
	}, nil
}

// Login 在验证测试凭证后交给核心处理账号创建和会话签发。
func (p ticketPlugin) Login(ctx context.Context, input ticketInput) (*authkit.LoginResult, error) {
	verified, err := p.verified(input)
	if err != nil {
		return nil, err
	}
	return p.core.LoginVerified(ctx, verified, p.policy)
}

// Bind 在验证测试凭证后显式绑定当前会话所属账号。
func (p ticketPlugin) Bind(
	ctx context.Context,
	token string,
	input ticketInput,
) (*authkit.LoginResult, error) {
	verified, err := p.verified(input)
	if err != nil {
		return nil, err
	}
	return p.core.BindVerified(ctx, token, verified)
}

// TestNewStoreRejectsMissingConnection 验证空连接在创建仓储时立即被拒绝。
func TestNewStoreRejectsMissingConnection(t *testing.T) {
	if _, err := authmysql.NewStore(nil); !errors.Is(err, authkit.ErrInvalidInput) {
		t.Fatalf("got %v", err)
	}
}

// TestCoreModelsAreOptionalPluginSchema 验证核心迁移只创建三张表，未启用的插件无需建表。
func TestCoreModelsAreOptionalPluginSchema(t *testing.T) {
	db, _ := testDatabase(t)
	if got := len(authmysql.Models()); got != 3 {
		t.Fatalf("core model count = %d, want 3", got)
	}
	for _, name := range []string{"auth_users", "auth_identities", "auth_sessions"} {
		if !db.Migrator().HasTable(name) {
			t.Fatalf("missing core table %s", name)
		}
	}
	for _, name := range []string{"auth_challenges", "auth_rates", "auth_wechat_accounts"} {
		if db.Migrator().HasTable(name) {
			t.Fatalf("core migration unexpectedly created %s", name)
		}
	}
}

// TestExternalPluginUsesOnlyCoreSchema 验证外部插件只凭已验证身份契约即可登录、绑定和准入。
// 新命名空间无需改动核心分支或增加插件专属表，绑定仍轮换当前会话。
func TestExternalPluginUsesOnlyCoreSchema(t *testing.T) {
	db, store := testDatabase(t)
	core, err := authkit.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var admitted authkit.Registration
	plugin := ticketPlugin{core: core, policy: authkit.RegistrationPolicyFunc(
		func(_ context.Context, registration authkit.Registration) error {
			admitted = registration
			return nil
		},
	)}
	input := ticketInput{
		Ticket:    "verified-test-ticket",
		Scope:     "app-one",
		Subject:   "external-subject",
		Reference: "host-ref",
	}
	if _, err := plugin.Login(
		ctx,
		ticketInput{Ticket: "unverified", Scope: input.Scope, Subject: input.Subject},
	); !errors.Is(
		err,
		errInvalidTicket,
	) {
		t.Fatalf("invalid proof = %v", err)
	}
	if countRows(t, db, &models.Identity{}) != 0 {
		t.Fatal("invalid proof allocated identity state")
	}
	first, err := plugin.Login(ctx, input)
	if err != nil || !first.Created || first.User.ID == "" {
		t.Fatalf("external plugin registration = %#v, %v", first, err)
	}
	if admitted.User.ID != first.User.ID || admitted.Method != "ticket" ||
		admitted.Identity.Namespace != "ticket" || admitted.Reference != "host-ref" {
		t.Fatalf("registration metadata = %#v", admitted)
	}
	second, err := plugin.Bind(ctx, first.Token, ticketInput{
		Ticket: "verified-test-ticket", Scope: "app-two", Subject: "external-subject",
	})
	if err != nil || second.User.ID != first.User.ID || second.Token == first.Token {
		t.Fatalf("external plugin bind = %#v, %v", second, err)
	}
	if _, err := core.Authenticate(ctx, first.Token); !errors.Is(err, authkit.ErrUnauthorized) {
		t.Fatalf("old token survived bind: %v", err)
	}
	identities, err := core.ListIdentities(ctx, first.User.ID)
	if err != nil || len(identities) != 2 {
		t.Fatalf("listed identities = %#v, %v", identities, err)
	}
	withoutRegistration := ticketPlugin{core: core}
	returning, err := withoutRegistration.Login(ctx, ticketInput{
		Ticket: "verified-test-ticket", Scope: "app-two", Subject: "external-subject",
	})
	if err != nil || returning.Created || returning.User.ID != first.User.ID {
		t.Fatalf("existing login without policy = %#v, %v", returning, err)
	}
	if _, err := withoutRegistration.Login(ctx, ticketInput{
		Ticket: "verified-test-ticket", Scope: "app-three", Subject: "new-subject",
	}); !errors.Is(err, authkit.ErrRegistrationDenied) {
		t.Fatalf("new registration without policy = %v", err)
	}
	if countRows(t, db, &models.User{}) != 1 || countRows(t, db, &models.Identity{}) != 2 ||
		countRows(t, db, &models.Session{}) != 2 {
		t.Fatal("unexpected core rows after external plugin calls")
	}
	if db.Migrator().HasTable("auth_challenges") || db.Migrator().HasTable("auth_rates") {
		t.Fatal("external plugin required email schema")
	}
}

// TestConcurrentBindingWithOneSessionToken 验证同一 Token 并发绑定时仅有一次成功。
// 另一事务锁定会话后重新检查撤销状态，不能凭先前的无锁认证继续绑定。
func TestConcurrentBindingWithOneSessionToken(t *testing.T) {
	db, store := testDatabase(t)
	core, err := authkit.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	plugin := ticketPlugin{core: core, policy: authkit.RegistrationPolicyFunc(allowRegistration)}
	ctx := context.Background()
	login, err := plugin.Login(ctx, ticketInput{
		Ticket: "verified-test-ticket", Scope: "original", Subject: "subject",
	})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	type result struct {
		login *authkit.LoginResult
		err   error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, scope := range []string{"second", "third"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			bound, err := plugin.Bind(ctx, login.Token, ticketInput{
				Ticket: "verified-test-ticket", Scope: scope, Subject: "subject",
			})
			results <- result{login: bound, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var succeeded, unauthorized int
	var newToken string
	for result := range results {
		switch {
		case result.err == nil:
			succeeded++
			newToken = result.login.Token
		case errors.Is(result.err, authkit.ErrUnauthorized):
			unauthorized++
		default:
			t.Errorf("unexpected binding result: %#v, %v", result.login, result.err)
		}
	}
	if succeeded != 1 || unauthorized != 1 || countRows(t, db, &models.Identity{}) != 2 ||
		countRows(t, db, &models.Session{}) != 1 {
		t.Fatalf("successful=%d unauthorized=%d", succeeded, unauthorized)
	}
	if _, err := core.Authenticate(ctx, login.Token); !errors.Is(err, authkit.ErrUnauthorized) {
		t.Fatalf("original token remains live: %v", err)
	}
	if _, err := core.Authenticate(ctx, newToken); err != nil {
		t.Fatalf("replacement token is invalid: %v", err)
	}
}

// TestIdentityUniquenessAndExactKeys 验证主体不能重归属，同账号同范围不能绑定两个主体。
// 同时检查重音邮箱及大小写不同的应用范围均按字节区分。
func TestIdentityUniquenessAndExactKeys(t *testing.T) {
	db, store := testDatabase(t)
	ctx := context.Background()
	if err := store.WithTransaction(ctx, func(r authkit.Repositories) error {
		for _, id := range []string{"one", "two"} {
			if err := r.Users().Create(ctx, &authkit.User{ID: id}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bind := func(key authkit.IdentityKey, userID string) error {
		return store.WithTransaction(ctx, func(r authkit.Repositories) error {
			if _, err := r.Identities().Lock(ctx, key); err != nil {
				return err
			}
			return r.Identities().Bind(ctx, key, userID)
		})
	}
	email := authkit.IdentityKey{Namespace: "email", Subject: "elise@example.com"}
	if err := bind(email, "one"); err != nil {
		t.Fatal(err)
	}
	if err := bind(email, "two"); !errors.Is(err, authkit.ErrIdentityConflict) {
		t.Fatalf("identity reassignment = %v", err)
	}
	if err := bind(
		authkit.IdentityKey{Namespace: "email", Subject: "other@example.com"},
		"one",
	); !errors.Is(
		err,
		authkit.ErrIdentityBound,
	) {
		t.Fatalf("second email on one account = %v", err)
	}
	for _, key := range []authkit.IdentityKey{
		{Namespace: "email", Subject: "élise@example.com"},
		{Namespace: "wechat", Scope: "CaseApp", Subject: "same-openid-hash"},
		{Namespace: "wechat", Scope: "caseapp", Subject: "same-openid-hash"},
	} {
		if err := bind(key, "two"); err != nil {
			t.Fatalf("exact identity key %#v: %v", key, err)
		}
	}
	if got := countRows(t, db, &models.Identity{}); got != 4 {
		t.Fatalf("identity rows = %d, want 4", got)
	}
	if err := store.WithTransaction(ctx, func(r authkit.Repositories) error {
		identities, err := r.Identities().ListByUser(ctx, "two")
		if err != nil {
			return err
		}
		if len(identities) != 3 {
			t.Fatalf("listed identities = %d, want 3", len(identities))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestConcurrentDistinctIdentityBindings 验证唯一索引在并发时仍只允许同范围绑定一个主体。
// 失败事务中的身份占位行必须回滚，不留下未归属记录。
func TestConcurrentDistinctIdentityBindings(t *testing.T) {
	db, store := testDatabase(t)
	ctx := context.Background()
	if err := store.WithTransaction(ctx, func(r authkit.Repositories) error {
		return r.Users().Create(ctx, &authkit.User{ID: "owner"})
	}); err != nil {
		t.Fatal(err)
	}
	keys := []authkit.IdentityKey{
		{Namespace: "wechat", Scope: "app-one", Subject: "subject-one"},
		{Namespace: "wechat", Scope: "app-one", Subject: "subject-two"},
	}
	start := make(chan struct{})
	results := make(chan error, len(keys))
	var wg sync.WaitGroup
	for _, key := range keys {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- store.WithTransaction(ctx, func(r authkit.Repositories) error {
				if _, err := r.Identities().Lock(ctx, key); err != nil {
					return err
				}
				return r.Identities().Bind(ctx, key, "owner")
			})
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var succeeded, bound int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, authkit.ErrIdentityBound):
			bound++
		default:
			t.Errorf("unexpected binding error: %v", err)
		}
	}
	if succeeded != 1 || bound != 1 || countRows(t, db, &models.Identity{}) != 1 {
		t.Fatalf("successful=%d identity-bound=%d", succeeded, bound)
	}
}

// TestConcurrentVerifiedRegistration 验证同一已验证主体并发首登只建一个账号。
// 准入策略只调用一次，每个成功请求各获独立会话，数据库只保存 Token 摘要。
func TestConcurrentVerifiedRegistration(t *testing.T) {
	db, store := testDatabase(t)
	svc, err := authkit.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	var admitted atomic.Int32
	policy := authkit.RegistrationPolicyFunc(func(context.Context, authkit.Registration) error {
		admitted.Add(1)
		return nil
	})
	verified := authkit.VerifiedIdentity{
		Identity: authkit.IdentityKey{
			Namespace: "wechat",
			Scope:     "test-app",
			Subject:   "verified-openid-hash",
		},
		Method: "wechat",
	}
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
			result, err := svc.LoginVerified(context.Background(), verified, policy)
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
	if len(tokens) != workers || created != 1 || admitted.Load() != 1 {
		t.Fatalf("sessions=%d created=%d admitted=%d", len(tokens), created, admitted.Load())
	}
	if countRows(t, db, &models.User{}) != 1 || countRows(t, db, &models.Identity{}) != 1 ||
		countRows(t, db, &models.Session{}) != workers {
		t.Fatal("unexpected persisted account/identity/session counts")
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

// TestWechatAdmissionReferenceAndNilPolicy 验证微信注册引用传给准入策略。
// 无策略时旧身份仍可登录，新身份注册遭拒且不留下占位行或账号。
func TestWechatAdmissionReferenceAndNilPolicy(t *testing.T) {
	db, store := testDatabase(t)
	core, err := authkit.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	var admitted authkit.Registration
	withRegistration, err := wechat.NewService(core, testWechat{}, authkit.RegistrationPolicyFunc(
		func(_ context.Context, registration authkit.Registration) error {
			admitted = registration
			return nil
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := withRegistration.Login(ctx, wechat.LoginInput{
		Code: "same-openid", RegistrationRef: "invitation-reference",
	})
	if err != nil || !first.Created {
		t.Fatalf("first WeChat login = %#v, %v", first, err)
	}
	if admitted.User.ID != first.User.ID || admitted.Method != wechat.Method ||
		admitted.Identity.Namespace != wechat.Namespace || admitted.Identity.Scope != "test-app" ||
		admitted.Reference != "invitation-reference" {
		t.Fatalf("registration metadata = %#v", admitted)
	}
	withoutRegistration, err := wechat.NewService(core, testWechat{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	returning, err := withoutRegistration.Login(ctx, wechat.LoginInput{Code: "same-openid"})
	if err != nil || returning.Created || returning.User.ID != first.User.ID {
		t.Fatalf("existing login without policy = %#v, %v", returning, err)
	}
	if _, err := withoutRegistration.Login(
		ctx,
		wechat.LoginInput{Code: "new-openid"},
	); !errors.Is(
		err,
		authkit.ErrRegistrationDenied,
	) {
		t.Fatalf("new login without policy = %v", err)
	}
	if countRows(t, db, &models.User{}) != 1 || countRows(t, db, &models.Identity{}) != 1 {
		t.Fatal("denied registration left persisted account or identity")
	}
}

// TestHostTransactionRollback 验证宿主业务回滚会同时撤销账号、身份和会话写入。
// 事务内产生的临时 Token 在提交失败后不能用于认证。
func TestHostTransactionRollback(t *testing.T) {
	db, store := testDatabase(t)
	svc, err := authkit.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	verified := authkit.VerifiedIdentity{
		Identity: authkit.IdentityKey{
			Namespace: "wechat",
			Scope:     "test-app",
			Subject:   "rollback-subject",
		},
		Method: "wechat",
	}
	failure := errors.New("host write failed")
	var issued *authkit.LoginResult
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		outcome, err := svc.InTransaction(authmysql.Bind(tx), authkit.RegistrationPolicyFunc(allowRegistration)).
			LoginVerified(ctx, verified)
		if err != nil {
			return err
		}
		issued = outcome.Login
		return failure
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if !errors.Is(err, failure) || issued == nil {
		t.Fatalf("transaction error=%v issued=%#v", err, issued)
	}
	for _, model := range []any{&models.User{}, &models.Identity{}, &models.Session{}} {
		if countRows(t, db, model) != 0 {
			t.Fatalf("rollback left persisted %T", model)
		}
	}
	if _, err := svc.Authenticate(ctx, issued.Token); !errors.Is(err, authkit.ErrUnauthorized) {
		t.Fatalf("provisional token authenticated: %v", err)
	}
}

// TestEmailAndWechatExplicitBinding 验证邮箱与微信只能凭已登录会话显式绑定。
// 绑定保留账号 ID、轮换当前 Token；跨账号占用冲突不会自动合并或撤销原会话。
func TestEmailAndWechatExplicitBinding(t *testing.T) {
	db, store := testDatabase(t)
	if err := db.AutoMigrate(emailmysql.Models()...); err != nil {
		t.Fatal(err)
	}
	core, err := authkit.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	emailStore, err := emailmysql.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	sender := &memorySender{}
	policy := authkit.RegistrationPolicyFunc(allowRegistration)
	emails, err := email.NewService(core, emailStore, sender, policy)
	if err != nil {
		t.Fatal(err)
	}
	weixin, err := wechat.NewService(core, testWechat{}, policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	issue := func(address string) string {
		t.Helper()
		if err := emails.SendCode(
			ctx,
			email.SendCodeInput{Email: address, IP: "127.0.0.1"},
		); err != nil {
			t.Fatal(err)
		}
		return sender.code(address)
	}
	alice, err := emails.Login(ctx, email.LoginInput{
		Email: "alice@example.com", Code: issue("alice@example.com"),
	})
	if err != nil || !alice.Created {
		t.Fatalf("email registration = %#v, %v", alice, err)
	}
	boundWechat, err := weixin.Bind(ctx, alice.Token, wechat.BindInput{Code: "alice-openid"})
	if err != nil || boundWechat.User.ID != alice.User.ID || boundWechat.Token == alice.Token {
		t.Fatalf("WeChat binding = %#v, %v", boundWechat, err)
	}
	if _, err := core.Authenticate(ctx, alice.Token); !errors.Is(err, authkit.ErrUnauthorized) {
		t.Fatalf("old token survived binding: %v", err)
	}
	returning, err := weixin.Login(ctx, wechat.LoginInput{Code: "alice-openid"})
	if err != nil || returning.Created || returning.User.ID != alice.User.ID {
		t.Fatalf("bound WeChat login = %#v, %v", returning, err)
	}
	bob, err := emails.Login(ctx, email.LoginInput{
		Email: "bob@example.com", Code: issue("bob@example.com"),
	})
	if err != nil || !bob.Created || bob.User.ID == alice.User.ID {
		t.Fatalf("separate email registration = %#v, %v", bob, err)
	}
	if _, err := weixin.Bind(
		ctx,
		bob.Token,
		wechat.BindInput{Code: "alice-openid"},
	); !errors.Is(
		err,
		authkit.ErrIdentityConflict,
	) {
		t.Fatalf("cross-account WeChat binding = %v", err)
	}
	if _, err := core.Authenticate(ctx, bob.Token); err != nil {
		t.Fatalf("conflicting bind revoked existing session: %v", err)
	}
	charlie, err := weixin.Login(ctx, wechat.LoginInput{Code: "charlie-openid"})
	if err != nil || !charlie.Created {
		t.Fatalf("WeChat registration = %#v, %v", charlie, err)
	}
	boundEmail, err := emails.Bind(ctx, charlie.Token, email.BindInput{
		Email: "charlie@example.com", Code: issue("charlie@example.com"),
	})
	if err != nil || boundEmail.User.ID != charlie.User.ID || boundEmail.Token == charlie.Token {
		t.Fatalf("email binding = %#v, %v", boundEmail, err)
	}
	returning, err = emails.Login(ctx, email.LoginInput{
		Email: "charlie@example.com", Code: sender.code("charlie@example.com"),
	})
	if !errors.Is(err, email.ErrChallengeInvalid) || returning != nil {
		t.Fatalf("bound proof was reusable: %#v, %v", returning, err)
	}
	if got := countRows(t, db, &models.User{}); got != 3 {
		t.Fatalf("account count = %d, want 3", got)
	}
	if got := countRows(t, db, &models.Identity{}); got != 5 {
		t.Fatalf("identity count = %d, want 5", got)
	}
}

// TestEmailChallengeAttemptsAndAdmissionWithMySQL 验证错误码次数在独立和宿主事务中均持久提交。
// 准入拒绝不消耗正确验证码；成功登录后验证码只能使用一次，退出会撤销会话。
func TestEmailChallengeAttemptsAndAdmissionWithMySQL(t *testing.T) {
	db, store := testDatabase(t)
	if err := db.AutoMigrate(emailmysql.Models()...); err != nil {
		t.Fatal(err)
	}
	core, err := authkit.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	emailStore, err := emailmysql.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	sender := &memorySender{}
	emails, err := email.NewService(
		core,
		emailStore,
		sender,
		authkit.RegistrationPolicyFunc(allowRegistration),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const address = "attempts@example.com"
	if err := emails.SendCode(ctx, email.SendCodeInput{
		Email: address, IP: "127.0.0.1", RegistrationRef: "host-ref:中文",
	}); err != nil {
		t.Fatal(err)
	}
	wrong := "000000"
	if sender.code(address) == wrong {
		wrong = "000001"
	}
	if _, err := emails.Login(
		ctx,
		email.LoginInput{Email: address, Code: wrong},
	); !errors.Is(
		err,
		email.ErrChallengeMismatch,
	) {
		t.Fatalf("wrong code = %v", err)
	}
	var rejection error
	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		outcome, err := emails.InTransaction(
			core.InTransaction(authmysql.Bind(tx), nil), emailmysql.Bind(tx),
		).Login(ctx, email.LoginInput{Email: address, Code: wrong})
		rejection = outcome.Rejected
		return err
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(rejection, email.ErrChallengeMismatch) {
		t.Fatalf("host transaction rejection = %v", rejection)
	}
	var challenge emailmysql.Challenge
	if err := db.Where("email = ?", address).Take(&challenge).Error; err != nil {
		t.Fatal(err)
	}
	if challenge.Attempts != 2 || !challenge.Ready || challenge.RegistrationRef != "host-ref:中文" ||
		countRows(t, db, &models.User{}) != 0 {
		t.Fatal("wrong proofs did not durably count both failures")
	}
	denied, err := email.NewService(core, emailStore, sender, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Login(
		ctx,
		email.LoginInput{Email: address, Code: sender.code(address)},
	); !errors.Is(
		err,
		authkit.ErrRegistrationDenied,
	) {
		t.Fatalf("missing registration policy = %v", err)
	}
	if err := db.Where("email = ?", address).Take(&challenge).Error; err != nil {
		t.Fatal(err)
	}
	if !challenge.Ready || challenge.Attempts != 2 {
		t.Fatal("admission failure consumed the proof")
	}
	login, err := emails.Login(ctx, email.LoginInput{Email: address, Code: sender.code(address)})
	if err != nil || !login.Created {
		t.Fatalf("successful email login = %#v, %v", login, err)
	}
	if _, err := emails.Login(
		ctx,
		email.LoginInput{Email: address, Code: sender.code(address)},
	); !errors.Is(
		err,
		email.ErrChallengeInvalid,
	) {
		t.Fatalf("proof reused: %v", err)
	}
	if err := core.Logout(ctx, login.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := core.Authenticate(ctx, login.Token); !errors.Is(err, authkit.ErrUnauthorized) {
		t.Fatalf("logout: %v", err)
	}
}

// TestConcurrentSendCodeSameMailbox 验证同一邮箱并发发码由挑战行锁串行化。
// 只有一次发送成功，其余请求受到重发冷却约束，最终仅保留一条可用挑战。
func TestConcurrentSendCodeSameMailbox(t *testing.T) {
	db, store := testDatabase(t)
	if err := db.AutoMigrate(emailmysql.Models()...); err != nil {
		t.Fatal(err)
	}
	core, err := authkit.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	emailStore, err := emailmysql.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	sender := &memorySender{}
	emails, err := email.NewService(
		core,
		emailStore,
		sender,
		authkit.RegistrationPolicyFunc(allowRegistration),
	)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 12
	start := make(chan struct{})
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- emails.SendCode(context.Background(), email.SendCodeInput{
				Email: "concurrent@example.com", IP: "127.0.0.1",
			})
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var sent, cooled int
	for err := range results {
		switch {
		case err == nil:
			sent++
		case errors.Is(err, email.ErrResendTooSoon):
			cooled++
		default:
			t.Errorf("unexpected SendCode error: %v", err)
		}
	}
	if sent != 1 || cooled != workers-1 || countRows(t, db, &emailmysql.Challenge{}) != 1 {
		t.Fatalf("sent=%d cooled=%d", sent, cooled)
	}
	var challenge emailmysql.Challenge
	if err := db.Where("email = ?", "concurrent@example.com").Take(&challenge).Error; err != nil {
		t.Fatal(err)
	}
	if !challenge.Ready || sender.code("concurrent@example.com") == "" {
		t.Fatal("successful delivery did not activate its challenge")
	}
}
