package authmysql_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/email"
	emailmysql "github.com/miebyte/authkit/email/mysql"
	authmysql "github.com/miebyte/authkit/mysql"
	"github.com/miebyte/authkit/mysql/models"
	"gorm.io/gorm"
)

// emailMySQLFixture 将核心与邮箱插件仓储接入同一个临时数据库。
type emailMySQLFixture struct {
	db         *gorm.DB
	coreStore  *authmysql.Store
	core       *authkit.Service
	emailStore *emailmysql.Store
	emails     *email.Service
	sender     *memorySender
}

// newEmailMySQLFixture 在已隔离的临时库内额外迁移邮箱挑战和限流表。
func newEmailMySQLFixture(t *testing.T) emailMySQLFixture {
	t.Helper()
	db, coreStore := testDatabase(t)
	if err := db.AutoMigrate(emailmysql.Models()...); err != nil {
		t.Fatal(err)
	}
	core, err := authkit.NewService(coreStore)
	if err != nil {
		t.Fatal(err)
	}
	emailStore, err := emailmysql.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	sender := &memorySender{}
	emails, err := email.NewService(core, emailStore, sender,
		authkit.RegistrationPolicyFunc(allowRegistration))
	if err != nil {
		t.Fatal(err)
	}
	return emailMySQLFixture{
		db: db, coreStore: coreStore, core: core, emailStore: emailStore,
		emails: emails, sender: sender,
	}
}

// TestConcurrentRateLimit 验证并发命中同一限流键时计数不会丢失。
// 固定一小时窗口到达边界前仍拒绝请求，恰好到达边界时允许重置。
func TestConcurrentRateLimit(t *testing.T) {
	f := newEmailMySQLFixture(t)
	const workers, limit = 20, 7
	var accepted atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := strings.Repeat("a", 64)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := f.emailStore.WithTransaction(context.Background(),
				func(_ authkit.Repositories, repos email.Repositories) error {
					return repos.Rates().Hit(context.Background(), id, now, limit)
				})
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, email.ErrTooManyRequests) {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if accepted.Load() != limit || countRows(t, f.db, &emailmysql.Rate{}) != 1 {
		t.Fatalf("accepted=%d, want=%d", accepted.Load(), limit)
	}
	if err := f.emailStore.WithTransaction(context.Background(),
		func(_ authkit.Repositories, repos email.Repositories) error {
			return repos.Rates().
				Hit(context.Background(), id, now.Add(time.Hour-time.Microsecond), limit)
		}); !errors.Is(err, email.ErrTooManyRequests) {
		t.Fatalf("before hourly reset: %v", err)
	}
	if err := f.emailStore.WithTransaction(context.Background(),
		func(_ authkit.Repositories, repos email.Repositories) error {
			return repos.Rates().Hit(context.Background(), id, now.Add(time.Hour), limit)
		}); err != nil {
		t.Fatalf("hourly reset: %v", err)
	}
}

// TestSessionExpirationAndChallengeZeroValues 验证会话到期时间的微秒精度与到期拒绝。
// 同时确认挑战仓储能显式写回 false、零计数和空字符串，而非跳过零值。
func TestSessionExpirationAndChallengeZeroValues(t *testing.T) {
	f := newEmailMySQLFixture(t)
	ctx := context.Background()
	login, err := f.core.LoginVerified(ctx, authkit.VerifiedIdentity{
		Identity: authkit.IdentityKey{Namespace: "test", Subject: "expiry-user"}, Method: "test",
	}, authkit.RegistrationPolicyFunc(allowRegistration))
	if err != nil {
		t.Fatal(err)
	}
	var session models.Session
	if err := f.db.Where("user_id = ?", login.User.ID).Take(&session).Error; err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
	if err := f.db.Model(&models.Session{}).Where("hash = ?", session.Hash).
		Update("expires", expires).Error; err != nil {
		t.Fatal(err)
	}
	stored, err := f.coreStore.Sessions().Get(ctx, session.Hash)
	if err != nil || !stored.Expires.Equal(expires) {
		t.Fatalf("session expiration = %#v, %v", stored, err)
	}
	if _, err := f.core.Authenticate(ctx, login.Token); err != nil {
		t.Fatalf("unexpired session: %v", err)
	}
	if err := f.db.Model(&models.Session{}).Where("hash = ?", session.Hash).
		Update("expires", time.Now().UTC().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := f.core.Authenticate(ctx, login.Token); !errors.Is(err, authkit.ErrUnauthorized) {
		t.Fatalf("expired session: %v", err)
	}
	if err := f.emailStore.WithTransaction(
		ctx,
		func(_ authkit.Repositories, repos email.Repositories) error {
			challenge, err := repos.Challenges().Get(ctx, "zero@example.com")
			if err != nil {
				return err
			}
			challenge.Hash, challenge.RegistrationRef, challenge.Attempts, challenge.Ready =
				strings.Repeat("f", 64), "ref", 4, true
			if err := repos.Challenges().Save(ctx, challenge); err != nil {
				return err
			}
			challenge.Hash, challenge.RegistrationRef, challenge.Attempts, challenge.Ready = "", "", 0, false
			return repos.Challenges().Save(ctx, challenge)
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := f.emailStore.WithTransaction(
		ctx,
		func(_ authkit.Repositories, repos email.Repositories) error {
			challenge, err := repos.Challenges().Get(ctx, "zero@example.com")
			if err != nil {
				return err
			}
			if challenge.Hash != "" || challenge.RegistrationRef != "" || challenge.Attempts != 0 ||
				challenge.Ready {
				t.Fatal("challenge failed to persist false/zero/empty values")
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
}

// TestMailboxCollationPreventsCrossAccountLogin 验证重音不同的邮箱保留独立挑战、
// 身份和账号，不受 MySQL 默认排序规则的宽松比较影响。
func TestMailboxCollationPreventsCrossAccountLogin(t *testing.T) {
	f := newEmailMySQLFixture(t)
	ctx := context.Background()
	var accounts []string
	for _, address := range []string{"elise@example.com", "élise@example.com"} {
		if err := f.emails.SendCode(
			ctx,
			email.SendCodeInput{Email: address, IP: "127.0.0.1"},
		); err != nil {
			t.Fatal(err)
		}
		login, err := f.emails.Login(
			ctx,
			email.LoginInput{Email: address, Code: f.sender.code(address)},
		)
		if err != nil || !login.Created {
			t.Fatalf("mailbox %q login = %#v, %v", address, login, err)
		}
		identities, err := f.core.ListIdentities(ctx, login.User.ID)
		if err != nil || len(identities) != 1 || identities[0].Key.Subject != address {
			t.Fatalf("mailbox %q identity = %#v, %v", address, identities, err)
		}
		accounts = append(accounts, login.User.ID)
	}
	if accounts[0] == accounts[1] || countRows(t, f.db, &models.User{}) != 2 ||
		countRows(t, f.db, &models.Identity{}) != 2 ||
		countRows(t, f.db, &emailmysql.Challenge{}) != 2 {
		t.Fatal("accent-distinct inboxes shared an identity, challenge or account")
	}
}

// TestUnknownMailboxVerificationDoesNotAllocateRows 验证未发码邮箱的登录猜测只读。
// 拒绝后不得创建挑战、身份、账号或会话记录。
func TestUnknownMailboxVerificationDoesNotAllocateRows(t *testing.T) {
	f := newEmailMySQLFixture(t)
	_, err := f.emails.Login(context.Background(), email.LoginInput{
		Email: "unknown@example.com", Code: "123456",
	})
	if !errors.Is(err, email.ErrChallengeInvalid) {
		t.Fatalf("unknown mailbox verification: %v", err)
	}
	if countRows(t, f.db, &emailmysql.Challenge{}) != 0 ||
		countRows(t, f.db, &models.Identity{}) != 0 ||
		countRows(t, f.db, &models.User{}) != 0 ||
		countRows(t, f.db, &models.Session{}) != 0 {
		t.Fatal("unknown mailbox verification allocated durable state")
	}
}
