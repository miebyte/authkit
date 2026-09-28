package email

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miebyte/authkit"
)

type fixture struct {
	memory  *memory
	core    *authkit.Service
	service *Service
	mail    *capturedMail
	now     time.Time
}

func allowRegistration(context.Context, authkit.Registration) error { return nil }

func newFixture(t *testing.T, policy authkit.RegistrationPolicy) *fixture {
	t.Helper()
	memory := &memory{state: newMemoryState()}
	core, err := authkit.NewService(&coreStore{memory})
	if err != nil {
		t.Fatal(err)
	}
	mail := &capturedMail{}
	service, err := NewService(core, &emailStore{memory}, mail, policy)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{memory: memory, core: core, service: service, mail: mail, now: time.Now().UTC()}
	service.now = func() time.Time { return f.now }
	return f
}

func (f *fixture) issue(t *testing.T, email string) string {
	t.Helper()
	if err := f.service.SendCode(
		context.Background(),
		SendCodeInput{Email: email, IP: "192.0.2.1"},
	); err != nil {
		t.Fatal(err)
	}
	return f.mail.code
}

func requireError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v; want %v", err, want)
	}
}

// TestEmailLifecycle 验证邮箱规范化、验证码一次性消费和新老账号会话创建。
func TestEmailLifecycle(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	code := f.issue(t, "  Alice@Example.com  ")
	if f.mail.email != "alice@example.com" || len(code) != 6 {
		t.Fatalf("delivery = %q, %q", f.mail.email, code)
	}
	challenge := f.memory.state.challenges["alice@example.com"]
	if challenge.Hash == "" || challenge.Hash == code || !challenge.Ready ||
		!challenge.Expires.Equal(f.now.Truncate(time.Microsecond).Add(CodeTTL)) {
		t.Fatalf("unexpected stored challenge: %#v", challenge)
	}
	login, err := f.service.Login(ctx, LoginInput{Email: "ALICE@example.com", Code: code})
	if err != nil {
		t.Fatal(err)
	}
	key := authkit.IdentityKey{Namespace: "email", Subject: "alice@example.com"}
	if !login.Created || login.User.ID == "" || login.Token == "" ||
		f.memory.state.identities[key].UserID != login.User.ID {
		t.Fatalf("login or identity = %#v, %#v", login, f.memory.state.identities[key])
	}
	if f.memory.state.challenges["alice@example.com"].Ready {
		t.Fatal("successful code was not consumed")
	}
	_, err = f.service.Login(ctx, LoginInput{Email: "alice@example.com", Code: code})
	requireError(t, err, ErrChallengeInvalid)
	user, err := f.core.Authenticate(ctx, login.Token)
	if err != nil || user.ID != login.User.ID {
		t.Fatalf("session = %#v, %v", user, err)
	}
	f.now = f.now.Add(ResendInterval)
	next := f.issue(t, "alice@example.com")
	returning, err := f.service.Login(ctx, LoginInput{Email: "alice@example.com", Code: next})
	if err != nil || returning.Created || returning.User.ID != login.User.ID {
		t.Fatalf("returning login = %#v, %v", returning, err)
	}
}

// TestChallengeFailuresAndLimits 验证错误次数、重发冷却及邮箱与 IP 限流上限。
func TestChallengeFailuresAndLimits(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	code := f.issue(t, "alice@example.com")
	requireError(t, f.service.SendCode(ctx, SendCodeInput{
		Email: "alice@example.com", IP: "192.0.2.1",
	}), ErrResendTooSoon)
	for i := 0; i < MaxAttempts; i++ {
		_, err := f.service.Login(ctx, LoginInput{Email: "alice@example.com", Code: "wrong"})
		requireError(t, err, ErrChallengeMismatch)
	}
	if f.memory.state.challenges["alice@example.com"].Attempts != MaxAttempts {
		t.Fatal("failed attempts did not commit")
	}
	_, err := f.service.Login(ctx, LoginInput{Email: "alice@example.com", Code: code})
	requireError(t, err, ErrChallengeInvalid)
	if len(f.memory.state.users) != 0 {
		t.Fatal("exhausted code created an account")
	}
	for i := 1; i < EmailRateLimit; i++ {
		f.now = f.now.Add(ResendInterval)
		f.issue(t, "alice@example.com")
	}
	f.now = f.now.Add(ResendInterval)
	requireError(t, f.service.SendCode(ctx, SendCodeInput{
		Email: "alice@example.com", IP: "192.0.2.1",
	}), ErrTooManyRequests)
	if len(f.memory.state.rates) != 2 {
		t.Fatal("mailbox and IP rates were not tracked independently")
	}
	for i := 0; i < IPRateLimit-EmailRateLimit; i++ {
		f.issue(t, fmt.Sprintf("other%d@example.com", i))
	}
	requireError(t, f.service.SendCode(ctx, SendCodeInput{
		Email: "over-ip-limit@example.com", IP: "192.0.2.1",
	}), ErrTooManyRequests)
}

// TestCodeExpiresAtBoundary 验证到期瞬间的正确验证码不能再注册账号。
func TestCodeExpiresAtBoundary(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	code := f.issue(t, "alice@example.com")
	f.now = f.now.Truncate(time.Microsecond).Add(CodeTTL)
	_, err := f.service.Login(
		context.Background(),
		LoginInput{Email: "alice@example.com", Code: code},
	)
	requireError(t, err, ErrChallengeInvalid)
	if len(f.memory.state.users) != 0 {
		t.Fatal("expired proof created an account")
	}
}

// TestRegistrationPolicyAndReference 验证注册准入失败保码及登录引用优先于发码引用。
func TestRegistrationPolicyAndReference(t *testing.T) {
	var seen authkit.Registration
	f := newFixture(t, nil)
	ctx := context.Background()
	if err := f.service.SendCode(ctx, SendCodeInput{
		Email: "alice@example.com", IP: "192.0.2.1", RegistrationRef: "sent-ref",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.service.Login(ctx, LoginInput{Email: "alice@example.com", Code: f.mail.code})
	requireError(t, err, authkit.ErrRegistrationDenied)
	if len(f.memory.state.users) != 0 || !f.memory.state.challenges["alice@example.com"].Ready {
		t.Fatal("denied registration wrote an account or consumed the code")
	}
	f.service.policy = authkit.RegistrationPolicyFunc(
		func(_ context.Context, registration authkit.Registration) error {
			seen = registration
			return nil
		},
	)
	_, err = f.service.Login(ctx, LoginInput{
		Email: "alice@example.com", Code: f.mail.code, RegistrationRef: "login-ref",
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen.Method != "email_code" || seen.Reference != "login-ref" ||
		seen.Identity != (authkit.IdentityKey{Namespace: "email", Subject: "alice@example.com"}) {
		t.Fatalf("registration = %#v", seen)
	}
	if err := f.service.SendCode(ctx, SendCodeInput{
		Email: "bob@example.com", IP: "192.0.2.1", RegistrationRef: "sent-ref",
	}); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.Login(ctx, LoginInput{Email: "bob@example.com", Code: f.mail.code})
	if err != nil || seen.Reference != "sent-ref" {
		t.Fatalf("saved reference = %#v, %v", seen, err)
	}
}

// TestMailFailureLeavesCodeUnusable 验证投递失败只保留冷却和限流，不激活验证码。
func TestMailFailureLeavesCodeUnusable(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	f.mail.err = errors.New("provider secret")
	ctx := context.Background()
	err := f.service.SendCode(ctx, SendCodeInput{Email: "alice@example.com", IP: "192.0.2.1"})
	requireError(t, err, ErrMailFailed)
	if f.memory.state.challenges["alice@example.com"].Ready || len(f.memory.state.rates) != 2 {
		t.Fatal("failed delivery activated code or lost rate state")
	}
	_, err = f.service.Login(ctx, LoginInput{Email: "alice@example.com", Code: f.mail.code})
	requireError(t, err, ErrChallengeInvalid)
}

// TestNewerCodeCannotBeActivatedByOlderDelivery 验证交错发码时旧投递不能覆盖新验证码。
func TestNewerCodeCannotBeActivatedByOlderDelivery(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	var newerErr error
	f.mail.hook = func() {
		f.mail.hook = nil
		f.now = f.now.Add(ResendInterval)
		newerErr = f.service.SendCode(ctx, SendCodeInput{
			Email: "alice@example.com", IP: "192.0.2.1",
		})
	}
	err := f.service.SendCode(ctx, SendCodeInput{Email: "alice@example.com", IP: "192.0.2.1"})
	requireError(t, err, ErrChallengeUpdated)
	if newerErr != nil {
		t.Fatal(newerErr)
	}
	if _, err := f.service.Login(ctx, LoginInput{
		Email: "alice@example.com", Code: f.mail.code,
	}); err != nil {
		t.Fatalf("newer proof failed: %v", err)
	}
}

// TestOlderDeliveryCannotActivateRepeatedCode 验证新旧验证码随机相同仍需比较发码时间。
func TestOlderDeliveryCannotActivateRepeatedCode(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	var newerErr error
	f.mail.hook = func() {
		f.mail.hook = nil
		// 后一次发码可能随机得到相同验证码，此时两个验证码的摘要也相同。
		newerErr = f.memory.transact(ctx, func(repos *memoryRepositories) error {
			newer, err := repos.Challenges().Find(ctx, "alice@example.com")
			if err != nil {
				return err
			}
			newer.Sent = newer.Sent.Add(ResendInterval)
			newer.Expires = newer.Sent.Add(CodeTTL)
			newer.RegistrationRef = "later-issuance"
			return repos.Challenges().Save(ctx, newer)
		})
	}
	err := f.service.SendCode(ctx, SendCodeInput{Email: "alice@example.com", IP: "192.0.2.1"})
	requireError(t, err, ErrChallengeUpdated)
	if newerErr != nil {
		t.Fatal(newerErr)
	}
	if f.memory.state.challenges["alice@example.com"].Ready {
		t.Fatal("old delivery activated a newer, undelivered code with the same hash")
	}
	_, err = f.service.Login(ctx, LoginInput{Email: "alice@example.com", Code: f.mail.code})
	requireError(t, err, ErrChallengeInvalid)
}

// TestUnissuedMailboxDoesNotAllocateChallenge 验证未知邮箱的猜测不会创建验证码记录。
func TestUnissuedMailboxDoesNotAllocateChallenge(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	for i := 0; i < 20; i++ {
		_, err := f.service.Login(context.Background(), LoginInput{
			Email: fmt.Sprintf("unknown%d@example.com", i), Code: "123456",
		})
		requireError(t, err, ErrChallengeInvalid)
	}
	if len(f.memory.state.challenges) != 0 || len(f.memory.state.users) != 0 {
		t.Fatal("unissued mailbox guesses allocated durable state")
	}
}

// TestBindIsExplicitAndConflictKeepsProof 验证显式绑定、会话轮换和冲突时保留正确验证码。
func TestBindIsExplicitAndConflictKeepsProof(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	initial, err := f.core.LoginVerified(ctx, authkit.VerifiedIdentity{
		Identity: authkit.IdentityKey{
			Namespace: "wechat",
			Scope:     "app",
			Subject:   "verified-subject",
		},
		Method: "wechat",
	}, authkit.RegistrationPolicyFunc(allowRegistration))
	if err != nil {
		t.Fatal(err)
	}
	code := f.issue(t, "alice@example.com")
	_, err = f.service.Bind(ctx, "invalid-token", BindInput{Email: "alice@example.com", Code: code})
	requireError(t, err, authkit.ErrUnauthorized)
	if !f.memory.state.challenges["alice@example.com"].Ready ||
		f.memory.state.challenges["alice@example.com"].Attempts != 0 {
		t.Fatal("invalid session spent email proof")
	}
	bound, err := f.service.Bind(
		ctx,
		initial.Token,
		BindInput{Email: "alice@example.com", Code: code},
	)
	if err != nil {
		t.Fatal(err)
	}
	key := authkit.IdentityKey{Namespace: "email", Subject: "alice@example.com"}
	if bound.User.ID != initial.User.ID || bound.Token == initial.Token ||
		f.memory.state.identities[key].UserID != initial.User.ID {
		t.Fatalf("binding = %#v", bound)
	}
	_, err = f.core.Authenticate(ctx, initial.Token)
	requireError(t, err, authkit.ErrUnauthorized)
	f.now = f.now.Add(ResendInterval)
	code = f.issue(t, "other@example.com")
	_, err = f.service.Bind(ctx, bound.Token, BindInput{Email: "other@example.com", Code: code})
	if err == nil {
		t.Fatal("second email identity was bound to one account")
	}
	if !f.memory.state.challenges["other@example.com"].Ready {
		t.Fatal("binding conflict consumed a valid code")
	}
}

// TestHostTransactionRollbackKeepsProof 验证宿主后续写入失败时账号、会话和验证码消费一起回滚。
func TestHostTransactionRollbackKeepsProof(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	code := f.issue(t, "alice@example.com")
	hostFailure := errors.New("host write failed")
	err := f.memory.transact(ctx, func(repos *memoryRepositories) error {
		coreTx := f.core.InTransaction(repos, authkit.RegistrationPolicyFunc(allowRegistration))
		outcome, err := f.service.InTransaction(coreTx, repos).Login(ctx, LoginInput{
			Email: "alice@example.com", Code: code,
		})
		if err != nil || outcome.Login == nil {
			t.Fatalf("provisional login = %#v, %v", outcome, err)
		}
		return hostFailure
	})
	requireError(t, err, hostFailure)
	if len(f.memory.state.users) != 0 || len(f.memory.state.sessions) != 0 ||
		!f.memory.state.challenges["alice@example.com"].Ready {
		t.Fatal("host rollback left an account, session or spent code")
	}
	if _, err := f.service.Login(
		ctx,
		LoginInput{Email: "alice@example.com", Code: code},
	); err != nil {
		t.Fatal(err)
	}
}

// TestHostTransactionUsesExplicitPolicy 验证宿主事务使用显式策略，不继承插件独立调用的策略。
func TestHostTransactionUsesExplicitPolicy(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	code := f.issue(t, "alice@example.com")
	err := f.memory.transact(ctx, func(repos *memoryRepositories) error {
		coreTx := f.core.InTransaction(repos, nil)
		_, err := f.service.InTransaction(coreTx, repos).Login(ctx, LoginInput{
			Email: "alice@example.com", Code: code,
		})
		return err
	})
	requireError(t, err, authkit.ErrRegistrationDenied)
	if len(f.memory.state.users) != 0 || len(f.memory.state.identities) != 0 ||
		len(f.memory.state.sessions) != 0 || !f.memory.state.challenges["alice@example.com"].Ready {
		t.Fatal("host transaction inherited plugin policy or consumed its proof")
	}
	login, err := f.service.Login(ctx, LoginInput{Email: "alice@example.com", Code: code})
	if err != nil || !login.Created {
		t.Fatalf("standalone plugin policy = %#v, %v", login, err)
	}
}

// TestInvalidEmailAndCodeLeaveNoState 验证非法邮箱及验证码不会写入任何身份或证明状态。
func TestInvalidEmailAndCodeLeaveNoState(t *testing.T) {
	f := newFixture(t, authkit.RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	for _, mailbox := range []string{"", "not-an-email", "Alice <alice@example.com>"} {
		requireError(t, f.service.SendCode(ctx, SendCodeInput{
			Email: mailbox, IP: "192.0.2.1",
		}), ErrInvalidEmail)
		_, err := f.service.Login(ctx, LoginInput{Email: mailbox, Code: "123456"})
		requireError(t, err, ErrInvalidEmail)
	}
	for _, code := range []string{"", strings.Repeat("1", 17)} {
		_, err := f.service.Login(ctx, LoginInput{Email: "alice@example.com", Code: code})
		requireError(t, err, authkit.ErrInvalidInput)
		_, err = f.service.Bind(
			ctx,
			"invalid-token",
			BindInput{Email: "alice@example.com", Code: code},
		)
		requireError(t, err, authkit.ErrInvalidInput)
	}
	state := f.memory.state
	if len(state.challenges) != 0 || len(state.rates) != 0 || len(state.identities) != 0 ||
		len(state.users) != 0 || len(state.sessions) != 0 {
		t.Fatal("malformed email or code persisted state")
	}
}
