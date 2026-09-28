package authkit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fixture keeps the clock, mailer and durable state under each test's control.
type fixture struct {
	service *Service
	store   *memoryStore
	mail    *capturedMail
	wechat  *fakeWechat
	now     time.Time
}

// newFixture wires a service with a deterministic clock and explicit registration policy.
func newFixture(t *testing.T, policy RegistrationPolicy) *fixture {
	t.Helper()
	f := &fixture{
		store: newMemoryStore(),
		mail:  &capturedMail{},
		now:   time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC),
	}
	f.wechat = &fakeWechat{
		identity: WechatIdentity{AppID: "app-one", OpenID: "verified-open-id"},
		store:    f.store,
	}
	var err error
	f.service, err = NewService(f.store, f.mail, f.wechat, policy)
	if err != nil {
		t.Fatal(err)
	}
	f.service.now = func() time.Time { return f.now }
	return f
}

// issue sends a code through the public API and returns the captured delivery.
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

// loginEmail creates an explicitly admitted account through the public email flow.
func (f *fixture) loginEmail(t *testing.T, email string) *LoginResult {
	t.Helper()
	code := f.issue(t, email)
	result, err := f.service.LoginEmail(
		context.Background(),
		EmailLoginInput{Email: email, Code: code},
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// requireError verifies stable errors rather than provider-specific strings.
func requireError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

// differentCode guarantees the attempted six-digit code is not the delivered code.
func differentCode(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}

// TestEmailLifecycle exercises normalization, one-time proof, session TTL and logout.
func TestEmailLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	code := f.issue(t, "  Alice@Example.com  ")
	if f.mail.email != "alice@example.com" || len(code) != 6 {
		t.Fatalf("unexpected mail delivery: email %q, code length %d", f.mail.email, len(code))
	}
	challenge := f.store.state.challenges["alice@example.com"]
	if challenge.Hash == "" || challenge.Hash == code || !challenge.Ready ||
		!challenge.Expires.Equal(f.now.Add(CodeTTL)) {
		t.Fatal("challenge must contain a ready, expiring digest")
	}
	result, err := f.service.LoginEmail(
		ctx,
		EmailLoginInput{Email: "ALICE@example.com", Code: code},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || result.Account.Email != "alice@example.com" || result.Account.ID == "" ||
		result.Token == "" ||
		!result.Expires.Equal(f.now.Add(SessionTTL)) {
		t.Fatalf("unexpected login result: %#v", result)
	}
	for digest, session := range f.store.state.sessions {
		if digest == result.Token || digest == "" || session.AccountID != result.Account.ID {
			t.Fatal("only token digests may be persisted")
		}
	}
	user, err := f.service.Authenticate(ctx, result.Token)
	if err != nil || user.ID != result.Account.ID || user.Username != "" {
		t.Fatalf("authenticate = %v, %v", user, err)
	}
	_, err = f.service.LoginEmail(ctx, EmailLoginInput{Email: "alice@example.com", Code: code})
	requireError(t, err, ErrChallengeInvalid)
	if err := f.service.Logout(ctx, result.Token); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.Authenticate(ctx, result.Token)
	requireError(t, err, ErrUnauthorized)
	if err := f.service.Logout(ctx, result.Token); err != nil {
		t.Fatal(err)
	}
}

// TestChallengeExpiryAndAttempts ensures failed proofs commit and exhaust the challenge.
func TestChallengeExpiryAndAttempts(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
		code := f.issue(t, "alice@example.com")
		f.now = f.now.Add(CodeTTL)
		_, err := f.service.LoginEmail(
			context.Background(),
			EmailLoginInput{Email: "alice@example.com", Code: code},
		)
		requireError(t, err, ErrChallengeInvalid)
		if len(f.store.state.accounts) != 0 {
			t.Fatal("expired proof created an account")
		}
	})
	t.Run("attempts", func(t *testing.T) {
		f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
		code := f.issue(t, "alice@example.com")
		for attempt := 1; attempt <= MaxAttempts; attempt++ {
			_, err := f.service.LoginEmail(
				context.Background(),
				EmailLoginInput{Email: "alice@example.com", Code: differentCode(code)},
			)
			requireError(t, err, ErrChallengeMismatch)
			if got := f.store.state.challenges["alice@example.com"].Attempts; got != attempt {
				t.Fatalf("durable attempts = %d, want %d", got, attempt)
			}
		}
		_, err := f.service.LoginEmail(
			context.Background(),
			EmailLoginInput{Email: "alice@example.com", Code: code},
		)
		requireError(t, err, ErrChallengeInvalid)
		if len(f.store.state.accounts) != 0 {
			t.Fatal("exhausted proof created an account")
		}
	})
}

// TestResendAndHourlyLimits checks the limits at their exact reset boundaries.
func TestResendAndHourlyLimits(t *testing.T) {
	t.Run("mailbox", func(t *testing.T) {
		f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
		old := f.issue(t, "alice@example.com")
		err := f.service.SendCode(
			context.Background(),
			SendCodeInput{Email: "alice@example.com", IP: "192.0.2.1"},
		)
		requireError(t, err, ErrResendTooSoon)
		for i := 1; i < EmailRateLimit; i++ {
			f.now = f.now.Add(ResendInterval)
			f.issue(t, "alice@example.com")
		}
		f.now = f.now.Add(ResendInterval)
		err = f.service.SendCode(
			context.Background(),
			SendCodeInput{Email: "alice@example.com", IP: "192.0.2.1"},
		)
		requireError(t, err, ErrTooManyRequests)
		if old != f.mail.code {
			_, err = f.service.LoginEmail(
				context.Background(),
				EmailLoginInput{Email: "alice@example.com", Code: old},
			)
			requireError(t, err, ErrChallengeMismatch)
		}
		f.now = f.now.Truncate(time.Hour).Add(time.Hour)
		f.issue(t, "alice@example.com")
	})
	t.Run("ip", func(t *testing.T) {
		f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
		for i := 0; i < IPRateLimit; i++ {
			f.issue(t, fmt.Sprintf("user%d@example.com", i))
		}
		err := f.service.SendCode(
			context.Background(),
			SendCodeInput{Email: "another@example.com", IP: "192.0.2.1"},
		)
		requireError(t, err, ErrTooManyRequests)
		if err := f.service.SendCode(
			context.Background(),
			SendCodeInput{Email: "another@example.com", IP: "192.0.2.2"},
		); err != nil {
			t.Fatal(err)
		}
		for key := range f.store.state.rates {
			if strings.Contains(key, "@") || strings.Contains(key, "192.0.2.") {
				t.Fatal("rate keys expose raw identifiers")
			}
		}
	})
}

// TestSendFailureAndReplacement keeps undelivered or superseded challenges unusable.
func TestSendFailureAndReplacement(t *testing.T) {
	t.Run("delivery failure", func(t *testing.T) {
		f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
		f.mail.err = errors.New("provider failure")
		err := f.service.SendCode(
			context.Background(),
			SendCodeInput{Email: "alice@example.com", IP: "192.0.2.1"},
		)
		requireError(t, err, ErrMailFailed)
		_, err = f.service.LoginEmail(
			context.Background(),
			EmailLoginInput{Email: "alice@example.com", Code: f.mail.code},
		)
		requireError(t, err, ErrChallengeInvalid)
		f.mail.err = nil
		f.now = f.now.Add(ResendInterval)
		f.loginEmail(t, "alice@example.com")
	})
	t.Run("late delivery", func(t *testing.T) {
		f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
		var current string
		f.mail.hook = func() {
			f.mail.hook = nil
			f.now = f.now.Add(ResendInterval)
			current = f.issue(t, "alice@example.com")
		}
		err := f.service.SendCode(
			context.Background(),
			SendCodeInput{Email: "alice@example.com", IP: "192.0.2.1"},
		)
		requireError(t, err, ErrChallengeUpdated)
		_, err = f.service.LoginEmail(
			context.Background(),
			EmailLoginInput{Email: "alice@example.com", Code: current},
		)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("late delivery with repeated code", func(t *testing.T) {
		f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
		ctx := context.Background()
		f.mail.hook = func() {
			f.mail.hook = nil
			// Model a later issuance randomly choosing the same six-digit code.
			newer := f.store.state.challenges["alice@example.com"]
			newer.Sent = newer.Sent.Add(ResendInterval)
			newer.Expires = newer.Sent.Add(CodeTTL)
			f.store.state.challenges[newer.Email] = newer
		}
		err := f.service.SendCode(ctx, SendCodeInput{Email: "alice@example.com", IP: "192.0.2.1"})
		requireError(t, err, ErrChallengeUpdated)
		if f.store.state.challenges["alice@example.com"].Ready {
			t.Fatal("old delivery activated the newer undelivered challenge")
		}
		_, err = f.service.LoginEmail(
			ctx,
			EmailLoginInput{Email: "alice@example.com", Code: f.mail.code},
		)
		requireError(t, err, ErrChallengeInvalid)
	})
}

// TestRegistrationAdmission checks default denial, rollback and the account shown to the policy.
func TestRegistrationAdmission(t *testing.T) {
	t.Run("default denial and existing account", func(t *testing.T) {
		f := newFixture(t, nil)
		code := f.issue(t, "alice@example.com")
		_, err := f.service.LoginEmail(
			context.Background(),
			EmailLoginInput{Email: "alice@example.com", Code: code},
		)
		requireError(t, err, ErrRegistrationDenied)
		if len(f.store.state.accounts) != 0 || len(f.store.state.sessions) != 0 ||
			!f.store.state.challenges["alice@example.com"].Ready {
			t.Fatal("admission rejection leaked writes or consumed proof")
		}
		f.store.state.accounts["existing"] = Account{ID: "existing", Email: "alice@example.com"}
		f.store.state.bindings[bindingKey(MethodEmail, "alice@example.com")] = "existing"
		result, err := f.service.LoginEmail(
			context.Background(),
			EmailLoginInput{Email: "alice@example.com", Code: code},
		)
		if err != nil || result.Account.ID != "existing" || result.Created {
			t.Fatalf("existing login = %v, %v", result, err)
		}
	})
	t.Run("policy", func(t *testing.T) {
		var seen Registration
		f := newFixture(
			t,
			RegistrationPolicyFunc(
				func(_ context.Context, registration Registration) error { seen = registration; return errPolicyFailure },
			),
		)
		err := f.service.SendCode(
			context.Background(),
			SendCodeInput{Email: "alice@example.com", IP: "192.0.2.1"},
		)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.service.LoginEmail(
			context.Background(),
			EmailLoginInput{Email: "alice@example.com", Code: f.mail.code},
		)
		requireError(t, err, errPolicyFailure)
		if seen.Account.ID == "" || seen.Account.Email != "alice@example.com" ||
			seen.Method != MethodEmail {
			t.Fatalf("policy received %#v", seen)
		}
		if len(f.store.state.accounts) != 0 ||
			!f.store.state.challenges["alice@example.com"].Ready {
			t.Fatal("policy failure did not roll back")
		}
	})
}

// TestWechatLogin verifies new and returning identity behavior and exchange ordering.
func TestWechatLogin(t *testing.T) {
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	first, err := f.service.LoginWechat(
		ctx,
		"one-time-provider-code",
		WechatLoginInput{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || first.Account.Email != "" || f.wechat.calledInsideTransaction {
		t.Fatalf("unexpected first login: %#v", first)
	}
	second, err := f.service.LoginWechat(ctx, "next-provider-code", WechatLoginInput{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Created || first.Account.ID != second.Account.ID || first.Token == second.Token ||
		len(f.store.state.accounts) != 1 {
		t.Fatal("returning WeChat identity must reuse the account with a fresh session")
	}
	for key := range f.store.state.bindings {
		if strings.Contains(key, f.wechat.identity.OpenID) {
			t.Fatal("raw OpenID was persisted")
		}
	}
	f.wechat.identity.OpenID = "another-verified-open-id"
	third, err := f.service.LoginWechat(ctx, "another-code", WechatLoginInput{})
	if err != nil || third.Account.ID == first.Account.ID {
		t.Fatalf("second WeChat-only account = %v, %v", third, err)
	}
}

// TestWechatEmailProof attaches an unused identity to an existing proved mailbox.
func TestWechatEmailProof(t *testing.T) {
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	account := f.loginEmail(t, "alice@example.com")
	f.now = f.now.Add(ResendInterval)
	code := f.issue(t, "alice@example.com")
	result, err := f.service.LoginWechat(
		ctx,
		"provider-code",
		WechatLoginInput{Email: "alice@example.com", EmailCode: code},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Created || result.Account.ID != account.Account.ID ||
		len(f.store.state.accounts) != 1 {
		t.Fatal("proved email did not reuse its existing account")
	}
	f.wechat.identity.OpenID = "different-open-id"
	f.now = f.now.Add(ResendInterval)
	code = f.issue(t, "alice@example.com")
	_, err = f.service.LoginWechat(
		ctx,
		"provider-code",
		WechatLoginInput{Email: "alice@example.com", EmailCode: code},
	)
	requireError(t, err, ErrWechatBound)
	if len(f.store.state.accounts) != 1 || !f.store.state.challenges["alice@example.com"].Ready {
		t.Fatal("binding conflict leaked writes")
	}
}

// TestWechatDoesNotMergeAccounts keeps independently registered email and WeChat identities separate.
func TestWechatDoesNotMergeAccounts(t *testing.T) {
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	emailUser := f.loginEmail(t, "alice@example.com")
	wxUser, err := f.service.LoginWechat(ctx, "provider-code", WechatLoginInput{})
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(ResendInterval)
	code := f.issue(t, "alice@example.com")
	_, err = f.service.BindEmail(
		ctx,
		wxUser.Token,
		BindEmailInput{Email: "alice@example.com", Code: code},
	)
	requireError(t, err, ErrEmailAccountConflict)
	_, err = f.service.LoginWechat(
		ctx,
		"another-provider-code",
		WechatLoginInput{Email: "alice@example.com", EmailCode: code},
	)
	requireError(t, err, ErrEmailAccountConflict)
	if len(f.store.state.accounts) != 2 || f.store.state.accounts[wxUser.Account.ID].Email != "" ||
		f.store.state.accounts[emailUser.Account.ID].Email == "" {
		t.Fatal("binding merged independent accounts")
	}
	if _, err := f.service.Authenticate(ctx, wxUser.Token); err != nil {
		t.Fatal("failed binding revoked a valid session")
	}
}

// TestBindEmailRotatesSession ensures email binding consumes proof and replaces the current token.
func TestBindEmailRotatesSession(t *testing.T) {
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	initial, err := f.service.LoginWechat(ctx, "provider-code", WechatLoginInput{})
	if err != nil {
		t.Fatal(err)
	}
	otherDevice, err := f.service.LoginWechat(ctx, "other-device-code", WechatLoginInput{})
	if err != nil {
		t.Fatal(err)
	}
	code := f.issue(t, "alice@example.com")
	bound, err := f.service.BindEmail(
		ctx,
		initial.Token,
		BindEmailInput{Email: "alice@example.com", Code: code},
	)
	if err != nil {
		t.Fatal(err)
	}
	if bound.Created || bound.Account.ID != initial.Account.ID ||
		bound.Account.Email != "alice@example.com" ||
		bound.Token == initial.Token {
		t.Fatalf("unexpected bind result: %#v", bound)
	}
	_, err = f.service.Authenticate(ctx, initial.Token)
	requireError(t, err, ErrUnauthorized)
	user, err := f.service.Authenticate(ctx, bound.Token)
	if err != nil || user.Email != "alice@example.com" {
		t.Fatalf("bound authenticate = %v, %v", user, err)
	}
	if user, err := f.service.Authenticate(
		ctx,
		otherDevice.Token,
	); err != nil ||
		user.Email != "alice@example.com" {
		t.Fatalf("other device session = %v, %v", user, err)
	}
	_, err = f.service.LoginEmail(ctx, EmailLoginInput{Email: "alice@example.com", Code: code})
	requireError(t, err, ErrChallengeInvalid)
	f.now = f.now.Add(ResendInterval)
	code = f.issue(t, "other@example.com")
	_, err = f.service.BindEmail(
		ctx,
		bound.Token,
		BindEmailInput{Email: "other@example.com", Code: code},
	)
	requireError(t, err, ErrEmailBound)
}

// TestWechatAdmissionAndProviderFailure proves rejected identities cannot leave state behind.
func TestWechatAdmissionAndProviderFailure(t *testing.T) {
	ctx := context.Background()
	t.Run("missing policy", func(t *testing.T) {
		f := newFixture(t, nil)
		_, err := f.service.LoginWechat(ctx, "provider-code", WechatLoginInput{})
		requireError(t, err, ErrRegistrationDenied)
		if len(f.store.state.accounts) != 0 || len(f.store.state.bindings) != 0 ||
			len(f.store.state.sessions) != 0 {
			t.Fatal("denied WeChat registration persisted identity state")
		}
	})
	t.Run("admission", func(t *testing.T) {
		var seen Registration
		f := newFixture(
			t,
			RegistrationPolicyFunc(
				func(_ context.Context, registration Registration) error { seen = registration; return nil },
			),
		)
		if err := f.service.SendCode(
			ctx,
			SendCodeInput{Email: "alice@example.com", IP: "192.0.2.1"},
		); err != nil {
			t.Fatal(err)
		}
		result, err := f.service.LoginWechat(
			ctx,
			"provider-code",
			WechatLoginInput{Email: "alice@example.com", EmailCode: f.mail.code},
		)
		if err != nil {
			t.Fatal(err)
		}
		if seen.Account.ID != result.Account.ID ||
			seen.Account.Email != "alice@example.com" ||
			seen.Method != "wechat" {
			t.Fatalf("unexpected WeChat admission: %#v", seen)
		}
	})
	t.Run("provider failure", func(t *testing.T) {
		f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
		f.wechat.err = ErrWechatLogin
		_, err := f.service.LoginWechat(ctx, "provider-code", WechatLoginInput{})
		requireError(t, err, ErrWechatLogin)
		if len(f.store.state.accounts) != 0 || len(f.store.state.bindings) != 0 ||
			len(f.store.state.sessions) != 0 {
			t.Fatal("failed provider exchange persisted identity state")
		}
	})
}

// TestTransactionPolicyOverride requires admission bound explicitly to the caller's transaction.
func TestTransactionPolicyOverride(t *testing.T) {
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	code := f.issue(t, "alice@example.com")
	err := f.store.WithTransaction(ctx, func(repos Repositories) error {
		_, err := f.service.InTransaction(repos, nil).
			LoginEmail(ctx, EmailLoginInput{Email: "alice@example.com", Code: code})
		return err
	})
	requireError(t, err, ErrRegistrationDenied)
	if len(f.store.state.accounts) != 0 || !f.store.state.challenges["alice@example.com"].Ready {
		t.Fatal("transaction inherited a standalone admission policy")
	}
}

// TestHostTransactionRollback discards identity writes when later host work fails.
func TestHostTransactionRollback(t *testing.T) {
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	code := f.issue(t, "alice@example.com")
	hostErr := errors.New("host group membership failed")
	var issued *LoginResult
	err := f.store.WithTransaction(ctx, func(repos Repositories) error {
		outcome, err := f.service.InTransaction(repos, RegistrationPolicyFunc(allowRegistration)).
			LoginEmail(ctx, EmailLoginInput{Email: "alice@example.com", Code: code})
		if err != nil {
			return err
		}
		if outcome.Rejected != nil {
			return outcome.Rejected
		}
		issued = outcome.Login
		return hostErr
	})
	requireError(t, err, hostErr)
	if issued == nil || len(f.store.state.accounts) != 0 || len(f.store.state.sessions) != 0 ||
		!f.store.state.challenges["alice@example.com"].Ready {
		t.Fatal("host failure did not roll back account, session and proof")
	}
	_, err = f.service.Authenticate(ctx, issued.Token)
	requireError(t, err, ErrUnauthorized)
	if _, err := f.service.LoginEmail(
		ctx,
		EmailLoginInput{Email: "alice@example.com", Code: code},
	); err != nil {
		t.Fatal("rolled-back proof could not be retried:", err)
	}
}

// TestHostTransactionRejected commits a bad attempt without permitting subsequent business work.
func TestHostTransactionRejected(t *testing.T) {
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	code := f.issue(t, "alice@example.com")
	var rejected error
	err := f.store.WithTransaction(ctx, func(repos Repositories) error {
		outcome, err := f.service.InTransaction(repos, RegistrationPolicyFunc(allowRegistration)).
			LoginEmail(ctx, EmailLoginInput{Email: "alice@example.com", Code: differentCode(code)})
		if err != nil {
			return err
		}
		rejected = outcome.Rejected
		if outcome.Login != nil {
			t.Fatal("rejected proof issued a token")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, rejected, ErrChallengeMismatch)
	if f.store.state.challenges["alice@example.com"].Attempts != 1 ||
		len(f.store.state.accounts) != 0 {
		t.Fatal("rejected outcome did not preserve only the failed attempt")
	}
}

// TestSessionExpiry treats the exact expiration instant as unauthorized.
func TestSessionExpiry(t *testing.T) {
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	login := f.loginEmail(t, "alice@example.com")
	f.now = login.Expires.Add(-time.Nanosecond)
	if _, err := f.service.Authenticate(context.Background(), login.Token); err != nil {
		t.Fatal(err)
	}
	f.now = login.Expires
	_, err := f.service.Authenticate(context.Background(), login.Token)
	requireError(t, err, ErrUnauthorized)
}

// TestInputValidation prevents malformed inputs and unknown credentials from producing state.
func TestInputValidation(t *testing.T) {
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	for _, email := range []string{"", "not-an-email", "Alice <alice@example.com>"} {
		requireError(
			t,
			f.service.SendCode(ctx, SendCodeInput{Email: email, IP: "192.0.2.1"}),
			ErrInvalidEmail,
		)
	}
	for _, token := range []string{"", "unknown-token"} {
		_, err := f.service.Authenticate(ctx, token)
		requireError(t, err, ErrUnauthorized)
	}
	_, err := f.service.LoginEmail(ctx, EmailLoginInput{Email: "alice@example.com", Code: "123456"})
	requireError(t, err, ErrChallengeInvalid)
	if len(f.store.state.accounts) != 0 || len(f.store.state.sessions) != 0 ||
		len(f.store.state.challenges) != 0 {
		t.Fatal("invalid requests persisted identity state")
	}
}

// TestUnissuedMailboxDoesNotAllocateChallenge prevents unauthenticated guesses from creating rows.
func TestUnissuedMailboxDoesNotAllocateChallenge(t *testing.T) {
	f := newFixture(t, RegistrationPolicyFunc(allowRegistration))
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, err := f.service.LoginEmail(
			ctx,
			EmailLoginInput{Email: fmt.Sprintf("unissued%d@example.com", i), Code: "123456"},
		)
		requireError(t, err, ErrChallengeInvalid)
	}
	var rejected error
	err := f.store.WithTransaction(ctx, func(repos Repositories) error {
		outcome, err := f.service.InTransaction(repos, nil).
			LoginEmail(ctx, EmailLoginInput{Email: "unissued-host@example.com", Code: "123456"})
		rejected = outcome.Rejected
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, rejected, ErrChallengeInvalid)
	if len(f.store.state.challenges) != 0 || len(f.store.state.accounts) != 0 ||
		len(f.store.state.sessions) != 0 {
		t.Fatal("unissued mailbox guesses allocated durable identity state")
	}
}
