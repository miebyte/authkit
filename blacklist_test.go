package authkit

import (
	"context"
	"errors"
	"maps"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestBlacklistBlocksUnregisteredCredentials(t *testing.T) {
	for _, method := range []string{MethodEmail, MethodWechat} {
		t.Run(method, func(t *testing.T) {
			f := newBlacklistFixture(t)
			credential := Credential{Method: method, Identifier: "blocked@example.com"}
			if method == MethodWechat {
				credential.Identifier = "BlockedOpenID"
				f.wechat.identity.OpenID = credential.Identifier
			}
			if err := f.service.AddBlacklist(context.Background(), credential); err != nil {
				t.Fatal(err)
			}
			if method == MethodEmail {
				requireBlacklistError(t, f.service.SendCode(context.Background(), SendCodeInput{
					Email: credential.Identifier, IP: "192.0.2.1",
				}), ErrBlacklisted)
				result, err := f.service.LoginEmail(context.Background(), EmailLoginInput{
					Email: credential.Identifier, Code: "123456",
				})
				requireBlacklistError(t, err, ErrBlacklisted)
				if result != nil || f.mail.sent != 0 || f.store.challengeReads != 0 {
					t.Fatal("blocked email reached delivery or code verification")
				}
			} else {
				result, err := f.service.LoginWechat(context.Background(), "provider-code")
				requireBlacklistError(t, err, ErrBlacklisted)
				if result != nil {
					t.Fatal("blocked OpenID received a session")
				}
			}
			if f.authorized != 0 || len(f.store.accounts) != 0 || len(f.store.sessions) != 0 {
				t.Fatal("blocked credential reached registration or session creation")
			}
		})
	}
}

func TestBlacklistDisablesAllBindingsAndDoesNotRestoreOldProofs(t *testing.T) {
	for _, method := range []string{MethodEmail, MethodWechat} {
		t.Run(method, func(t *testing.T) {
			f := newBlacklistFixture(t)
			accountID := strings.Repeat("a", 64)
			f.store.bind(accountID, "user@example.com", "UserOpenID")
			f.wechat.identity.OpenID = "UserOpenID"
			emailLogin := f.loginEmail(t, "user@example.com")
			wechatLogin, err := f.service.LoginWechat(context.Background(), "provider-code")
			if err != nil {
				t.Fatal(err)
			}
			f.now = f.now.Add(ResendInterval)
			pendingCode := f.sendCode(t, "user@example.com")
			credential := Credential{Method: method, Identifier: "user@example.com"}
			if method == MethodWechat {
				credential.Identifier = "UserOpenID"
			}
			if err := f.service.AddBlacklist(context.Background(), credential); err != nil {
				t.Fatal(err)
			}
			requireBlacklistError(t, f.service.SendCode(context.Background(), SendCodeInput{
				Email: "user@example.com", IP: "192.0.2.1",
			}), ErrBlacklisted)
			_, err = f.service.LoginEmail(context.Background(), EmailLoginInput{
				Email: "user@example.com", Code: pendingCode,
			})
			requireBlacklistError(t, err, ErrBlacklisted)
			_, err = f.service.LoginWechat(context.Background(), "provider-code")
			requireBlacklistError(t, err, ErrBlacklisted)
			for _, token := range []string{emailLogin.Token, wechatLogin.Token} {
				if account, err := f.service.Authenticate(
					context.Background(),
					token,
				); err == nil ||
					account != nil {
					t.Fatal("blacklisted account retained an existing session")
				}
			}
			other := f.loginEmail(t, "other@example.com")
			if _, err := f.service.Authenticate(context.Background(), other.Token); err != nil {
				t.Fatalf("unrelated account was blocked: %v", err)
			}
			page, err := f.service.ListBlacklist(context.Background(), 1, 10)
			if err != nil || len(page.Items) != 1 {
				t.Fatalf("blacklist = %+v, err = %v", page, err)
			}
			if err := f.service.RemoveBlacklist(
				context.Background(),
				page.Items[0].ID,
			); err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{emailLogin.Token, wechatLogin.Token} {
				_, err := f.service.Authenticate(context.Background(), token)
				requireBlacklistError(t, err, ErrUnauthorized)
			}
			if method == MethodEmail {
				_, err = f.service.LoginEmail(context.Background(), EmailLoginInput{
					Email: "user@example.com", Code: pendingCode,
				})
				requireBlacklistError(t, err, ErrChallengeInvalid)
			}
			f.now = f.now.Add(ResendInterval)
			fresh := f.loginEmail(t, "user@example.com")
			if fresh.Account.ID != accountID || fresh.Created {
				t.Fatal("unblocked login did not use the existing account")
			}
			if _, err := f.service.LoginWechat(context.Background(), "provider-code"); err != nil {
				t.Fatalf("unblocked OpenID could not login: %v", err)
			}
		})
	}
}

func TestBlacklistAuthenticateChecksAccountBindings(t *testing.T) {
	f := newBlacklistFixture(t)
	login := f.loginEmail(t, "user@example.com")
	// Authenticate 必须独立检查绑定，覆盖黑名单已有记录但会话仍存在的情况。
	f.store.entries[blacklistCredentialKey(Credential{Method: MethodEmail, Identifier: "user@example.com"})] = BlacklistEntry{
		ID:         strings.Repeat("b", 64),
		Method:     MethodEmail,
		Identifier: "user@example.com",
	}
	account, err := f.service.Authenticate(context.Background(), login.Token)
	requireBlacklistError(t, err, ErrBlacklisted)
	if account != nil {
		t.Fatal("blocked authentication returned an account")
	}
}

func TestBlacklistRejectsHostTransactionLogin(t *testing.T) {
	for _, method := range []string{MethodEmail, MethodWechat} {
		t.Run(method, func(t *testing.T) {
			f := newBlacklistFixture(t)
			credential := Credential{Method: method, Identifier: "blocked@example.com"}
			if method == MethodWechat {
				credential.Identifier = "BlockedOpenID"
			}
			if err := f.service.AddBlacklist(context.Background(), credential); err != nil {
				t.Fatal(err)
			}
			tx := f.service.InTransaction(f.store, f.policy)
			var outcome Outcome
			var err error
			if method == MethodEmail {
				outcome, err = tx.LoginEmail(context.Background(), EmailLoginInput{
					Email: credential.Identifier, Code: "123456",
				})
			} else {
				outcome, err = tx.LoginWechat(context.Background(), WechatIdentity{
					AppID: "test-app", OpenID: credential.Identifier,
				})
			}
			requireBlacklistError(t, err, ErrBlacklisted)
			if outcome.Login != nil || f.authorized != 0 || len(f.store.accounts) != 0 {
				t.Fatal("host transaction bypassed the blacklist")
			}
		})
	}
}

func TestBlacklistAddedDuringDeliveryCannotActivateCode(t *testing.T) {
	f := newBlacklistFixture(t)
	f.mail.afterSend = func() {
		if err := f.service.AddBlacklist(context.Background(), Credential{
			Method: MethodEmail, Identifier: "user@example.com",
		}); err != nil {
			t.Fatal(err)
		}
	}
	err := f.service.SendCode(
		context.Background(),
		SendCodeInput{Email: "user@example.com", IP: "192.0.2.1"},
	)
	requireBlacklistError(t, err, ErrBlacklisted)
	if f.store.challenges["user@example.com"].Ready {
		t.Fatal("code was activated after its email was blacklisted during delivery")
	}
}

func TestBlacklistStorageFailureRejectsRequests(t *testing.T) {
	backendError := errors.New("blacklist backend unavailable")
	for _, operation := range []string{"send", "email", "wechat", "authenticate", "activate", "account", "newaccount", "newwechataccount"} {
		t.Run(operation, func(t *testing.T) {
			f := newBlacklistFixture(t)
			var err error
			if operation == "authenticate" {
				login := f.loginEmail(t, "user@example.com")
				f.store.accountCheckError = backendError
				_, err = f.service.Authenticate(context.Background(), login.Token)
			} else if operation == "activate" {
				f.mail.afterSend = func() { f.store.checkError = backendError }
				err = f.service.SendCode(
					context.Background(),
					SendCodeInput{Email: "user@example.com"},
				)
				if f.store.challenges["user@example.com"].Ready {
					t.Fatal("failed blacklist lookup activated a code")
				}
			} else if operation == "account" || operation == "newaccount" {
				if operation == "account" {
					f.store.bind(strings.Repeat("a", 64), "user@example.com", "")
				}
				code := f.sendCode(t, "user@example.com")
				f.store.accountCheckError = backendError
				_, err = f.service.LoginEmail(
					context.Background(),
					EmailLoginInput{Email: "user@example.com", Code: code},
				)
				if !f.store.challenges["user@example.com"].Ready || len(f.store.sessions) != 0 {
					t.Fatal("failed account blacklist lookup consumed the code or issued a session")
				}
				if operation == "newaccount" && len(f.store.accounts) != 0 {
					t.Fatal("failed account blacklist lookup persisted a new account")
				}
			} else if operation == "newwechataccount" {
				f.store.accountCheckError = backendError
				_, err = f.service.LoginWechat(context.Background(), "provider-code")
				if len(f.store.accounts) != 0 || len(f.store.sessions) != 0 {
					t.Fatal(
						"failed account blacklist lookup persisted a new WeChat account or session",
					)
				}
			} else {
				f.store.checkError = backendError
				switch operation {
				case "send":
					err = f.service.SendCode(
						context.Background(),
						SendCodeInput{Email: "user@example.com"},
					)
				case "email":
					_, err = f.service.LoginEmail(
						context.Background(),
						EmailLoginInput{Email: "user@example.com", Code: "123456"},
					)
				case "wechat":
					_, err = f.service.LoginWechat(context.Background(), "provider-code")
				}
				if f.mail.sent != 0 || f.authorized != 0 || len(f.store.sessions) != 0 {
					t.Fatal("failed blacklist lookup allowed an identity operation")
				}
			}
			requireBlacklistError(t, err, backendError)
		})
	}
}

func TestBlacklistNormalizesEmailAndPreservesOpenIDCase(t *testing.T) {
	f := newBlacklistFixture(t)
	for _, email := range []string{" User@Example.COM ", "user@example.com"} {
		if err := f.service.AddBlacklist(
			context.Background(),
			Credential{Method: MethodEmail, Identifier: email},
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.service.AddBlacklist(
		context.Background(),
		Credential{Method: MethodWechat, Identifier: "MixedCaseOpenID"},
	); err != nil {
		t.Fatal(err)
	}
	page, err := f.service.ListBlacklist(context.Background(), 1, 10)
	if err != nil || page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("blacklist = %+v, err = %v", page, err)
	}
	for _, entry := range page.Items {
		if entry.Method == MethodWechat && entry.Identifier != "" {
			t.Fatal("blacklist list exposed the OpenID digest")
		}
	}
	for _, entry := range f.store.entries {
		identifier := "user@example.com"
		if entry.Method == MethodWechat {
			identifier = digest("MixedCaseOpenID")
		}
		if entry.Identifier != identifier || entry.ID != digest(entry.Method+":"+identifier) {
			t.Fatalf("stored blacklist identity = %+v", entry)
		}
		if !entry.CreatedAt.Equal(f.now) {
			t.Fatalf("CreatedAt = %v, want %v", entry.CreatedAt, f.now)
		}
	}
	requireBlacklistError(
		t,
		f.service.SendCode(context.Background(), SendCodeInput{Email: " USER@EXAMPLE.COM "}),
		ErrBlacklisted,
	)
	f.wechat.identity.OpenID = "MixedCaseOpenID"
	_, err = f.service.LoginWechat(context.Background(), "provider-code")
	requireBlacklistError(t, err, ErrBlacklisted)
	f.wechat.identity.OpenID = "mixedcaseopenid"
	if _, err := f.service.LoginWechat(context.Background(), "provider-code"); err != nil {
		t.Fatalf("different OpenID case was blocked: %v", err)
	}
}

func TestBlacklistRejectsInvalidCredentials(t *testing.T) {
	for _, credential := range []Credential{
		{Method: "other", Identifier: "user@example.com"},
		{Method: MethodEmail, Identifier: "invalid"},
		{Method: MethodEmail, Identifier: "User <user@example.com>"},
		{Method: MethodWechat, Identifier: " \t "},
		{Method: MethodWechat, Identifier: strings.Repeat("a", 129)},
	} {
		t.Run(credential.Method+"/"+credential.Identifier, func(t *testing.T) {
			f := newBlacklistFixture(t)
			if err := f.service.AddBlacklist(context.Background(), credential); err == nil {
				t.Fatal("invalid credential was added to the blacklist")
			}
			if len(f.store.entries) != 0 {
				t.Fatal("invalid credential reached storage")
			}
		})
	}
	f := newBlacklistFixture(t)
	if err := f.service.AddBlacklist(
		context.Background(),
		Credential{Method: MethodWechat, Identifier: strings.Repeat("a", 128)},
	); err != nil {
		t.Fatalf("valid OpenID length was rejected: %v", err)
	}
}

func TestAdminBlacklistProtectsConfiguredAccount(t *testing.T) {
	f := newBlacklistFixture(t)
	adminID := strings.Repeat("a", 64)
	f.store.bind(adminID, "admin@example.com", "AdminOpenID")
	for _, credential := range []Credential{
		{Method: MethodEmail, Identifier: " ADMIN@Example.com "},
		{Method: MethodWechat, Identifier: "AdminOpenID"},
	} {
		requireBlacklistError(
			t,
			f.service.AdminAddBlacklist(context.Background(), credential, adminID),
			ErrProtectedAccount,
		)
	}
	if len(f.store.entries) != 0 {
		t.Fatal("administrator's binding was blacklisted")
	}
	if err := f.service.AdminAddBlacklist(context.Background(), Credential{
		Method: MethodEmail, Identifier: "other@example.com",
	}, adminID); err != nil {
		t.Fatalf("unrelated credential could not be blacklisted: %v", err)
	}
}

func TestBlacklistManagementRejectsInvalidInput(t *testing.T) {
	f := newBlacklistFixture(t)
	for _, id := range []string{"", "invalid-id"} {
		requireBlacklistError(
			t,
			f.service.RemoveBlacklist(context.Background(), id),
			ErrInvalidInput,
		)
		requireBlacklistError(t, f.service.AdminAddBlacklist(context.Background(), Credential{
			Method: MethodEmail, Identifier: "user@example.com",
		}, id), ErrInvalidInput)
	}
	for _, input := range [][2]int{{0, 10}, {1, 0}, {1, 101}, {int(^uint(0) >> 1), 100}} {
		_, err := f.service.ListBlacklist(context.Background(), input[0], input[1])
		requireBlacklistError(t, err, ErrInvalidInput)
	}
	if err := f.service.RemoveBlacklist(context.Background(), strings.Repeat("a", 64)); err != nil {
		t.Fatalf("removing an absent entry was not idempotent: %v", err)
	}
	if len(f.store.entries) != 0 {
		t.Fatal("invalid management request created a blacklist entry")
	}
}

type blacklistFixture struct {
	service    *Service
	store      *blacklistMemoryStore
	mail       *blacklistMail
	wechat     *blacklistWechat
	policy     RegistrationPolicy
	now        time.Time
	authorized int
}

func newBlacklistFixture(t *testing.T) *blacklistFixture {
	t.Helper()
	f := &blacklistFixture{
		store: &blacklistMemoryStore{
			accounts: make(map[string]Account), bindings: make(map[string]string),
			challenges: make(map[string]Challenge), sessions: make(map[string]Session),
			entries:   make(map[string]BlacklistEntry),
			passwords: make(map[string]string), rates: make(map[string]blacklistRate),
		},
		mail:   &blacklistMail{},
		wechat: &blacklistWechat{identity: WechatIdentity{AppID: "test-app", OpenID: "TestOpenID"}},
		now:    time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC),
	}
	f.policy = RegistrationPolicyFunc(
		func(context.Context, Registration) error { f.authorized++; return nil },
	)
	var err error
	f.service, err = NewService(f.store, f.mail, f.wechat, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	f.service.now = func() time.Time { return f.now }
	return f
}

func (f *blacklistFixture) sendCode(t *testing.T, email string) string {
	t.Helper()
	if err := f.service.SendCode(
		context.Background(),
		SendCodeInput{Email: email, IP: "192.0.2.1"},
	); err != nil {
		t.Fatal(err)
	}
	return f.mail.code
}

func (f *blacklistFixture) loginEmail(t *testing.T, email string) *LoginResult {
	t.Helper()
	code := f.sendCode(t, email)
	result, err := f.service.LoginEmail(
		context.Background(),
		EmailLoginInput{Email: email, Code: code},
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func requireBlacklistError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

type blacklistMail struct {
	code      string
	sent      int
	afterSend func()
}

func (s *blacklistMail) SendCode(_ context.Context, _ string, code string) error {
	s.code = code
	s.sent++
	if s.afterSend != nil {
		s.afterSend()
	}
	return nil
}

type blacklistWechat struct{ identity WechatIdentity }

func (s *blacklistWechat) ExchangeCode(context.Context, string) (WechatIdentity, error) {
	return s.identity, nil
}

type blacklistMemoryStore struct {
	accounts          map[string]Account
	bindings          map[string]string
	challenges        map[string]Challenge
	sessions          map[string]Session
	entries           map[string]BlacklistEntry
	passwords         map[string]string
	rates             map[string]blacklistRate
	checkError        error
	accountCheckError error
	accountCheckHook  func(string)
	challengeReads    int
}

func (s *blacklistMemoryStore) WithTransaction(
	_ context.Context,
	fn func(Repositories) error,
) error {
	accounts, bindings := maps.Clone(s.accounts), maps.Clone(s.bindings)
	challenges, sessions, entries := maps.Clone(
		s.challenges,
	), maps.Clone(
		s.sessions,
	), maps.Clone(
		s.entries,
	)
	passwords, rates := maps.Clone(s.passwords), maps.Clone(s.rates)
	if err := fn(s); err != nil {
		s.accounts, s.bindings, s.challenges, s.sessions, s.entries = accounts, bindings, challenges, sessions, entries
		s.passwords, s.rates = passwords, rates
		return err
	}
	return nil
}

func (s *blacklistMemoryStore) Accounts() AccountRepository     { return blacklistAccounts{s} }
func (s *blacklistMemoryStore) Challenges() ChallengeRepository { return blacklistChallenges{s} }
func (s *blacklistMemoryStore) Rates() RateRepository           { return blacklistRates{s} }
func (s *blacklistMemoryStore) Sessions() SessionRepository     { return blacklistSessions{s} }
func (s *blacklistMemoryStore) Blacklist() BlacklistRepository  { return blacklistRepository{s} }

func (s *blacklistMemoryStore) bind(id, email, openID string) {
	s.accounts[id] = Account{ID: id, Email: email}
	if email != "" {
		s.bindings[blacklistCredentialKey(Credential{Method: MethodEmail, Identifier: email})] = id
	}
	if openID != "" {
		s.bindings[blacklistCredentialKey(Credential{Method: MethodWechat, Identifier: digest(openID)})] = id
	}
}

func blacklistCredentialKey(credential Credential) string {
	return credential.Method + "\x00" + credential.Identifier
}

type blacklistAccounts struct{ store *blacklistMemoryStore }

func (r blacklistAccounts) GetByID(_ context.Context, id string) (*Account, error) {
	account, ok := r.store.accounts[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &account, nil
}

func (r blacklistAccounts) GetByPasswordIdentifier(
	_ context.Context,
	identifier string,
) (*Account, error) {
	return r.lookup(Credential{Method: MethodPassword, Identifier: identifier})
}

func (r blacklistAccounts) GetPasswordIdentifier(
	_ context.Context,
	accountID string,
) (string, error) {
	for key, owner := range r.store.bindings {
		if owner == accountID && strings.HasPrefix(key, MethodPassword+"\x00") {
			return strings.TrimPrefix(key, MethodPassword+"\x00"), nil
		}
	}
	return "", ErrNotFound
}

func (r blacklistAccounts) lookup(credential Credential) (*Account, error) {
	id, ok := r.store.bindings[blacklistCredentialKey(credential)]
	if !ok {
		return nil, ErrNotFound
	}
	account := r.store.accounts[id]
	return &account, nil
}

func (r blacklistAccounts) GetByEmail(_ context.Context, email string) (*Account, error) {
	return r.lookup(Credential{Method: MethodEmail, Identifier: email})
}

func (r blacklistAccounts) GetByWechat(_ context.Context, hash string) (*Account, error) {
	return r.lookup(Credential{Method: MethodWechat, Identifier: hash})
}

func (r blacklistAccounts) Create(
	_ context.Context,
	account *Account,
	credential Credential,
) error {
	key := blacklistCredentialKey(credential)
	if _, ok := r.store.bindings[key]; ok {
		return ErrConflict
	}
	r.store.accounts[account.ID], r.store.bindings[key] = *account, account.ID
	return nil
}

func (r blacklistAccounts) GetBySessionToken(
	_ context.Context,
	hash string,
	now time.Time,
) (*Account, error) {
	session, ok := r.store.sessions[hash]
	if !ok || !now.Before(session.Expires) {
		return nil, ErrNotFound
	}
	account, ok := r.store.accounts[session.AccountID]
	if !ok {
		return nil, ErrNotFound
	}
	return &account, nil
}

type blacklistChallenges struct{ store *blacklistMemoryStore }

func (r blacklistChallenges) Get(_ context.Context, email string) (*Challenge, error) {
	r.store.challengeReads++
	challenge := r.store.challenges[email]
	challenge.Email = email
	return &challenge, nil
}

func (r blacklistChallenges) Find(_ context.Context, email string) (*Challenge, error) {
	r.store.challengeReads++
	challenge, ok := r.store.challenges[email]
	if !ok {
		return nil, ErrNotFound
	}
	return &challenge, nil
}

func (r blacklistChallenges) Save(_ context.Context, challenge *Challenge) error {
	r.store.challenges[challenge.Email] = *challenge
	return nil
}

func (r blacklistAccounts) GetPasswordHash(_ context.Context, accountID string) (string, error) {
	hash, ok := r.store.passwords[accountID]
	if !ok {
		return "", ErrNotFound
	}
	return hash, nil
}

func (r blacklistAccounts) SetPasswordHash(
	ctx context.Context,
	accountID, identifier, hash string,
) error {
	key := blacklistCredentialKey(Credential{Method: MethodPassword, Identifier: identifier})
	if owner := r.store.bindings[key]; owner != "" && owner != accountID {
		return ErrConflict
	}
	if existing, err := r.GetPasswordIdentifier(
		ctx,
		accountID,
	); err == nil &&
		existing != identifier {
		return ErrConflict
	}
	r.store.bindings[key], r.store.passwords[accountID] = accountID, hash
	return nil
}

type blacklistRate struct {
	Starts time.Time
	Hits   int
}

type blacklistRates struct{ store *blacklistMemoryStore }

func (r blacklistRates) Hit(_ context.Context, id string, now time.Time, limit int) error {
	rate := r.store.rates[id]
	if rate.Starts.IsZero() || now.Sub(rate.Starts) >= time.Hour {
		rate = blacklistRate{Starts: now}
	}
	if rate.Hits >= limit {
		return ErrTooManyRequests
	}
	rate.Hits++
	r.store.rates[id] = rate
	return nil
}

type blacklistSessions struct{ store *blacklistMemoryStore }

func (r blacklistSessions) Get(_ context.Context, hash string) (*Session, error) {
	session, ok := r.store.sessions[hash]
	if !ok {
		return nil, ErrNotFound
	}
	return &session, nil
}

func (r blacklistSessions) Create(_ context.Context, session *Session) error {
	r.store.sessions[session.Hash] = *session
	return nil
}

func (r blacklistSessions) Delete(_ context.Context, hash string) error {
	delete(r.store.sessions, hash)
	return nil
}

func (r blacklistSessions) DeleteByAccount(_ context.Context, accountID string) error {
	for hash, session := range r.store.sessions {
		if session.AccountID == accountID {
			delete(r.store.sessions, hash)
		}
	}
	return nil
}

type blacklistRepository struct{ store *blacklistMemoryStore }

func (r blacklistRepository) Check(_ context.Context, credential Credential) error {
	if r.store.checkError != nil {
		return r.store.checkError
	}
	if _, ok := r.store.entries[blacklistCredentialKey(credential)]; ok {
		return ErrBlacklisted
	}
	return nil
}

func (r blacklistRepository) CheckAccount(_ context.Context, accountID string) error {
	if r.store.accountCheckError != nil {
		return r.store.accountCheckError
	}
	if r.store.accountCheckHook != nil {
		r.store.accountCheckHook(accountID)
	}
	for key, owner := range r.store.bindings {
		if owner == accountID {
			if _, ok := r.store.entries[key]; ok {
				return ErrBlacklisted
			}
		}
	}
	return nil
}

func (r blacklistRepository) Add(_ context.Context, entry BlacklistEntry) error {
	key := blacklistCredentialKey(Credential{Method: entry.Method, Identifier: entry.Identifier})
	r.store.entries[key] = entry
	accountID := r.store.bindings[key]
	for hash, session := range r.store.sessions {
		if session.AccountID == accountID {
			delete(r.store.sessions, hash)
		}
	}
	if entry.Method == MethodEmail {
		delete(r.store.challenges, entry.Identifier)
	}
	return nil
}

func (r blacklistRepository) Remove(_ context.Context, id string) error {
	for key, entry := range r.store.entries {
		if entry.ID == id {
			delete(r.store.entries, key)
		}
	}
	return nil
}

func (r blacklistRepository) List(_ context.Context, page, limit int) (BlacklistPage, error) {
	if page < 1 || limit < 1 || limit > 100 {
		return BlacklistPage{}, ErrInvalidInput
	}
	items := make([]BlacklistEntry, 0, len(r.store.entries))
	for _, entry := range r.store.entries {
		if entry.Method == MethodWechat {
			entry.Identifier = ""
		}
		items = append(items, entry)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	start := min((page-1)*limit, len(items))
	end := min(start+limit, len(items))
	return BlacklistPage{
		Items: items[start:end],
		Total: int64(len(items)),
		Page:  page,
		Limit: limit,
	}, nil
}

func (s *blacklistMemoryStore) AdminOverview(context.Context, time.Time) (AdminOverview, error) {
	return AdminOverview{Accounts: int64(len(s.accounts))}, nil
}

func (s *blacklistMemoryStore) AdminListAccounts(
	_ context.Context,
	_ string,
	page, limit int,
	_ time.Time,
) (AdminAccountPage, error) {
	return AdminAccountPage{Page: page, Limit: limit, Total: int64(len(s.accounts))}, nil
}

func (s *blacklistMemoryStore) AdminGetAccount(
	_ context.Context,
	id string,
	_ time.Time,
) (AdminAccountDetail, error) {
	account, ok := s.accounts[id]
	if !ok {
		return AdminAccountDetail{}, ErrNotFound
	}
	return AdminAccountDetail{ID: id, Email: account.Email}, nil
}

func (s *blacklistMemoryStore) AdminDeleteBinding(_ context.Context, id, method string) error {
	for key, owner := range s.bindings {
		if owner == id && strings.HasPrefix(key, method+"\x00") {
			delete(s.bindings, key)
		}
	}
	return nil
}

func (s *blacklistMemoryStore) AdminRevokeSession(_ context.Context, id, hash string) error {
	if s.sessions[hash].AccountID == id {
		delete(s.sessions, hash)
	}
	return nil
}

func (s *blacklistMemoryStore) AdminRevokeAllSessions(_ context.Context, id string) error {
	for hash, session := range s.sessions {
		if session.AccountID == id {
			delete(s.sessions, hash)
		}
	}
	return nil
}
