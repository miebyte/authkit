package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miebyte/authkit"
)

const (
	testAdminID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testUserID  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type handlerFixture struct {
	service *authkit.Service
	auth    *handlerAuthStore
	mail    *handlerMail
	mux     *http.ServeMux
	handler http.Handler
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	f := &handlerFixture{
		auth: &handlerAuthStore{
			accounts: map[string]authkit.Account{
				testAdminID: {ID: testAdminID, Email: "admin@example.com"},
				testUserID:  {ID: testUserID, Email: "user@example.com"},
			},
			challenges: make(map[string]authkit.Challenge),
			sessions:   make(map[string]authkit.Session),
		},
		mail: &handlerMail{},
		mux:  http.NewServeMux(),
	}
	var err error
	f.service, err = authkit.NewService(f.auth, f.mail, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHTTPHandler(f.service, testAdminID)
	if err != nil {
		t.Fatal(err)
	}
	f.handler = handler
	f.mux.Handle("/authkit/admin/", http.StripPrefix("/authkit/admin", handler))
	return f
}

func (f *handlerFixture) request(method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func (f *handlerFixture) login(t *testing.T, email string) string {
	t.Helper()
	if err := f.service.SendCode(context.Background(), authkit.SendCodeInput{Email: email, IP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	result, err := f.service.LoginEmail(context.Background(), authkit.EmailLoginInput{Email: email, Code: f.mail.lastCode})
	if err != nil {
		t.Fatal(err)
	}
	return result.Token
}

func requireStatus(t *testing.T, got *httptest.ResponseRecorder, want int) {
	t.Helper()
	if got.Code != want {
		t.Fatalf("status = %d, want %d; body = %s", got.Code, want, got.Body.String())
	}
}

func TestConsolePageAndAssets(t *testing.T) {
	f := newHandlerFixture(t)
	for _, path := range []string{
		"/authkit/admin/",
		"/authkit/admin/assets/app.css",
		"/authkit/admin/assets/app.js",
	} {
		t.Run(path, func(t *testing.T) {
			response := f.request(http.MethodGet, path, "", "")
			requireStatus(t, response, http.StatusOK)
			if response.Body.Len() == 0 || response.Header().Get("Content-Type") == "" {
				t.Fatal("embedded resource is empty or missing its content type")
			}
			if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q", got)
			}
		})
	}
}

func TestHTTPHandlerServesConsoleAtRoot(t *testing.T) {
	f := newHandlerFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusOK)
	if response.Body.Len() == 0 {
		t.Fatal("console page is empty")
	}
}

func TestNewHTTPHandlerCustomPrefix(t *testing.T) {
	f := newHandlerFixture(t)
	handler, err := NewHTTPHandler(f.service, testAdminID)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/ops/", http.StripPrefix("/ops", handler))
	for _, path := range []string{"/ops/", "/ops/assets/app.css", "/ops/assets/app.js"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		requireStatus(t, response, http.StatusOK)
	}
	request := httptest.NewRequest(http.MethodGet, "/ops/api/me", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusUnauthorized)
	token := f.login(t, "admin@example.com")
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusOK)
}

func TestAdminAPIRequiresConfiguredAccount(t *testing.T) {
	f := newHandlerFixture(t)
	ordinaryToken := f.login(t, "user@example.com")
	requests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/authkit/admin/api/me"},
		{http.MethodGet, "/authkit/admin/api/overview"},
		{http.MethodGet, "/authkit/admin/api/accounts"},
		{http.MethodGet, "/authkit/admin/api/accounts/" + testUserID},
		{http.MethodDelete, "/authkit/admin/api/accounts/" + testUserID + "/bindings/email"},
		{http.MethodDelete, "/authkit/admin/api/accounts/" + testUserID + "/sessions/" + testUserID},
		{http.MethodPost, "/authkit/admin/api/accounts/" + testUserID + "/sessions/revoke"},
		{http.MethodPost, "/authkit/admin/api/logout"},
	}
	for _, request := range requests {
		t.Run(request.method+" "+request.path, func(t *testing.T) {
			requireStatus(t, f.request(request.method, request.path, "", ""), http.StatusUnauthorized)
			requireStatus(t, f.request(request.method, request.path, "", ordinaryToken), http.StatusForbidden)
		})
	}
}

func TestAdminCodeAndLoginUseExistingAccount(t *testing.T) {
	f := newHandlerFixture(t)
	for _, email := range []string{"user@example.com", "missing@example.com"} {
		response := f.request(http.MethodPost, "/authkit/admin/api/codes", `{"email":"`+email+`"}`, "")
		requireStatus(t, response, http.StatusNoContent)
		if f.mail.sent != 0 {
			t.Fatalf("sent %d codes to non-admin mailboxes", f.mail.sent)
		}
	}

	response := f.request(http.MethodPost, "/authkit/admin/api/codes", `{"email":" ADMIN@Example.com "}`, "")
	requireStatus(t, response, http.StatusNoContent)
	if f.mail.sent != 1 || f.mail.lastEmail != "admin@example.com" || len(f.mail.lastCode) != 6 {
		t.Fatalf("unexpected code delivery: sent=%d email=%q code length=%d", f.mail.sent, f.mail.lastEmail, len(f.mail.lastCode))
	}

	response = f.request(http.MethodPost, "/authkit/admin/api/login",
		`{"email":"admin@example.com","code":"`+f.mail.lastCode+`"}`, "")
	requireStatus(t, response, http.StatusOK)
	var login struct {
		Token   string `json:"token"`
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	if login.Token == "" || login.Account.ID != testAdminID {
		t.Fatalf("unexpected login response: account=%q token length=%d", login.Account.ID, len(login.Token))
	}
	account, err := f.service.Authenticate(context.Background(), login.Token)
	if err != nil || account.ID != testAdminID {
		t.Fatalf("authkit token did not authenticate the configured account: account=%v err=%v", account, err)
	}

	for _, path := range []string{
		"/authkit/admin/api/me",
		"/authkit/admin/api/overview",
		"/authkit/admin/api/accounts",
		"/authkit/admin/api/accounts/" + testUserID,
	} {
		requireStatus(t, f.request(http.MethodGet, path, "", login.Token), http.StatusOK)
	}
	requireStatus(t, f.request(http.MethodPost, "/authkit/admin/api/logout", "", login.Token), http.StatusNoContent)
	requireStatus(t, f.request(http.MethodGet, "/authkit/admin/api/me", "", login.Token), http.StatusUnauthorized)
}

func TestOrdinaryAccountCannotLoginToConsole(t *testing.T) {
	f := newHandlerFixture(t)
	if err := f.service.SendCode(context.Background(), authkit.SendCodeInput{
		Email: "user@example.com", IP: "192.0.2.1",
	}); err != nil {
		t.Fatal(err)
	}
	code := f.mail.lastCode
	response := f.request(http.MethodPost, "/authkit/admin/api/login",
		`{"email":"user@example.com","code":"`+code+`"}`, "")
	requireStatus(t, response, http.StatusForbidden)
	if strings.Contains(response.Body.String(), `"token"`) {
		t.Fatal("ordinary account login exposed a token")
	}
	if _, err := f.service.LoginEmail(context.Background(), authkit.EmailLoginInput{
		Email: "user@example.com", Code: code,
	}); err != nil {
		t.Fatalf("console login consumed the ordinary account's code: %v", err)
	}
}

func TestAdminCannotRemoveOwnBinding(t *testing.T) {
	f := newHandlerFixture(t)
	token := f.login(t, "admin@example.com")
	for _, method := range []string{authkit.MethodEmail, authkit.MethodWechat} {
		response := f.request(http.MethodDelete,
			"/authkit/admin/api/accounts/"+testAdminID+"/bindings/"+method, "", token)
		requireStatus(t, response, http.StatusForbidden)
	}
	if f.auth.deletedBinding != "" {
		t.Fatal("store was asked to delete the administrator's binding")
	}
}

func TestAdminActionsTargetRequestedAccount(t *testing.T) {
	f := newHandlerFixture(t)
	token := f.login(t, "admin@example.com")
	requireStatus(t, f.request(http.MethodDelete,
		"/authkit/admin/api/accounts/"+testUserID+"/bindings/email", "", token), http.StatusNoContent)
	if f.auth.deletedBinding != testUserID+"/email" {
		t.Fatalf("deleted binding = %q", f.auth.deletedBinding)
	}
	requireStatus(t, f.request(http.MethodDelete,
		"/authkit/admin/api/accounts/"+testUserID+"/sessions/"+testUserID, "", token), http.StatusNoContent)
	if f.auth.revokedSession != testUserID+"/"+testUserID {
		t.Fatalf("revoked session = %q", f.auth.revokedSession)
	}
	requireStatus(t, f.request(http.MethodPost,
		"/authkit/admin/api/accounts/"+testUserID+"/sessions/revoke", "", token), http.StatusNoContent)
	if f.auth.revokedAll != testUserID {
		t.Fatalf("revoked all sessions for = %q", f.auth.revokedAll)
	}
}

func TestAdminRejectsBadInputBeforeStorage(t *testing.T) {
	f := newHandlerFixture(t)
	token := f.login(t, "admin@example.com")
	requests := []struct {
		method string
		path   string
		body   string
		token  string
	}{
		{http.MethodPost, "/authkit/admin/api/codes", `{"email":"invalid"}`, ""},
		{http.MethodPost, "/authkit/admin/api/codes", `{"email":"admin@example.com","extra":true}`, ""},
		{http.MethodPost, "/authkit/admin/api/login", `{"email":"admin@example.com","code":""}`, ""},
		{http.MethodGet, "/authkit/admin/api/accounts?page=0", "", token},
		{http.MethodGet, "/authkit/admin/api/accounts?limit=101", "", token},
		{http.MethodGet, "/authkit/admin/api/accounts/bad-id", "", token},
		{http.MethodDelete, "/authkit/admin/api/accounts/" + testUserID + "/bindings/other", "", token},
		{http.MethodDelete, "/authkit/admin/api/accounts/" + testUserID + "/sessions/bad-id", "", token},
		{http.MethodPost, "/authkit/admin/api/accounts/bad-id/sessions/revoke", "", token},
	}
	for _, request := range requests {
		t.Run(request.method+" "+request.path, func(t *testing.T) {
			requireStatus(t, f.request(request.method, request.path, request.body, request.token), http.StatusBadRequest)
		})
	}
	if f.mail.sent != 1 {
		t.Fatalf("bad requests sent %d additional codes", f.mail.sent-1)
	}
}

func TestNewHTTPHandlerRequiresConfiguredAccount(t *testing.T) {
	f := newHandlerFixture(t)
	for _, id := range []string{"", "not-an-account-id"} {
		if _, err := NewHTTPHandler(f.service, id); err == nil {
			t.Fatalf("NewHTTPHandler accepted account ID %q", id)
		}
	}
}

func TestNewHTTPHandlerRequiresAdminCapableService(t *testing.T) {
	service, err := authkit.NewService(handlerUnsupportedStore{}, &handlerMail{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewHTTPHandler(service, testAdminID)
	if !errors.Is(err, authkit.ErrAdminUnavailable) {
		t.Fatalf("NewHTTPHandler with unsupported store = %v", err)
	}
}

type handlerUnsupportedStore struct{ authkit.Store }

// 身份替身只实现公开验证码和登录流程会调用的仓储方法。
// 该流程一旦调用额外的仓储操作，嵌入的接口会立即失败。
type handlerAuthStore struct {
	accounts       map[string]authkit.Account
	challenges     map[string]authkit.Challenge
	sessions       map[string]authkit.Session
	deletedBinding string
	revokedSession string
	revokedAll     string
}

func (s *handlerAuthStore) WithTransaction(ctx context.Context, fn func(authkit.Repositories) error) error {
	return fn(s)
}
func (s *handlerAuthStore) Accounts() authkit.AccountRepository {
	return handlerAccounts{AccountRepository: nil, store: s}
}
func (s *handlerAuthStore) Challenges() authkit.ChallengeRepository {
	return handlerChallenges{ChallengeRepository: nil, store: s}
}
func (s *handlerAuthStore) Rates() authkit.RateRepository { return handlerRates{} }
func (s *handlerAuthStore) Sessions() authkit.SessionRepository {
	return handlerSessions{store: s}
}

type handlerAccounts struct {
	authkit.AccountRepository
	store *handlerAuthStore
}

func (r handlerAccounts) GetByEmail(_ context.Context, email string) (*authkit.Account, error) {
	for _, account := range r.store.accounts {
		if account.Email == email {
			return &account, nil
		}
	}
	return nil, authkit.ErrNotFound
}

func (r handlerAccounts) GetBySessionToken(_ context.Context, hash string, now time.Time) (*authkit.Account, error) {
	session, ok := r.store.sessions[hash]
	if !ok || !now.Before(session.Expires) {
		return nil, authkit.ErrNotFound
	}
	account := r.store.accounts[session.AccountID]
	return &account, nil
}

type handlerChallenges struct {
	authkit.ChallengeRepository
	store *handlerAuthStore
}

func (r handlerChallenges) Get(_ context.Context, email string) (*authkit.Challenge, error) {
	challenge := r.store.challenges[email]
	challenge.Email = email
	return &challenge, nil
}

func (r handlerChallenges) Find(_ context.Context, email string) (*authkit.Challenge, error) {
	challenge, ok := r.store.challenges[email]
	if !ok {
		return nil, authkit.ErrNotFound
	}
	return &challenge, nil
}

func (r handlerChallenges) Save(_ context.Context, challenge *authkit.Challenge) error {
	r.store.challenges[challenge.Email] = *challenge
	return nil
}

type handlerRates struct{}

func (handlerRates) Hit(context.Context, string, time.Time, int) error { return nil }

type handlerSessions struct {
	store *handlerAuthStore
}

func (r handlerSessions) Create(_ context.Context, session *authkit.Session) error {
	r.store.sessions[session.Hash] = *session
	return nil
}

func (r handlerSessions) Delete(_ context.Context, hash string) error {
	delete(r.store.sessions, hash)
	return nil
}

type handlerMail struct {
	sent      int
	lastEmail string
	lastCode  string
}

func (m *handlerMail) SendCode(_ context.Context, email, code string) error {
	m.sent++
	m.lastEmail, m.lastCode = email, code
	return nil
}

func (s *handlerAuthStore) AdminOverview(_ context.Context, _ time.Time) (authkit.AdminOverview, error) {
	return authkit.AdminOverview{Accounts: int64(len(s.accounts))}, nil
}

func (s *handlerAuthStore) AdminListAccounts(_ context.Context, _ string, page, limit int, _ time.Time) (authkit.AdminAccountPage, error) {
	return authkit.AdminAccountPage{Items: []authkit.AdminAccountSummary{}, Total: int64(len(s.accounts)), Page: page, Limit: limit}, nil
}

func (s *handlerAuthStore) AdminGetAccount(_ context.Context, id string, _ time.Time) (authkit.AdminAccountDetail, error) {
	account, ok := s.accounts[id]
	if !ok {
		return authkit.AdminAccountDetail{}, authkit.ErrNotFound
	}
	return authkit.AdminAccountDetail{ID: account.ID, Email: account.Email}, nil
}

func (s *handlerAuthStore) AdminDeleteBinding(_ context.Context, id, method string) error {
	s.deletedBinding = id + "/" + method
	return nil
}

func (s *handlerAuthStore) AdminRevokeSession(_ context.Context, id, sessionID string) error {
	s.revokedSession = id + "/" + sessionID
	return nil
}

func (s *handlerAuthStore) AdminRevokeAllSessions(_ context.Context, id string) error {
	s.revokedAll = id
	return nil
}
