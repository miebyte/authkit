package admin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"regexp"
	"sort"
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
			challenges:          make(map[string]authkit.Challenge),
			sessions:            make(map[string]authkit.Session),
			blacklist:           make(map[string]authkit.BlacklistEntry),
			wechatIDs:           make(map[string]string),
			passwords:           make(map[string]string),
			passwordIdentifiers: make(map[string]string),
			rateHits:            make(map[string]int),
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

var consoleResourceRefs = regexp.MustCompile(`(?:src|href)="([^"]+)"`)

func assertConsoleResources(t *testing.T, mux *http.ServeMux, pagePath string) {
	t.Helper()
	page := httptest.NewRecorder()
	mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, pagePath, nil))
	requireStatus(t, page, http.StatusOK)
	if page.Body.Len() == 0 || !strings.HasPrefix(page.Header().Get("Content-Type"), "text/html") {
		t.Fatal("console page is empty or has the wrong content type")
	}
	if got := page.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	pageURL, err := url.Parse("http://example.test" + pagePath)
	if err != nil {
		t.Fatal(err)
	}
	var hasJS, hasCSS, hasFavicon bool
	for _, match := range consoleResourceRefs.FindAllStringSubmatch(page.Body.String(), -1) {
		ref, err := url.Parse(match[1])
		if err != nil {
			t.Fatal(err)
		}
		assetPath := strings.TrimPrefix(ref.Path, "./")
		if !strings.HasPrefix(assetPath, "assets/") {
			continue
		}
		resource := httptest.NewRecorder()
		mux.ServeHTTP(resource, httptest.NewRequest(http.MethodGet, pageURL.ResolveReference(ref).RequestURI(), nil))
		requireStatus(t, resource, http.StatusOK)
		if resource.Body.Len() == 0 || resource.Header().Get("Content-Type") == "" {
			t.Fatalf("embedded resource %q is empty or missing its content type", match[1])
		}
		if got := resource.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("resource %q X-Content-Type-Options = %q", match[1], got)
		}
		switch path.Ext(assetPath) {
		case ".js":
			hasJS = true
		case ".css":
			hasCSS = true
		case ".svg":
			if path.Base(assetPath) == "favicon.svg" {
				hasFavicon = true
				if got := resource.Header().Get("Content-Type"); got != "image/svg+xml" {
					t.Fatalf("favicon Content-Type = %q", got)
				}
			}
		}
	}
	if !hasJS || !hasCSS || !hasFavicon {
		t.Fatalf("console resource references: JS=%t CSS=%t favicon=%t", hasJS, hasCSS, hasFavicon)
	}
}

func TestConsolePageAndAssets(t *testing.T) {
	f := newHandlerFixture(t)
	assertConsoleResources(t, f.mux, "/authkit/admin/")
	page := f.request(http.MethodGet, "/authkit/admin/", "", "")
	if !strings.Contains(page.Body.String(), `<meta name="authkit-title" content="AuthKit">`) {
		t.Fatal("console page does not expose its default title")
	}
}

func TestConsoleCustomTitle(t *testing.T) {
	f := newHandlerFixture(t)
	title := `工作台 <管理> & "运营" '后台'`
	handler, err := NewHTTPHandler(f.service, testAdminID, Config{Title: title})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/ops/", http.StripPrefix("/ops", handler))
	for _, path := range []string{"/ops/", "/ops/login", "/ops/overview", "/ops/accounts", "/ops/blacklist"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		requireStatus(t, response, http.StatusOK)
		body := response.Body.String()
		if !strings.Contains(body, `<meta name="authkit-title" content="`+html.EscapeString(title)+`">`) {
			t.Fatalf("%s does not expose escaped custom title", path)
		}
		if !strings.Contains(body, "<title>"+html.EscapeString(title)+" 超管后台</title>") {
			t.Fatalf("%s does not use custom browser title", path)
		}
	}
}

func TestConsoleEmptyTitleUsesDefault(t *testing.T) {
	f := newHandlerFixture(t)
	handler, err := NewHTTPHandler(f.service, testAdminID, Config{Title: " \t "})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	requireStatus(t, response, http.StatusOK)
	if !strings.Contains(response.Body.String(), `<meta name="authkit-title" content="AuthKit">`) {
		t.Fatal("blank title did not use the default")
	}
	if _, err := NewHTTPHandler(f.service, testAdminID, Config{}, Config{}); !errors.Is(err, authkit.ErrInvalidInput) {
		t.Fatalf("multiple title configurations = %v", err)
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
	for _, path := range []string{"/ops/", "/ops/login", "/ops/overview", "/ops/accounts", "/ops/blacklist"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		requireStatus(t, response, http.StatusOK)
	}
	assertConsoleResources(t, mux, "/ops/accounts")
	assertConsoleResources(t, mux, "/ops/blacklist")
	for _, path := range []string{"/ops/unknown", "/ops/assets/missing.js"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		requireStatus(t, response, http.StatusNotFound)
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
		{http.MethodGet, "/authkit/admin/api/blacklist"},
		{http.MethodPost, "/authkit/admin/api/blacklist"},
		{http.MethodDelete, "/authkit/admin/api/blacklist/" + testUserID},
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

func (f *handlerFixture) setPassword(t *testing.T, accountID, identifier string) {
	t.Helper()
	account := f.auth.accounts[accountID]
	account.Username = identifier
	f.auth.accounts[accountID] = account
	if err := f.service.SetPassword(context.Background(), authkit.SetPasswordInput{
		AccountID: accountID, Identifier: identifier, Password: "test-password-123",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAdminPasswordLoginUsesConfiguredAccount(t *testing.T) {
	f := newHandlerFixture(t)
	f.setPassword(t, testAdminID, "admin@example.com")
	for _, identifier := range []string{" admin@example.com ", " ADMIN@Example.com "} {
		body, err := json.Marshal(passwordLoginRequest{Identifier: identifier, Password: "test-password-123"})
		if err != nil {
			t.Fatal(err)
		}
		response := f.request(http.MethodPost, "/authkit/admin/api/password/login", string(body), "")
		requireStatus(t, response, http.StatusOK)
		var result struct {
			Token   string          `json:"token"`
			Account accountResponse `json:"account"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Account.ID != testAdminID || result.Account.Username != "admin@example.com" || result.Token == "" {
			t.Fatalf("unexpected password login result: %+v", result.Account)
		}
		if strings.Contains(response.Body.String(), f.auth.passwords[testAdminID]) {
			t.Fatal("password login exposed the stored hash")
		}
		requireStatus(t, f.request(http.MethodGet, "/authkit/admin/api/me", "", result.Token), http.StatusOK)
		requireStatus(t, f.request(http.MethodPost, "/authkit/admin/api/logout", "", result.Token), http.StatusNoContent)
	}
	ipKey := fmt.Sprintf("%x", sha256.Sum256([]byte("password-ip:192.0.2.1")))
	if f.auth.rateHits[ipKey] != 2 {
		t.Fatalf("password logins counted %d attempts for the connection IP", f.auth.rateHits[ipKey])
	}
}

func TestPasswordOnlyAdminCanLogin(t *testing.T) {
	f := newHandlerFixture(t)
	f.auth.accounts[testAdminID] = authkit.Account{ID: testAdminID}
	f.setPassword(t, testAdminID, "admin")
	response := f.request(http.MethodPost, "/authkit/admin/api/password/login",
		`{"identifier":"admin","password":"test-password-123"}`, "")
	requireStatus(t, response, http.StatusOK)
	if !strings.Contains(response.Body.String(), `"email":""`) {
		t.Fatalf("password-only login response = %s", response.Body.String())
	}
}

func TestAdminPasswordLoginIgnoresDisplayName(t *testing.T) {
	f := newHandlerFixture(t)
	f.setPassword(t, testAdminID, "admin@example.com")
	account := f.auth.accounts[testAdminID]
	account.Username = "管理员"
	f.auth.accounts[testAdminID] = account
	for _, identifier := range []string{"admin@example.com", " ADMIN@EXAMPLE.COM "} {
		response := f.request(http.MethodPost, "/authkit/admin/api/password/login",
			`{"identifier":"`+identifier+`","password":"test-password-123"}`, "")
		requireStatus(t, response, http.StatusOK)
		var result struct {
			Token   string          `json:"token"`
			Account accountResponse `json:"account"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Account.ID != testAdminID || result.Account.Username != "管理员" || result.Token == "" {
			t.Fatalf("renamed account login result = %+v", result.Account)
		}
	}
	response := f.request(http.MethodPost, "/authkit/admin/api/password/login",
		`{"identifier":"管理员","password":"test-password-123"}`, "")
	requireStatus(t, response, http.StatusUnauthorized)
}

func TestAdminPasswordRejectsOtherAccountsWithoutSession(t *testing.T) {
	f := newHandlerFixture(t)
	f.setPassword(t, testAdminID, "admin")
	for _, body := range []string{
		`{"identifier":"missing","password":"test-password-123"}`,
		`{"identifier":"admin","password":"wrong-password"}`,
		`{"identifier":"user@example.com","password":"test-password-123"}`,
	} {
		response := f.request(http.MethodPost, "/authkit/admin/api/password/login", body, "")
		requireStatus(t, response, http.StatusUnauthorized)
		if response.Body.String() != "{\"error\":\"invalid_credentials\"}\n" {
			t.Fatalf("password rejection = %s", response.Body.String())
		}
	}
	f.setPassword(t, testUserID, "user")
	for _, identifier := range []string{"user", "user@example.com"} {
		before := 0
		for _, hits := range f.auth.rateHits {
			before += hits
		}
		response := f.request(http.MethodPost, "/authkit/admin/api/password/login",
			`{"identifier":"`+identifier+`","password":"test-password-123"}`, "")
		requireStatus(t, response, http.StatusUnauthorized)
		if response.Body.String() != "{\"error\":\"invalid_credentials\"}\n" {
			t.Fatalf("ordinary account rejection = %s", response.Body.String())
		}
		after := 0
		for _, hits := range f.auth.rateHits {
			after += hits
		}
		if after <= before {
			t.Fatal("ordinary account's password attempt did not consume a rate allowance")
		}
	}
	if len(f.auth.sessions) != 0 {
		t.Fatal("rejected password login left a session")
	}
}

func TestAdminPasswordRejectsBadJSONBeforeStorage(t *testing.T) {
	f := newHandlerFixture(t)
	for _, body := range []string{
		`{"identifier":"admin","password":"secret","extra":true}`,
		`{"identifier":"admin","password":"secret"} {}`,
		`{"identifier":true,"password":"secret"}`,
	} {
		requireStatus(t, f.request(http.MethodPost, "/authkit/admin/api/password/login", body, ""), http.StatusBadRequest)
	}
	if len(f.auth.rateHits) != 0 || len(f.auth.sessions) != 0 {
		t.Fatal("invalid password JSON reached the login storage")
	}
}

func TestAdminDisplaysAndDeletesPasswordBinding(t *testing.T) {
	f := newHandlerFixture(t)
	f.setPassword(t, testUserID, "user")
	storedAccount := f.auth.accounts[testUserID]
	storedAccount.Username = "用户"
	f.auth.accounts[testUserID] = storedAccount
	token := f.login(t, "admin@example.com")
	response := f.request(http.MethodGet, "/authkit/admin/api/accounts/"+testUserID, "", token)
	requireStatus(t, response, http.StatusOK)
	var account authkit.AdminAccountDetail
	if err := json.Unmarshal(response.Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}
	if len(account.Bindings) != 2 || account.Bindings[1].Method != authkit.MethodPassword || account.Bindings[1].Identifier != "user" {
		t.Fatalf("password binding projection = %+v", account.Bindings)
	}
	if account.Username != "用户" {
		t.Fatalf("account display name = %q", account.Username)
	}
	if strings.Contains(response.Body.String(), f.auth.passwords[testUserID]) {
		t.Fatal("account detail exposed a password hash")
	}
	requireStatus(t, f.request(http.MethodDelete,
		"/authkit/admin/api/accounts/"+testUserID+"/bindings/password", "", token), http.StatusNoContent)
	if f.auth.deletedBinding != testUserID+"/password" || f.auth.passwords[testUserID] != "" || f.auth.passwordIdentifiers[testUserID] != "" {
		t.Fatal("handler did not remove the requested password credential")
	}
	if f.auth.accounts[testUserID].Username != "用户" {
		t.Fatal("removing a password changed the account username")
	}
}

func TestAdminCannotRemoveOwnBinding(t *testing.T) {
	f := newHandlerFixture(t)
	token := f.login(t, "admin@example.com")
	for _, method := range []string{authkit.MethodEmail, authkit.MethodWechat, authkit.MethodPassword} {
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
		{http.MethodGet, "/authkit/admin/api/blacklist?page=0", "", token},
		{http.MethodGet, "/authkit/admin/api/blacklist?limit=101", "", token},
		{http.MethodPost, "/authkit/admin/api/blacklist", `{"method":"other","identifier":"user@example.com"}`, token},
		{http.MethodPost, "/authkit/admin/api/blacklist", `{"method":"email","identifier":"invalid"}`, token},
		{http.MethodPost, "/authkit/admin/api/blacklist", `{"method":"email","identifier":"user@example.com","extra":true}`, token},
		{http.MethodPost, "/authkit/admin/api/blacklist", `{"method":"wechat","identifier":""}`, token},
		{http.MethodPost, "/authkit/admin/api/blacklist", `{"method":"wechat","identifier":" "}`, token},
		{http.MethodPost, "/authkit/admin/api/blacklist", `{"method":"wechat","identifier":"` + strings.Repeat("a", 129) + `"}`, token},
		{http.MethodDelete, "/authkit/admin/api/blacklist/bad-id", "", token},
	}
	for _, request := range requests {
		t.Run(request.method+" "+request.path, func(t *testing.T) {
			requireStatus(t, f.request(request.method, request.path, request.body, request.token), http.StatusBadRequest)
		})
	}
	if f.mail.sent != 1 {
		t.Fatalf("bad requests sent %d additional codes", f.mail.sent-1)
	}
	if len(f.auth.blacklist) != 0 {
		t.Fatal("invalid requests added blacklist entries")
	}
}

func TestAdminManagesBlacklist(t *testing.T) {
	f := newHandlerFixture(t)
	token := f.login(t, "admin@example.com")
	for _, body := range []string{
		`{"method":"email","identifier":" USER@Example.com "}`,
		`{"method":"email","identifier":"unregistered@example.com"}`,
		`{"method":"wechat","identifier":"RawOpenID"}`,
	} {
		requireStatus(t, f.request(http.MethodPost, "/authkit/admin/api/blacklist", body, token), http.StatusNoContent)
	}
	response := f.request(http.MethodGet, "/authkit/admin/api/blacklist?page=1&limit=2", "", token)
	requireStatus(t, response, http.StatusOK)
	var result authkit.BlacklistPage
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 3 || result.Page != 1 || result.Limit != 2 || len(result.Items) != 2 {
		t.Fatalf("unexpected blacklist page: %+v", result)
	}
	response = f.request(http.MethodGet, "/authkit/admin/api/blacklist", "", token)
	requireStatus(t, response, http.StatusOK)
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	var emailID, wechatID string
	for _, entry := range result.Items {
		if entry.Method == authkit.MethodEmail && entry.Identifier == "user@example.com" {
			emailID = entry.ID
		}
		if entry.Method == authkit.MethodWechat {
			wechatID = entry.ID
			if entry.Identifier != "" {
				t.Fatalf("wechat blacklist exposed identifier %q", entry.Identifier)
			}
		}
	}
	if emailID == "" || wechatID == "" {
		t.Fatalf("missing normalized email or wechat entry: %+v", result.Items)
	}
	requireStatus(t, f.request(http.MethodDelete, "/authkit/admin/api/blacklist/"+emailID, "", token), http.StatusNoContent)
	requireStatus(t, f.request(http.MethodDelete, "/authkit/admin/api/blacklist/"+wechatID, "", token), http.StatusNoContent)
	if len(f.auth.blacklist) != 1 {
		t.Fatalf("remaining blacklist entries = %d", len(f.auth.blacklist))
	}
	requireStatus(t, f.request(http.MethodDelete, "/authkit/admin/api/blacklist/"+emailID, "", token), http.StatusNoContent)
}

func TestAdminCannotBlacklistOwnCredentials(t *testing.T) {
	f := newHandlerFixture(t)
	f.setPassword(t, testAdminID, "admin")
	account := f.auth.accounts[testAdminID]
	account.Username = "管理员"
	f.auth.accounts[testAdminID] = account
	f.auth.wechatIDs[fmt.Sprintf("%x", sha256.Sum256([]byte("AdminOpenID")))] = testAdminID
	token := f.login(t, "admin@example.com")
	for _, body := range []string{
		`{"method":"email","identifier":" ADMIN@Example.com "}`,
		`{"method":"wechat","identifier":"AdminOpenID"}`,
		`{"method":"password","identifier":" admin "}`,
	} {
		response := f.request(http.MethodPost, "/authkit/admin/api/blacklist", body, token)
		requireStatus(t, response, http.StatusForbidden)
		if !strings.Contains(response.Body.String(), `"error":"forbidden"`) {
			t.Fatalf("protected account response = %s", response.Body.String())
		}
	}
	if len(f.auth.blacklist) != 0 {
		t.Fatal("configured administrator was blacklisted")
	}
	requireStatus(t, f.request(http.MethodGet, "/authkit/admin/api/me", "", token), http.StatusOK)
}

func TestAdminCanBlacklistDisplayNameWithoutBlockingAccount(t *testing.T) {
	f := newHandlerFixture(t)
	f.setPassword(t, testAdminID, "admin")
	account := f.auth.accounts[testAdminID]
	account.Username = "管理员"
	f.auth.accounts[testAdminID] = account
	token := f.login(t, "admin@example.com")
	requireStatus(t, f.request(http.MethodPost, "/authkit/admin/api/blacklist",
		`{"method":"password","identifier":"管理员"}`, token), http.StatusNoContent)
	requireStatus(t, f.request(http.MethodGet, "/authkit/admin/api/me", "", token), http.StatusOK)
	for _, identifier := range []string{"admin"} {
		requireStatus(t, f.request(http.MethodPost, "/authkit/admin/api/password/login",
			`{"identifier":"`+identifier+`","password":"test-password-123"}`, ""), http.StatusOK)
	}
}

func TestAdminManagesPasswordBlacklist(t *testing.T) {
	f := newHandlerFixture(t)
	f.setPassword(t, testUserID, "user")
	account := f.auth.accounts[testUserID]
	account.Username = "用户"
	f.auth.accounts[testUserID] = account
	userToken := f.login(t, "user@example.com")
	token := f.login(t, "admin@example.com")
	requireStatus(t, f.request(http.MethodPost, "/authkit/admin/api/blacklist",
		`{"method":"password","identifier":" user "}`, token), http.StatusNoContent)
	requireStatus(t, f.request(http.MethodGet, "/authkit/admin/api/me", "", userToken), http.StatusUnauthorized)
	response := f.request(http.MethodGet, "/authkit/admin/api/blacklist", "", token)
	requireStatus(t, response, http.StatusOK)
	var result authkit.BlacklistPage
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(result.Items) != 1 || result.Items[0].Method != authkit.MethodPassword || result.Items[0].Identifier != "user" {
		t.Fatalf("password blacklist = %+v", result)
	}
	requireStatus(t, f.request(http.MethodDelete, "/authkit/admin/api/blacklist/"+result.Items[0].ID, "", token), http.StatusNoContent)
	if len(f.auth.blacklist) != 0 {
		t.Fatal("password blacklist entry was not removed")
	}
}

func TestAdminMapsBlacklistedError(t *testing.T) {
	response := httptest.NewRecorder()
	writeError(response, authkit.ErrBlacklisted)
	requireStatus(t, response, http.StatusForbidden)
	if !strings.Contains(response.Body.String(), `"error":"blacklisted"`) {
		t.Fatalf("blacklisted response = %s", response.Body.String())
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

// handlerAuthStore 实现公开登录流程与后台操作使用的仓储替身。
// 该流程一旦调用额外的仓储操作，嵌入的接口会立即失败。
type handlerAuthStore struct {
	accounts            map[string]authkit.Account
	challenges          map[string]authkit.Challenge
	sessions            map[string]authkit.Session
	blacklist           map[string]authkit.BlacklistEntry
	wechatIDs           map[string]string
	passwords           map[string]string
	passwordIdentifiers map[string]string
	rateHits            map[string]int
	deletedBinding      string
	revokedSession      string
	revokedAll          string
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
func (s *handlerAuthStore) Rates() authkit.RateRepository { return handlerRates{store: s} }
func (s *handlerAuthStore) Sessions() authkit.SessionRepository {
	return handlerSessions{store: s}
}
func (s *handlerAuthStore) Blacklist() authkit.BlacklistRepository {
	return handlerBlacklist{store: s}
}

type handlerAccounts struct {
	authkit.AccountRepository
	store *handlerAuthStore
}

func (r handlerAccounts) GetByID(_ context.Context, id string) (*authkit.Account, error) {
	account, ok := r.store.accounts[id]
	if !ok {
		return nil, authkit.ErrNotFound
	}
	return &account, nil
}

func (r handlerAccounts) GetByPasswordIdentifier(ctx context.Context, identifier string) (*authkit.Account, error) {
	for id, existing := range r.store.passwordIdentifiers {
		if existing == identifier {
			return r.GetByID(ctx, id)
		}
	}
	return nil, authkit.ErrNotFound
}

func (r handlerAccounts) GetPasswordIdentifier(_ context.Context, accountID string) (string, error) {
	identifier, ok := r.store.passwordIdentifiers[accountID]
	if !ok {
		return "", authkit.ErrNotFound
	}
	return identifier, nil
}

func (r handlerAccounts) GetPasswordHash(_ context.Context, accountID string) (string, error) {
	hash, ok := r.store.passwords[accountID]
	if !ok {
		return "", authkit.ErrNotFound
	}
	return hash, nil
}

func (r handlerAccounts) SetPasswordHash(ctx context.Context, accountID, identifier, hash string) error {
	if _, err := r.GetByID(ctx, accountID); err != nil {
		return err
	}
	if existing, ok := r.store.passwordIdentifiers[accountID]; ok && existing != identifier {
		return authkit.ErrConflict
	}
	for id, existing := range r.store.passwordIdentifiers {
		if id != accountID && existing == identifier {
			return authkit.ErrConflict
		}
	}
	r.store.passwordIdentifiers[accountID] = identifier
	r.store.passwords[accountID] = hash
	return nil
}

func (r handlerAccounts) GetByEmail(_ context.Context, email string) (*authkit.Account, error) {
	for _, account := range r.store.accounts {
		if account.Email == email {
			return &account, nil
		}
	}
	return nil, authkit.ErrNotFound
}

func (r handlerAccounts) GetByWechat(_ context.Context, hash string) (*authkit.Account, error) {
	account, ok := r.store.accounts[r.store.wechatIDs[hash]]
	if !ok {
		return nil, authkit.ErrNotFound
	}
	return &account, nil
}

type handlerBlacklist struct {
	store *handlerAuthStore
}

func (r handlerBlacklist) Check(_ context.Context, credential authkit.Credential) error {
	for _, entry := range r.store.blacklist {
		if entry.Method == credential.Method && entry.Identifier == credential.Identifier {
			return authkit.ErrBlacklisted
		}
	}
	return nil
}

func (r handlerBlacklist) CheckAccount(ctx context.Context, id string) error {
	account, ok := r.store.accounts[id]
	if !ok {
		return authkit.ErrNotFound
	}
	if account.Email != "" {
		if err := r.Check(ctx, authkit.Credential{Method: authkit.MethodEmail, Identifier: account.Email}); err != nil {
			return err
		}
	}
	if _, ok := r.store.passwords[id]; ok {
		if err := r.Check(ctx, authkit.Credential{Method: authkit.MethodPassword, Identifier: r.store.passwordIdentifiers[id]}); err != nil {
			return err
		}
	}
	for hash, accountID := range r.store.wechatIDs {
		if accountID == id {
			if err := r.Check(ctx, authkit.Credential{Method: authkit.MethodWechat, Identifier: hash}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r handlerBlacklist) Add(_ context.Context, entry authkit.BlacklistEntry) error {
	for _, existing := range r.store.blacklist {
		if existing.Method == entry.Method && existing.Identifier == entry.Identifier {
			return nil
		}
	}
	r.store.blacklist[entry.ID] = entry
	accountID := r.store.wechatIDs[entry.Identifier]
	if entry.Method == authkit.MethodEmail {
		delete(r.store.challenges, entry.Identifier)
		for id, account := range r.store.accounts {
			if account.Email == entry.Identifier {
				accountID = id
			}
		}
	}
	if entry.Method == authkit.MethodPassword {
		for id, identifier := range r.store.passwordIdentifiers {
			if identifier == entry.Identifier && r.store.passwords[id] != "" {
				accountID = id
			}
		}
	}
	for hash, session := range r.store.sessions {
		if session.AccountID == accountID {
			delete(r.store.sessions, hash)
		}
	}
	return nil
}

func (r handlerBlacklist) Remove(_ context.Context, id string) error {
	delete(r.store.blacklist, id)
	return nil
}

func (r handlerBlacklist) List(_ context.Context, page, limit int) (authkit.BlacklistPage, error) {
	items := make([]authkit.BlacklistEntry, 0, len(r.store.blacklist))
	for _, entry := range r.store.blacklist {
		if entry.Method == authkit.MethodWechat {
			entry.Identifier = ""
		}
		items = append(items, entry)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	total := int64(len(items))
	start := min((page-1)*limit, len(items))
	end := min(start+limit, len(items))
	return authkit.BlacklistPage{Items: items[start:end], Total: total, Page: page, Limit: limit}, nil
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

type handlerRates struct {
	store *handlerAuthStore
}

func (r handlerRates) Hit(_ context.Context, id string, _ time.Time, limit int) error {
	if r.store.rateHits[id] >= limit {
		return authkit.ErrTooManyRequests
	}
	r.store.rateHits[id]++
	return nil
}

type handlerSessions struct {
	store *handlerAuthStore
}

func (r handlerSessions) Get(_ context.Context, hash string) (*authkit.Session, error) {
	session, ok := r.store.sessions[hash]
	if !ok {
		return nil, authkit.ErrNotFound
	}
	return &session, nil
}

func (r handlerSessions) Create(_ context.Context, session *authkit.Session) error {
	r.store.sessions[session.Hash] = *session
	return nil
}

func (r handlerSessions) Delete(_ context.Context, hash string) error {
	delete(r.store.sessions, hash)
	return nil
}

func (r handlerSessions) DeleteByAccount(_ context.Context, id string) error {
	for hash, session := range r.store.sessions {
		if session.AccountID == id {
			delete(r.store.sessions, hash)
		}
	}
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
	bindings := []authkit.AdminBindingInfo{}
	if account.Email != "" {
		bindings = append(bindings, authkit.AdminBindingInfo{Method: authkit.MethodEmail, Identifier: account.Email})
	}
	if s.passwords[id] != "" {
		bindings = append(bindings, authkit.AdminBindingInfo{Method: authkit.MethodPassword, Identifier: s.passwordIdentifiers[id]})
	}
	return authkit.AdminAccountDetail{ID: account.ID, Username: account.Username, Email: account.Email, Bindings: bindings}, nil
}

func (s *handlerAuthStore) AdminDeleteBinding(ctx context.Context, id, method string) error {
	s.deletedBinding = id + "/" + method
	if method == authkit.MethodPassword {
		delete(s.passwords, id)
		delete(s.passwordIdentifiers, id)
		return (handlerSessions{store: s}).DeleteByAccount(ctx, id)
	}
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

func TestAdminRejectsDerivedSessions(t *testing.T) {
	f := newHandlerFixture(t)
	parent := f.login(t, "user@example.com")
	derived, err := f.service.LoginAs(context.Background(), parent, testAdminID)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, f.request(http.MethodGet, "/authkit/admin/api/me", "", derived.Token), http.StatusForbidden)
}
