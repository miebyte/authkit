// Package admin 提供可选的内嵌超级管理员控制台。
// 宿主通过传入已有的 auth_accounts ID 指定管理员。
package admin

import (
	"bytes"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/miebyte/authkit"
)

//go:embed assets
var assets embed.FS

// Config 配置内置超管界面的可选展示信息。
type Config struct {
	// Title 设置左上角品牌名；留空时使用 AuthKit。
	Title string
}

// handler 按挂载路径提供控制台及其需认证的 API。
type handler struct {
	service *authkit.Service
	adminID string
	title   string
	mux     *http.ServeMux
}

// NewHTTPHandler 返回可挂载到任意路径的控制台。宿主通过 ID 选择已有的超级管理员账号。
func NewHTTPHandler(service *authkit.Service, adminAccountID string, configs ...Config) (http.Handler, error) {
	if service == nil || !validID(adminAccountID) || len(configs) > 1 {
		return nil, authkit.ErrInvalidInput
	}

	title := "AuthKit"
	if len(configs) == 1 && strings.TrimSpace(configs[0].Title) != "" {
		title = strings.TrimSpace(configs[0].Title)
	}

	h := &handler{
		service: service,
		adminID: strings.ToLower(adminAccountID),
		title:   title,
		mux:     http.NewServeMux(),
	}
	h.mux.HandleFunc("GET /{$}", h.index)
	h.mux.HandleFunc("GET /login", h.index)
	h.mux.HandleFunc("GET /overview", h.index)
	h.mux.HandleFunc("GET /accounts", h.index)
	h.mux.HandleFunc("GET /blacklist", h.index)
	h.mux.HandleFunc("GET /assets/", h.asset)
	h.mux.HandleFunc("POST /api/codes", h.sendCode)
	h.mux.HandleFunc("POST /api/login", h.login)
	h.mux.HandleFunc("POST /api/password/login", h.loginPassword)
	h.mux.HandleFunc("POST /api/logout", h.withAdmin(h.logout))
	h.mux.HandleFunc("GET /api/me", h.withAdmin(h.me))
	h.mux.HandleFunc("GET /api/overview", h.withAdmin(h.overview))
	h.mux.HandleFunc("GET /api/accounts", h.withAdmin(h.accounts))
	h.mux.HandleFunc("GET /api/accounts/{id}", h.withAdmin(h.account))
	h.mux.HandleFunc("GET /api/blacklist", h.withAdmin(h.blacklist))
	h.mux.HandleFunc("POST /api/blacklist", h.withAdmin(h.addBlacklist))
	h.mux.HandleFunc("DELETE /api/blacklist/{id}", h.withAdmin(h.removeBlacklist))
	h.mux.HandleFunc("DELETE /api/accounts/{id}/bindings/{method}", h.withAdmin(h.deleteBinding))
	h.mux.HandleFunc("DELETE /api/accounts/{id}/sessions/{sessionID}", h.withAdmin(h.revokeSession))
	h.mux.HandleFunc("POST /api/accounts/{id}/sessions/revoke", h.withAdmin(h.revokeAllSessions))
	return h, nil
}

// ServeHTTP 实现 http.Handler。用 http.StripPrefix 把它挂到路径前缀下。
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *handler) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, _ := assets.ReadFile("assets/index.html")
	escapedTitle := html.EscapeString(h.title)
	data = bytes.Replace(data, []byte(`<meta name="authkit-title" content="AuthKit">`), []byte(`<meta name="authkit-title" content="`+escapedTitle+`">`), 1)
	data = bytes.Replace(data, []byte("<title>AuthKit 超管后台</title>"), []byte("<title>"+escapedTitle+" 超管后台</title>"), 1)
	_, _ = w.Write(data)
}

func (h *handler) asset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	name := "assets" + r.URL.Path
	data, err := assets.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(data)
}

type emailRequest struct {
	Email string `json:"email"`
}

type loginRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type passwordLoginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type blacklistRequest struct {
	Method     string `json:"method"`
	Identifier string `json:"identifier"`
}

type accountResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func accountFrom(account *authkit.Account) accountResponse {
	return accountResponse{ID: account.ID, Username: account.Username, Email: account.Email}
}

func (h *handler) sendCode(w http.ResponseWriter, r *http.Request) {
	var body emailRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}

	email, err := authkit.NormalizeEmail(body.Email)
	if err != nil {
		writeError(w, err)
		return
	}

	account, err := h.service.AdminAccountByEmail(r.Context(), email)
	if errors.Is(err, authkit.ErrNotFound) || err == nil && (account == nil || account.ID != h.adminID) {
		// 不暴露哪个邮箱属于管理员账号。
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}

	if err := h.service.SendCode(r.Context(), authkit.SendCodeInput{Email: email, IP: clientIP(r)}); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	var body loginRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	email, err := authkit.NormalizeEmail(body.Email)
	if err != nil {
		writeError(w, err)
		return
	}
	account, err := h.service.AdminAccountByEmail(r.Context(), email)
	if errors.Is(err, authkit.ErrNotFound) || err == nil && (account == nil || account.ID != h.adminID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	result, err := h.service.LoginEmail(r.Context(), authkit.EmailLoginInput{Email: email, Code: body.Code})
	if err != nil {
		writeError(w, err)
		return
	}
	if result.Account.ID != h.adminID {
		_ = h.service.Logout(r.Context(), result.Token)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Token   string          `json:"token"`
		Account accountResponse `json:"account"`
	}{Token: result.Token, Account: accountFrom(&result.Account)})
}

func (h *handler) loginPassword(w http.ResponseWriter, r *http.Request) {
	var body passwordLoginRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	result, err := h.service.AdminLoginPassword(r.Context(), h.adminID, authkit.PasswordLoginInput{
		Identifier: body.Identifier,
		Password:   body.Password,
		IP:         clientIP(r),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Token   string          `json:"token"`
		Account accountResponse `json:"account"`
	}{Token: result.Token, Account: accountFrom(&result.Account)})
}

func (h *handler) withAdmin(next func(http.ResponseWriter, *http.Request, *authkit.Account, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, authkit.ErrUnauthorized)
			return
		}
		session, err := h.service.AuthenticateSession(r.Context(), token)
		if err != nil {
			writeError(w, err)
			return
		}
		if session.Account.ID != h.adminID || session.Actor != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		next(w, r, &session.Account, token)
	}
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request, _ *authkit.Account, token string) {
	if err := h.service.Logout(r.Context(), token); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) me(w http.ResponseWriter, _ *http.Request, account *authkit.Account, _ string) {
	writeJSON(w, http.StatusOK, accountFrom(account))
}

func (h *handler) overview(w http.ResponseWriter, r *http.Request, _ *authkit.Account, _ string) {
	result, err := h.service.AdminOverview(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) accounts(w http.ResponseWriter, r *http.Request, _ *authkit.Account, _ string) {
	page, err := positiveInt(r.URL.Query().Get("page"), 1, 1000000)
	if err != nil {
		writeError(w, err)
		return
	}
	limit, err := positiveInt(r.URL.Query().Get("limit"), 20, 100)
	if err != nil {
		writeError(w, err)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	if len(query) > 254 {
		writeError(w, authkit.ErrInvalidInput)
		return
	}
	result, err := h.service.AdminListAccounts(r.Context(), query, page, limit)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) blacklist(w http.ResponseWriter, r *http.Request, _ *authkit.Account, _ string) {
	page, err := positiveInt(r.URL.Query().Get("page"), 1, 1000000)
	if err != nil {
		writeError(w, err)
		return
	}
	limit, err := positiveInt(r.URL.Query().Get("limit"), 20, 100)
	if err != nil {
		writeError(w, err)
		return
	}
	result, err := h.service.ListBlacklist(r.Context(), page, limit)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) addBlacklist(w http.ResponseWriter, r *http.Request, _ *authkit.Account, _ string) {
	var body blacklistRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	credential := authkit.Credential{Method: body.Method, Identifier: body.Identifier}
	if err := h.service.AdminAddBlacklist(r.Context(), credential, h.adminID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) removeBlacklist(w http.ResponseWriter, r *http.Request, _ *authkit.Account, _ string) {
	id := r.PathValue("id")
	if !validID(id) {
		writeError(w, authkit.ErrInvalidInput)
		return
	}
	if err := h.service.RemoveBlacklist(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) account(w http.ResponseWriter, r *http.Request, _ *authkit.Account, _ string) {
	id := r.PathValue("id")
	if !validID(id) {
		writeError(w, authkit.ErrInvalidInput)
		return
	}
	result, err := h.service.AdminGetAccount(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) deleteBinding(w http.ResponseWriter, r *http.Request, _ *authkit.Account, _ string) {
	id, method := r.PathValue("id"), r.PathValue("method")
	if !validID(id) || method != authkit.MethodEmail && method != authkit.MethodWechat && method != authkit.MethodPassword {
		writeError(w, authkit.ErrInvalidInput)
		return
	}
	if id == h.adminID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if err := h.service.AdminDeleteBinding(r.Context(), id, method); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) revokeSession(w http.ResponseWriter, r *http.Request, _ *authkit.Account, _ string) {
	id, sessionID := r.PathValue("id"), r.PathValue("sessionID")
	if !validID(id) || !validID(sessionID) {
		writeError(w, authkit.ErrInvalidInput)
		return
	}
	if err := h.service.AdminRevokeSession(r.Context(), id, sessionID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) revokeAllSessions(w http.ResponseWriter, r *http.Request, _ *authkit.Account, _ string) {
	id := r.PathValue("id")
	if !validID(id) {
		writeError(w, authkit.ErrInvalidInput)
		return
	}
	if err := h.service.AdminRevokeAllSessions(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dest any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return authkit.ErrInvalidInput
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return authkit.ErrInvalidInput
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, err error) {
	status, code := http.StatusInternalServerError, "internal"
	switch {
	case errors.Is(err, authkit.ErrInvalidInput), errors.Is(err, authkit.ErrInvalidEmail):
		status, code = http.StatusBadRequest, "invalid_input"
	case errors.Is(err, authkit.ErrTooManyRequests):
		status, code = http.StatusTooManyRequests, "too_many_requests"
	case errors.Is(err, authkit.ErrResendTooSoon):
		status, code = http.StatusTooManyRequests, "resend_too_soon"
	case errors.Is(err, authkit.ErrChallengeInvalid):
		status, code = http.StatusBadRequest, "code_invalid"
	case errors.Is(err, authkit.ErrChallengeMismatch):
		status, code = http.StatusBadRequest, "incorrect_code"
	case errors.Is(err, authkit.ErrUnauthorized):
		status, code = http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, authkit.ErrInvalidCredentials):
		status, code = http.StatusUnauthorized, "invalid_credentials"
	case errors.Is(err, authkit.ErrEmailUnavailable):
		status, code = http.StatusServiceUnavailable, "email_unavailable"
	case errors.Is(err, authkit.ErrBlacklisted):
		status, code = http.StatusForbidden, "blacklisted"
	case errors.Is(err, authkit.ErrProtectedAccount):
		status, code = http.StatusForbidden, "forbidden"
	case errors.Is(err, authkit.ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, authkit.ErrLastBinding):
		status, code = http.StatusConflict, "last_binding"
	case errors.Is(err, authkit.ErrConflict):
		status, code = http.StatusConflict, "conflict"
	case errors.Is(err, authkit.ErrMailFailed):
		status, code = http.StatusBadGateway, "mail_failed"
	}
	writeJSON(w, status, map[string]string{"error": code})
}

func bearerToken(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func positiveInt(value string, fallback, max int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > max {
		return 0, authkit.ErrInvalidInput
	}
	return n, nil
}

func validID(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
