package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/miebyte/authkit"
)

// sendCodeRequest 是 POST /auth/email/codes 的请求体。
type sendCodeRequest struct {
	Email string `json:"email"`
}

// emailLoginRequest 是 POST /auth/email/login 的请求体。
type emailLoginRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// wechatLoginRequest 是 POST /auth/wechat/login 的请求体。
type wechatLoginRequest struct {
	Code string `json:"code"`
}

// accountResponse 是返回给客户端的账号。它从不包含 OpenID。
type accountResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// sessionResponse 是登录响应体。
type sessionResponse struct {
	Account accountResponse `json:"account"`
	Token   string          `json:"token"`
	Expires time.Time       `json:"expires"`
	Created bool            `json:"created"`
}

// errorResponse 是所有失败响应的响应体。
type errorResponse struct {
	Error string `json:"error"`
}

// sessionFrom 把已提交的登录结果映射为公开的会话响应体。
func sessionFrom(result *authkit.LoginResult) sessionResponse {
	return sessionResponse{
		Account: accountFrom(result.Account),
		Token:   result.Token,
		Expires: result.Expires,
		Created: result.Created,
	}
}

// accountFrom 映射客户端允许看到的身份字段。
func accountFrom(account authkit.Account) accountResponse {
	return accountResponse{ID: account.ID, Username: account.Username, Email: account.Email}
}

// decodeJSON 读取一个对象，并拒绝未知字段。
func decodeJSON(w http.ResponseWriter, r *http.Request, dest any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return authkit.ErrInvalidInput
	}
	return nil
}

// writeJSON 设置 JSON 内容类型并编码响应体。
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError 把稳定的 authkit 错误映射为 HTTP 状态码和错误码。
func writeError(w http.ResponseWriter, err error) {
	status, code := httpStatus(err)
	writeJSON(w, status, errorResponse{Error: code})
}

// httpStatus 返回服务失败对应的状态码和公开错误码。
func httpStatus(err error) (int, string) {
	switch {
	case errors.Is(err, authkit.ErrInvalidInput):
		return http.StatusBadRequest, "invalid_input"
	case errors.Is(err, authkit.ErrInvalidEmail):
		return http.StatusBadRequest, "invalid_email"
	case errors.Is(err, authkit.ErrChallengeMismatch):
		return http.StatusBadRequest, "incorrect_code"
	case errors.Is(err, authkit.ErrChallengeInvalid):
		return http.StatusBadRequest, "code_invalid"
	case errors.Is(err, authkit.ErrWechatCode):
		return http.StatusBadRequest, "wechat_code"
	case errors.Is(err, authkit.ErrResendTooSoon):
		return http.StatusTooManyRequests, "resend_too_soon"
	case errors.Is(err, authkit.ErrTooManyRequests):
		return http.StatusTooManyRequests, "too_many_requests"
	case errors.Is(err, authkit.ErrUnauthorized):
		return http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, authkit.ErrRegistrationDenied):
		return http.StatusForbidden, "registration_denied"
	case errors.Is(err, authkit.ErrChallengeUpdated):
		return http.StatusConflict, "code_replaced"
	case errors.Is(err, authkit.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, authkit.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, authkit.ErrMailFailed):
		return http.StatusBadGateway, "mail_failed"
	case errors.Is(err, authkit.ErrWechatLogin):
		return http.StatusBadGateway, "wechat_login"
	case errors.Is(err, authkit.ErrWechatUnavailable):
		return http.StatusServiceUnavailable, "wechat_unavailable"
	default:
		return http.StatusInternalServerError, "internal"
	}
}
