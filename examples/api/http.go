package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/miebyte/authkit"
)

// sendCodeRequest is POST /auth/email/codes.
type sendCodeRequest struct {
	Email string `json:"email"`
}

// emailLoginRequest is POST /auth/email/login.
type emailLoginRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// wechatLoginRequest is POST /auth/wechat/login.
// Email and email_code are supplied together when the login must prove a mailbox.
type wechatLoginRequest struct {
	Code      string `json:"code"`
	Email     string `json:"email,omitempty"`
	EmailCode string `json:"email_code,omitempty"`
}

// bindEmailRequest is POST /auth/email/bind.
type bindEmailRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// accountResponse is the account returned to the client. It never includes an OpenID.
type accountResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// sessionResponse is the body of login and bind.
type sessionResponse struct {
	Account accountResponse `json:"account"`
	Token   string          `json:"token"`
	Expires time.Time       `json:"expires"`
	Created bool            `json:"created"`
}

// errorResponse is the body of every failure.
type errorResponse struct {
	Error string `json:"error"`
}

// sessionFrom maps a committed login into the public session body.
func sessionFrom(result *authkit.LoginResult) sessionResponse {
	return sessionResponse{
		Account: accountFrom(result.Account),
		Token:   result.Token,
		Expires: result.Expires,
		Created: result.Created,
	}
}

// accountFrom maps the identity fields a client is allowed to see.
func accountFrom(account authkit.Account) accountResponse {
	return accountResponse{ID: account.ID, Username: account.Username, Email: account.Email}
}

// decodeJSON reads one object and rejects unknown fields.
func decodeJSON(w http.ResponseWriter, r *http.Request, dest any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return authkit.ErrInvalidInput
	}
	return nil
}

// writeJSON sets the JSON content type and encodes body.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError maps a stable authkit error onto an HTTP status and error code.
func writeError(w http.ResponseWriter, err error) {
	status, code := httpStatus(err)
	writeJSON(w, status, errorResponse{Error: code})
}

// httpStatus returns the status and public error code for a service failure.
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
	case errors.Is(err, authkit.ErrWechatRequired):
		return http.StatusForbidden, "wechat_required"
	case errors.Is(err, authkit.ErrChallengeUpdated):
		return http.StatusConflict, "code_replaced"
	case errors.Is(err, authkit.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, authkit.ErrWechatBound):
		return http.StatusConflict, "wechat_bound"
	case errors.Is(err, authkit.ErrEmailAccountConflict):
		return http.StatusConflict, "email_conflict"
	case errors.Is(err, authkit.ErrEmailBound):
		return http.StatusConflict, "email_bound"
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
