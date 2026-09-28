// Package api demonstrates the JSON HTTP contract a host can place in front of authkit.
//
//	POST   /auth/email/codes    {"email"}
//	POST   /auth/email/login    {"email","code"}
//	POST   /auth/wechat/login   {"code","email?","email_code?"}
//	POST   /auth/email/bind     Authorization: Bearer, {"email","code"}
//	GET    /auth/session        Authorization: Bearer
//	DELETE /auth/session        Authorization: Bearer
//
// Login and bind responses use the session object. Failures use {"error":"..."}.
package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/miebyte/authkit"
)

// Handler serves the authkit HTTP API on a host-owned mux.
type Handler struct {
	service *authkit.Service
}

// NewHandler requires the identity service the routes call.
func NewHandler(service *authkit.Service) *Handler {
	return &Handler{service: service}
}

// Register attaches every auth route. Paths are rooted at /auth.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/email/codes", h.sendEmailCode)
	mux.HandleFunc("POST /auth/email/login", h.loginEmail)
	mux.HandleFunc("POST /auth/wechat/login", h.loginWechat)
	mux.HandleFunc("POST /auth/email/bind", h.bindEmail)
	mux.HandleFunc("GET /auth/session", h.session)
	mux.HandleFunc("DELETE /auth/session", h.logout)
}

// sendEmailCode accepts {"email"} and responds 204 after delivery.
func (h *Handler) sendEmailCode(w http.ResponseWriter, r *http.Request) {
	var body sendCodeRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	err := h.service.SendCode(r.Context(), authkit.SendCodeInput{
		Email: body.Email,
		IP:    clientIP(r),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// loginEmail accepts {"email","code"} and returns a session.
func (h *Handler) loginEmail(w http.ResponseWriter, r *http.Request) {
	var body emailLoginRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	result, err := h.service.LoginEmail(r.Context(), authkit.EmailLoginInput{
		Email: body.Email,
		Code:  body.Code,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionFrom(result))
}

// loginWechat accepts {"code","email?","email_code?"} and returns a session.
func (h *Handler) loginWechat(w http.ResponseWriter, r *http.Request) {
	var body wechatLoginRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	result, err := h.service.LoginWechat(r.Context(), body.Code, authkit.WechatLoginInput{
		Email:     body.Email,
		EmailCode: body.EmailCode,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionFrom(result))
}

// bindEmail accepts a bearer token and {"email","code"}, then returns the rotated session.
func (h *Handler) bindEmail(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, authkit.ErrUnauthorized)
		return
	}
	var body bindEmailRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	result, err := h.service.BindEmail(r.Context(), token, authkit.BindEmailInput{
		Email: body.Email,
		Code:  body.Code,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionFrom(result))
}

// session returns the account for the bearer token.
func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	account, err := h.service.Authenticate(r.Context(), bearerToken(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accountFrom(*account))
}

// logout revokes the bearer token and responds 204.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.service.Logout(r.Context(), bearerToken(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// bearerToken reads the credential from Authorization: Bearer.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, prefix))
}

// clientIP uses the connection address. A host behind a trusted proxy should replace it.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
