// Package api 演示宿主可以放在 authkit 前面的 JSON HTTP 约定。
//
//	POST   /auth/email/codes    {"email"}
//	POST   /auth/email/login    {"email","code"}
//	POST   /auth/password/login {"identifier","password"}
//	POST   /auth/wechat/login   {"code"}
//	GET    /auth/session        Authorization: Bearer
//	DELETE /auth/session        Authorization: Bearer
//
// 登录响应使用 session 对象。失败响应使用 {"error":"..."}。
package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/miebyte/authkit"
)

// Handler 在宿主拥有的 mux 上提供 authkit HTTP API。
type Handler struct {
	service *authkit.Service
}

// NewHandler 需要路由所调用的身份服务。
func NewHandler(service *authkit.Service) *Handler {
	return &Handler{service: service}
}

// Register 注册全部认证路由。路径以 /auth 为根。
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/email/codes", h.sendEmailCode)
	mux.HandleFunc("POST /auth/email/login", h.loginEmail)
	mux.HandleFunc("POST /auth/password/login", h.loginPassword)
	mux.HandleFunc("POST /auth/wechat/login", h.loginWechat)
	mux.HandleFunc("GET /auth/session", h.session)
	mux.HandleFunc("DELETE /auth/session", h.logout)
}

// sendEmailCode 接受 {"email"}，投递完成后返回 204。
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

// loginEmail 接受 {"email","code"} 并返回会话。
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

// loginPassword 接受 {"identifier","password"} 并返回已有账号的会话。
func (h *Handler) loginPassword(w http.ResponseWriter, r *http.Request) {
	var body passwordLoginRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	result, err := h.service.LoginPassword(r.Context(), authkit.PasswordLoginInput{
		Identifier: body.Identifier,
		Password:   body.Password,
		IP:         clientIP(r),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionFrom(result))
}

// loginWechat 接受 {"code"} 并返回会话。
func (h *Handler) loginWechat(w http.ResponseWriter, r *http.Request) {
	var body wechatLoginRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	result, err := h.service.LoginWechat(r.Context(), body.Code)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionFrom(result))
}

// session 返回 Bearer 令牌对应的账号。
func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	account, err := h.service.Authenticate(r.Context(), bearerToken(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accountFrom(*account))
}

// logout 撤销 Bearer 令牌并返回 204。
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.service.Logout(r.Context(), bearerToken(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// bearerToken 从 Authorization: Bearer 读取凭证。
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, prefix))
}

// clientIP 使用连接地址。位于可信代理之后的宿主应替换该实现。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
