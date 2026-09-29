package authkit

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrAdminUnavailable means the service's store does not support administration.
	ErrAdminUnavailable = errors.New("authkit: admin backend unavailable")
	// ErrLastBinding prevents an account from losing its final login method.
	ErrLastBinding = errors.New("authkit: cannot remove the last binding")
)

// AdminOverview contains counts for the administrator dashboard.
type AdminOverview struct {
	Accounts       int64 `json:"accounts"`
	EmailBindings  int64 `json:"email_bindings"`
	WechatBindings int64 `json:"wechat_bindings"`
	ActiveSessions int64 `json:"active_sessions"`
}

// AdminAccountSummary is the account list projection.
type AdminAccountSummary struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	Wechat         bool   `json:"wechat"`
	ActiveSessions int64  `json:"active_sessions"`
}

// AdminAccountPage is one page of matching accounts.
type AdminAccountPage struct {
	Items []AdminAccountSummary `json:"items"`
	Total int64                 `json:"total"`
	Page  int                   `json:"page"`
	Limit int                   `json:"limit"`
}

// AdminBindingInfo describes one login method. WeChat identifiers are withheld.
type AdminBindingInfo struct {
	Method     string `json:"method"`
	Identifier string `json:"identifier"`
}

// AdminSessionInfo describes one live session by its stored digest.
type AdminSessionInfo struct {
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
}

// AdminAccountDetail contains one account's bindings and live sessions.
type AdminAccountDetail struct {
	ID       string             `json:"id"`
	Username string             `json:"username"`
	Email    string             `json:"email"`
	Bindings []AdminBindingInfo `json:"bindings"`
	Sessions []AdminSessionInfo `json:"sessions"`
}

func (s *Service) adminRepository() (AdminRepository, error) {
	return s.store, nil
}

// AdminAccountByEmail resolves an existing mailbox account. The caller must
// enforce administrator authorization before exposing the result.
func (s *Service) AdminAccountByEmail(ctx context.Context, email string) (*Account, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	return s.store.Accounts().GetByEmail(ctx, email)
}

// AdminOverview returns live identity counts; callers must enforce admin authorization.
func (s *Service) AdminOverview(ctx context.Context) (AdminOverview, error) {
	repo, err := s.adminRepository()
	if err != nil {
		return AdminOverview{}, err
	}
	return repo.AdminOverview(ctx, s.now().UTC())
}

// AdminListAccounts searches accounts; callers must enforce admin authorization.
func (s *Service) AdminListAccounts(ctx context.Context, query string, page, limit int) (AdminAccountPage, error) {
	repo, err := s.adminRepository()
	if err != nil {
		return AdminAccountPage{}, err
	}
	return repo.AdminListAccounts(ctx, query, page, limit, s.now().UTC())
}

// AdminGetAccount loads bindings and live sessions; callers must enforce admin authorization.
func (s *Service) AdminGetAccount(ctx context.Context, id string) (AdminAccountDetail, error) {
	repo, err := s.adminRepository()
	if err != nil {
		return AdminAccountDetail{}, err
	}
	return repo.AdminGetAccount(ctx, id, s.now().UTC())
}

// AdminDeleteBinding removes a login method; callers must enforce admin authorization.
func (s *Service) AdminDeleteBinding(ctx context.Context, id, method string) error {
	repo, err := s.adminRepository()
	if err != nil {
		return err
	}
	return repo.AdminDeleteBinding(ctx, id, method)
}

// AdminRevokeSession removes one session; callers must enforce admin authorization.
func (s *Service) AdminRevokeSession(ctx context.Context, id, hash string) error {
	repo, err := s.adminRepository()
	if err != nil {
		return err
	}
	return repo.AdminRevokeSession(ctx, id, hash)
}

// AdminRevokeAllSessions removes an account's sessions; callers must enforce admin authorization.
func (s *Service) AdminRevokeAllSessions(ctx context.Context, id string) error {
	repo, err := s.adminRepository()
	if err != nil {
		return err
	}
	return repo.AdminRevokeAllSessions(ctx, id)
}
