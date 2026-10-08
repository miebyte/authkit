package authkit

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrAdminUnavailable 表示服务的存储不支持管理能力。
	ErrAdminUnavailable = errors.New("authkit: admin backend unavailable")
	// ErrLastBinding 防止账号失去最后一种登录方式。
	ErrLastBinding = errors.New("authkit: cannot remove the last binding")
)

// AdminOverview 包含管理后台的统计计数。
type AdminOverview struct {
	Accounts       int64 `json:"accounts"`
	EmailBindings  int64 `json:"email_bindings"`
	WechatBindings int64 `json:"wechat_bindings"`
	ActiveSessions int64 `json:"active_sessions"`
}

// AdminAccountSummary 是账号列表的投影。
type AdminAccountSummary struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	Wechat         bool   `json:"wechat"`
	Password       bool   `json:"password"`
	ActiveSessions int64  `json:"active_sessions"`
}

// AdminAccountPage 是匹配账号的一页结果。
type AdminAccountPage struct {
	Items []AdminAccountSummary `json:"items"`
	Total int64                 `json:"total"`
	Page  int                   `json:"page"`
	Limit int                   `json:"limit"`
}

// AdminBindingInfo 描述一种登录方式。微信标识会被隐藏。
type AdminBindingInfo struct {
	Method     string `json:"method"`
	Identifier string `json:"identifier"`
}

// AdminSessionInfo 用已存储的摘要描述一个有效会话。
type AdminSessionInfo struct {
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
}

// AdminAccountDetail 包含一个账号的绑定和有效会话。
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

// AdminAccountByEmail 解析已存在的邮箱账号。调用方在暴露结果前必须完成管理员鉴权。
func (s *Service) AdminAccountByEmail(ctx context.Context, email string) (*Account, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	return s.store.Accounts().GetByEmail(ctx, email)
}

// AdminOverview 返回当前身份计数；调用方必须完成管理员鉴权。
func (s *Service) AdminOverview(ctx context.Context) (AdminOverview, error) {
	repo, err := s.adminRepository()
	if err != nil {
		return AdminOverview{}, err
	}
	return repo.AdminOverview(ctx, s.now().UTC())
}

// AdminListAccounts 搜索账号；调用方必须完成管理员鉴权。
func (s *Service) AdminListAccounts(
	ctx context.Context,
	query string,
	page, limit int,
) (AdminAccountPage, error) {
	repo, err := s.adminRepository()
	if err != nil {
		return AdminAccountPage{}, err
	}
	return repo.AdminListAccounts(ctx, query, page, limit, s.now().UTC())
}

// AdminGetAccount 加载绑定和有效会话；调用方必须完成管理员鉴权。
func (s *Service) AdminGetAccount(ctx context.Context, id string) (AdminAccountDetail, error) {
	repo, err := s.adminRepository()
	if err != nil {
		return AdminAccountDetail{}, err
	}
	return repo.AdminGetAccount(ctx, id, s.now().UTC())
}

// AdminDeleteBinding 移除一种登录方式；调用方必须完成管理员鉴权。
func (s *Service) AdminDeleteBinding(ctx context.Context, id, method string) error {
	repo, err := s.adminRepository()
	if err != nil {
		return err
	}
	return repo.AdminDeleteBinding(ctx, id, method)
}

// AdminRevokeSession 移除一个会话；调用方必须完成管理员鉴权。
func (s *Service) AdminRevokeSession(ctx context.Context, id, hash string) error {
	repo, err := s.adminRepository()
	if err != nil {
		return err
	}
	return repo.AdminRevokeSession(ctx, id, hash)
}

// AdminRevokeAllSessions 移除账号的全部会话；调用方必须完成管理员鉴权。
func (s *Service) AdminRevokeAllSessions(ctx context.Context, id string) error {
	repo, err := s.adminRepository()
	if err != nil {
		return err
	}
	return repo.AdminRevokeAllSessions(ctx, id)
}
