package authkit

import (
	"context"
	"errors"
	"strings"
	"time"
)

// BlacklistEntry 描述一条黑名单。列表中的微信标识为空，不暴露 OpenID 或其摘要。
type BlacklistEntry struct {
	ID         string    `json:"id"`
	Method     string    `json:"method"`
	Identifier string    `json:"identifier"`
	CreatedAt  time.Time `json:"created_at"`
}

// BlacklistPage 是已拉黑凭证的一页结果。
type BlacklistPage struct {
	Items []BlacklistEntry `json:"items"`
	Total int64            `json:"total"`
	Page  int              `json:"page"`
	Limit int              `json:"limit"`
}

// AddBlacklist 拉黑邮箱、密码登录标识或原始微信 OpenID，并撤销关联账号的会话；调用方必须完成管理鉴权。
func (s *Service) AddBlacklist(ctx context.Context, credential Credential) error {
	return s.addBlacklist(ctx, credential, "")
}

// AdminAddBlacklist 加入黑名单，同时保护指定管理员的登录凭证；调用方必须完成管理鉴权。
func (s *Service) AdminAddBlacklist(ctx context.Context, credential Credential, protectedAccountID string) error {
	if !validToken(protectedAccountID) {
		return ErrInvalidInput
	}
	return s.addBlacklist(ctx, credential, strings.ToLower(protectedAccountID))
}

// addBlacklist 规范化输入，并在身份事务内限制凭证。
func (s *Service) addBlacklist(ctx context.Context, input Credential, protectedAccountID string) error {
	credential, err := blacklistCredential(input)
	if err != nil {
		return err
	}
	entry := BlacklistEntry{
		ID:     digest(credential.Method + ":" + credential.Identifier),
		Method: credential.Method, Identifier: credential.Identifier,
		CreatedAt: s.now().UTC().Truncate(time.Microsecond),
	}
	return s.store.WithTransaction(ctx, func(repos Repositories) error {
		if protectedAccountID != "" {
			if err := repos.Blacklist().Check(ctx, credential); err != nil && !errors.Is(err, ErrBlacklisted) {
				return err
			}
			var account *Account
			var err error
			switch credential.Method {
			case MethodEmail:
				account, err = repos.Accounts().GetByEmail(ctx, credential.Identifier)
			case MethodWechat:
				account, err = repos.Accounts().GetByWechat(ctx, credential.Identifier)
			case MethodPassword:
				account, err = repos.Accounts().GetByPasswordIdentifier(ctx, credential.Identifier)
			}
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if account != nil && account.ID == protectedAccountID {
				return ErrProtectedAccount
			}
		}
		return repos.Blacklist().Add(ctx, entry)
	})
}

// RemoveBlacklist 按条目 ID 幂等解除限制；已撤销的验证码和会话不会恢复，调用方必须完成管理鉴权。
func (s *Service) RemoveBlacklist(ctx context.Context, id string) error {
	if !validToken(id) {
		return ErrInvalidInput
	}
	return s.store.WithTransaction(ctx, func(repos Repositories) error {
		return repos.Blacklist().Remove(ctx, strings.ToLower(id))
	})
}

// ListBlacklist 分页列出黑名单；调用方必须完成管理鉴权。
func (s *Service) ListBlacklist(ctx context.Context, page, limit int) (BlacklistPage, error) {
	if page < 1 || limit < 1 || limit > 100 || page-1 > int(^uint(0)>>1)/limit {
		return BlacklistPage{}, ErrInvalidInput
	}
	return s.store.Blacklist().List(ctx, page, limit)
}

// blacklistCredential 将管理输入转换为仓储使用的邮箱、密码登录标识或 OpenID 摘要。
func blacklistCredential(input Credential) (Credential, error) {
	switch input.Method {
	case MethodEmail:
		email, err := NormalizeEmail(input.Identifier)
		return Credential{Method: MethodEmail, Identifier: email}, err
	case MethodPassword:
		identifier, err := NormalizeUsername(input.Identifier)
		return Credential{Method: MethodPassword, Identifier: identifier}, err
	case MethodWechat:
		if strings.TrimSpace(input.Identifier) == "" || len(input.Identifier) > 128 {
			return Credential{}, ErrInvalidInput
		}
		return Credential{Method: MethodWechat, Identifier: digest(input.Identifier)}, nil
	default:
		return Credential{}, ErrInvalidInput
	}
}

// checkEmailAccount 检查邮箱账号的其他绑定，防止通过未拉黑的邮箱绕过限制。
func checkEmailAccount(ctx context.Context, repos Repositories, email string) error {
	account, err := repos.Accounts().GetByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return repos.Blacklist().CheckAccount(ctx, account.ID)
}
