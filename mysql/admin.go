package authmysql

import (
	"context"
	"strings"
	"time"

	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var _ authkit.AdminRepository = (*Store)(nil)

// AdminOverview 统计账号、已归属的绑定和未过期会话。
func (s *Store) AdminOverview(ctx context.Context, now time.Time) (authkit.AdminOverview, error) {
	var result authkit.AdminOverview
	if err := s.db.WithContext(ctx).Model(&models.Account{}).Count(&result.Accounts).Error; err != nil {
		return authkit.AdminOverview{}, mapError(err)
	}
	if err := s.db.WithContext(ctx).Model(&models.Binding{}).
		Where("method = ? AND account_id IS NOT NULL", authkit.MethodEmail).
		Count(&result.EmailBindings).Error; err != nil {
		return authkit.AdminOverview{}, mapError(err)
	}
	if err := s.db.WithContext(ctx).Model(&models.Binding{}).
		Where("method = ? AND account_id IS NOT NULL", authkit.MethodWechat).
		Count(&result.WechatBindings).Error; err != nil {
		return authkit.AdminOverview{}, mapError(err)
	}
	if err := s.db.WithContext(ctx).Model(&models.Session{}).
		Where("expires > ?", now.UTC()).Count(&result.ActiveSessions).Error; err != nil {
		return authkit.AdminOverview{}, mapError(err)
	}
	return result, nil
}

// AdminListAccounts 按账号 ID、用户名和已绑定邮箱搜索。
func (s *Store) AdminListAccounts(
	ctx context.Context, search string, page, limit int, now time.Time,
) (authkit.AdminAccountPage, error) {
	if page < 1 || limit < 1 || page-1 > int(^uint(0)>>1)/limit {
		return authkit.AdminAccountPage{}, authkit.ErrInvalidInput
	}
	result := authkit.AdminAccountPage{Items: []authkit.AdminAccountSummary{}, Page: page, Limit: limit}
	query := s.db.WithContext(ctx).Model(&models.Account{})
	if search = strings.TrimSpace(search); search != "" {
		pattern := "%" + escapeLike(strings.ToLower(search)) + "%"
		query = query.Where(`auth_accounts.id LIKE ? ESCAPE '!' OR LOWER(auth_accounts.username) LIKE ? ESCAPE '!' OR
			EXISTS (SELECT 1 FROM auth_bindings AS b WHERE b.account_id = auth_accounts.id
			AND b.method = ? AND b.identifier LIKE ? ESCAPE '!')`,
			pattern, pattern, authkit.MethodEmail, pattern)
	}
	if err := query.Count(&result.Total).Error; err != nil {
		return authkit.AdminAccountPage{}, mapError(err)
	}
	if err := query.Select(`auth_accounts.id,
		COALESCE(auth_accounts.username, '') AS username,
		COALESCE((SELECT b.identifier FROM auth_bindings AS b
			WHERE b.account_id = auth_accounts.id AND b.method = ? LIMIT 1), '') AS email,
		EXISTS (SELECT 1 FROM auth_bindings AS b
			WHERE b.account_id = auth_accounts.id AND b.method = ?) AS wechat,
		(SELECT COUNT(*) FROM auth_sessions AS sess
			WHERE sess.account_id = auth_accounts.id AND sess.expires > ?) AS active_sessions`,
		authkit.MethodEmail, authkit.MethodWechat, now.UTC()).
		Order("auth_accounts.id").Limit(limit).Offset((page - 1) * limit).
		Scan(&result.Items).Error; err != nil {
		return authkit.AdminAccountPage{}, mapError(err)
	}
	return result, nil
}

// AdminGetAccount 加载账号的凭证和有效会话。
func (s *Store) AdminGetAccount(ctx context.Context, id string, now time.Time) (authkit.AdminAccountDetail, error) {
	if strings.TrimSpace(id) == "" {
		return authkit.AdminAccountDetail{}, authkit.ErrInvalidInput
	}
	var account models.Account
	if err := s.db.WithContext(ctx).Where("id = ?", id).Take(&account).Error; err != nil {
		return authkit.AdminAccountDetail{}, mapError(err)
	}
	result := authkit.AdminAccountDetail{ID: account.ID, Bindings: []authkit.AdminBindingInfo{}, Sessions: []authkit.AdminSessionInfo{}}
	if account.Username != nil {
		result.Username = *account.Username
	}
	var bindings []models.Binding
	if err := s.db.WithContext(ctx).Where("account_id = ?", id).
		Order("method").Find(&bindings).Error; err != nil {
		return authkit.AdminAccountDetail{}, mapError(err)
	}
	for _, binding := range bindings {
		info := authkit.AdminBindingInfo{Method: binding.Method}
		if binding.Method == authkit.MethodEmail {
			info.Identifier = binding.Identifier
			result.Email = binding.Identifier
		}
		result.Bindings = append(result.Bindings, info)
	}
	var sessions []models.Session
	if err := s.db.WithContext(ctx).Where("account_id = ? AND expires > ?", id, now.UTC()).
		Order("expires DESC").Find(&sessions).Error; err != nil {
		return authkit.AdminAccountDetail{}, mapError(err)
	}
	for _, session := range sessions {
		result.Sessions = append(result.Sessions, authkit.AdminSessionInfo{ID: session.Hash, Expires: session.Expires})
	}
	return result, nil
}

// AdminDeleteBinding 移除一条凭证，同时保留至少一种登录方式。
func (s *Store) AdminDeleteBinding(ctx context.Context, accountID, method string) error {
	if strings.TrimSpace(accountID) == "" ||
		(method != authkit.MethodEmail && method != authkit.MethodWechat) {
		return authkit.ErrInvalidInput
	}
	return mapError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var account models.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", accountID).Take(&account).Error; err != nil {
			return mapError(err)
		}
		var binding models.Binding
		if err := tx.Where("account_id = ? AND method = ?", accountID, method).
			Take(&binding).Error; err != nil {
			return mapError(err)
		}
		var count int64
		if err := tx.Model(&models.Binding{}).
			Where("account_id = ? AND method IN ?", accountID,
				[]string{authkit.MethodEmail, authkit.MethodWechat}).Count(&count).Error; err != nil {
			return mapError(err)
		}
		if count <= 1 {
			return authkit.ErrLastBinding
		}
		result := tx.Where("account_id = ? AND method = ? AND identifier = ?",
			accountID, method, binding.Identifier).Delete(&models.Binding{})
		if result.Error != nil {
			return mapError(result.Error)
		}
		if result.RowsAffected == 0 {
			return authkit.ErrNotFound
		}
		if method == authkit.MethodEmail {
			if err := tx.Where("email = ?", binding.Identifier).Delete(&models.Challenge{}).Error; err != nil {
				return mapError(err)
			}
		}
		return mapError(tx.Where("account_id = ?", accountID).Delete(&models.Session{}).Error)
	}))
}

// AdminRevokeSession 只移除属于指定账号的会话。
func (s *Store) AdminRevokeSession(ctx context.Context, accountID, hash string) error {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(hash) == "" {
		return authkit.ErrInvalidInput
	}
	result := s.db.WithContext(ctx).
		Where("account_id = ? AND hash = ?", accountID, hash).Delete(&models.Session{})
	if result.Error != nil {
		return mapError(result.Error)
	}
	if result.RowsAffected == 0 {
		return authkit.ErrNotFound
	}
	return nil
}

// AdminRevokeAllSessions 移除一个账号的全部会话。
func (s *Store) AdminRevokeAllSessions(ctx context.Context, accountID string) error {
	if strings.TrimSpace(accountID) == "" {
		return authkit.ErrInvalidInput
	}
	var account models.Account
	if err := s.db.WithContext(ctx).Where("id = ?", accountID).Take(&account).Error; err != nil {
		return mapError(err)
	}
	return mapError(s.db.WithContext(ctx).
		Where("account_id = ?", accountID).Delete(&models.Session{}).Error)
}

func escapeLike(value string) string {
	return strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(value)
}
