package authmysql

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// blacklistRepository 持久化凭证禁用状态，并撤销关联账号的会话。
type blacklistRepository struct{ db *gorm.DB }

var _ authkit.BlacklistRepository = (*blacklistRepository)(nil)

// Check 在所属事务内锁定凭证占位，禁用凭证返回 ErrBlacklisted。
func (r *blacklistRepository) Check(ctx context.Context, credential authkit.Credential) error {
	entry, err := r.lock(ctx, credential)
	if err != nil {
		return err
	}
	if entry.Blocked {
		return authkit.ErrBlacklisted
	}
	return nil
}

// CheckAccount 锁定账号后检查全部凭证，与禁用操作串行化会话签发。
func (r *blacklistRepository) CheckAccount(ctx context.Context, accountID string) error {
	var account models.Account
	if err := r.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).
		Select("id").Where("id = ?", accountID).Take(&account).Error; err != nil {
		return mapError(err)
	}
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.Blacklist{}).
		Joins("JOIN auth_bindings ON auth_bindings.method = auth_blacklist.method AND auth_bindings.identifier = auth_blacklist.identifier").
		Where("auth_bindings.account_id = ? AND auth_blacklist.blocked = ?", accountID, true).
		Count(&count).Error; err != nil {
		return mapError(err)
	}
	if count > 0 {
		return authkit.ErrBlacklisted
	}
	return nil
}

// Add 在所属事务内幂等禁用凭证，清除邮箱验证码及关联账号的全部会话。
func (r *blacklistRepository) Add(ctx context.Context, entry authkit.BlacklistEntry) error {
	credential := authkit.Credential{Method: entry.Method, Identifier: entry.Identifier}
	if entry.ID != blacklistID(credential) {
		return authkit.ErrInvalidInput
	}
	current, err := r.lock(ctx, credential)
	if err != nil {
		return err
	}
	if !current.Blocked {
		if err := r.db.WithContext(ctx).Model(&models.Blacklist{}).
			Where("id = ?", current.ID).
			Updates(map[string]any{"blocked": true, "created_at": entry.CreatedAt.UTC()}).Error; err != nil {
			return mapError(err)
		}
	}
	var binding models.Binding
	if err := r.db.WithContext(ctx).Select("account_id").
		Where("method = ? AND identifier = ?", entry.Method, entry.Identifier).
		Find(&binding).Error; err != nil {
		return mapError(err)
	}
	if binding.AccountID != nil {
		var account models.Account
		if err := r.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id").Where("id = ?", *binding.AccountID).Take(&account).Error; err != nil {
			return mapError(err)
		}
	}
	if entry.Method == authkit.MethodEmail {
		if err := r.db.WithContext(ctx).Where("email = ?", entry.Identifier).
			Delete(&models.Challenge{}).Error; err != nil {
			return mapError(err)
		}
	}
	if binding.AccountID != nil {
		return mapError(r.db.WithContext(ctx).Where("account_id = ?", *binding.AccountID).
			Delete(&models.Session{}).Error)
	}
	return nil
}

// Remove 幂等解除禁用，并保留登录检查所使用的锁定占位。
func (r *blacklistRepository) Remove(ctx context.Context, id string) error {
	return mapError(r.db.WithContext(ctx).Model(&models.Blacklist{}).
		Where("id = ?", id).Update("blocked", false).Error)
}

// List 仅返回禁用条目，按加入时间及 ID 稳定分页，并隐藏微信凭证摘要。
func (r *blacklistRepository) List(ctx context.Context, page, limit int) (authkit.BlacklistPage, error) {
	if page < 1 || limit < 1 || page-1 > int(^uint(0)>>1)/limit {
		return authkit.BlacklistPage{}, authkit.ErrInvalidInput
	}
	result := authkit.BlacklistPage{Items: []authkit.BlacklistEntry{}, Page: page, Limit: limit}
	query := r.db.WithContext(ctx).Model(&models.Blacklist{}).Where("blocked = ?", true)
	if err := query.Count(&result.Total).Error; err != nil {
		return authkit.BlacklistPage{}, mapError(err)
	}
	var entries []models.Blacklist
	if err := query.Order("created_at DESC, id").Limit(limit).Offset((page - 1) * limit).
		Find(&entries).Error; err != nil {
		return authkit.BlacklistPage{}, mapError(err)
	}
	for _, entry := range entries {
		item := authkit.BlacklistEntry{ID: entry.ID, Method: entry.Method, CreatedAt: entry.CreatedAt}
		if entry.Method == authkit.MethodEmail || entry.Method == authkit.MethodPassword {
			item.Identifier = entry.Identifier
		}
		result.Items = append(result.Items, item)
	}
	return result, nil
}

// lock 通过自更新立即取得排他锁，避免首次检查同一凭证时升级共享锁。
func (r *blacklistRepository) lock(ctx context.Context, credential authkit.Credential) (*models.Blacklist, error) {
	id := blacklistID(credential)
	if err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"id"}),
	}).Create(&models.Blacklist{
		ID: id, Method: credential.Method, Identifier: credential.Identifier,
		CreatedAt: time.Unix(0, 0).UTC(),
	}).Error; err != nil {
		return nil, mapError(err)
	}
	var entry models.Blacklist
	if err := r.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", id).Take(&entry).Error; err != nil {
		return nil, mapError(err)
	}
	return &entry, nil
}

// blacklistID 为方法和已规范化标识生成稳定的黑名单条目 ID。
func blacklistID(credential authkit.Credential) string {
	sum := sha256.Sum256([]byte(credential.Method + ":" + credential.Identifier))
	return hex.EncodeToString(sum[:])
}
