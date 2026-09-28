package authmysql

import (
	"context"
	"errors"

	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/mapper"
	"github.com/miebyte/authkit/mysql/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// userRepository 只持久化账号，登录方式的主体和归属另由 identityRepository 管理。
type userRepository struct{ db *gorm.DB }

// GetByID 读取账号但不加写锁，适用于只需认证身份的查询。
func (r *userRepository) GetByID(ctx context.Context, id string) (*authkit.User, error) {
	var m models.User
	if err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return mapper.UserModelToDomain(&m), nil
}

// Lock 使用 FOR UPDATE 锁定账号，供身份绑定和会话轮换使用。
// 调用方应先取得身份行锁，再锁账号，最后锁当前会话，以保持统一锁序。
func (r *userRepository) Lock(ctx context.Context, id string) (*authkit.User, error) {
	var m models.User
	if err := r.db.WithContext(ctx).Where("id = ?", id).
		Clauses(clause.Locking{Strength: "UPDATE"}).Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return mapper.UserModelToDomain(&m), nil
}

// Create 只插入账号 ID；创建账号与绑定首个身份必须处于同一事务。
func (r *userRepository) Create(ctx context.Context, u *authkit.User) error {
	return mapError(r.db.WithContext(ctx).Create(mapper.UserDomainToModel(u)).Error)
}

// identityRepository 管理已验证主体与账号之间的唯一归属。
type identityRepository struct{ db *gorm.DB }

// Lock 首次访问时插入 UserID 为 NULL 的占位行，随后使用 FOR UPDATE 加独占锁。
// 冲突时对身份键做无实质变化的更新，使并发首登在同一行上串行化；调用方必须在事务中使用。
func (r *identityRepository) Lock(
	ctx context.Context,
	key authkit.IdentityKey,
) (*authkit.Identity, error) {
	if err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"namespace"}),
	}).Create(&models.Identity{
		Namespace: key.Namespace, Scope: key.Scope, Subject: key.Subject,
	}).Error; err != nil {
		return nil, mapError(err)
	}
	var m models.Identity
	if err := r.db.WithContext(ctx).
		Where("namespace = ? AND scope = ? AND subject = ?", key.Namespace, key.Scope, key.Subject).
		Clauses(clause.Locking{Strength: "UPDATE"}).Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return mapper.IdentityModelToDomain(&m), nil
}

// Bind 仅将已锁定的 NULL 占位行指派给账号，不覆盖已有归属。
// 主键保证主体不被另一个账号取得，identity_owner 唯一索引保证一个账号在
// 同一命名空间和范围内只绑定一个主体；两类冲突分别返回稳定错误。
func (r *identityRepository) Bind(
	ctx context.Context,
	key authkit.IdentityKey,
	userID string,
) error {
	res := r.db.WithContext(ctx).Model(&models.Identity{}).
		Where("namespace = ? AND scope = ? AND subject = ? AND user_id IS NULL",
			key.Namespace, key.Scope, key.Subject).
		Update("user_id", userID)
	if errors.Is(mapError(res.Error), authkit.ErrConflict) {
		return authkit.ErrIdentityBound
	}
	if res.Error != nil {
		return mapError(res.Error)
	}
	if res.RowsAffected == 1 {
		return nil
	}
	var m models.Identity
	if err := r.db.WithContext(ctx).
		Where("namespace = ? AND scope = ? AND subject = ?", key.Namespace, key.Scope, key.Subject).
		Take(&m).Error; err != nil {
		return mapError(err)
	}
	if m.UserID == nil {
		return authkit.ErrConflict
	}
	if *m.UserID != userID {
		return authkit.ErrIdentityConflict
	}
	return nil
}

// ListByUser 按身份键排序返回账号已绑定的身份，不包含 UserID 为 NULL 的占位行。
func (r *identityRepository) ListByUser(
	ctx context.Context,
	userID string,
) ([]authkit.Identity, error) {
	var rows []models.Identity
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).
		Order("namespace, scope, subject").Find(&rows).Error; err != nil {
		return nil, mapError(err)
	}
	identities := make([]authkit.Identity, 0, len(rows))
	for i := range rows {
		identities = append(identities, *mapper.IdentityModelToDomain(&rows[i]))
	}
	return identities, nil
}

// sessionRepository 仅存储应用凭证的摘要、账号归属和到期时间。
type sessionRepository struct{ db *gorm.DB }

// Get 不加写锁读取会话，供普通认证检查使用。
func (r *sessionRepository) Get(ctx context.Context, hash string) (*authkit.Session, error) {
	var m models.Session
	if err := r.db.WithContext(ctx).Where("hash = ?", hash).Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return mapper.SessionModelToDomain(&m), nil
}

// GetForUpdate 锁定当前会话，供绑定时重查其有效性并轮换凭证。
// 调用方先锁身份和账号，再锁会话；并发使用同一 Token 时只有一次绑定可成功。
func (r *sessionRepository) GetForUpdate(
	ctx context.Context,
	hash string,
) (*authkit.Session, error) {
	var m models.Session
	if err := r.db.WithContext(ctx).Where("hash = ?", hash).
		Clauses(clause.Locking{Strength: "UPDATE"}).Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return mapper.SessionModelToDomain(&m), nil
}

// Create 仅持久化 Token 摘要；明文 Token 只由上层在事务提交后交付。
func (r *sessionRepository) Create(ctx context.Context, session *authkit.Session) error {
	return mapError(r.db.WithContext(ctx).Create(mapper.SessionDomainToModel(session)).Error)
}

// Delete 按摘要撤销单个会话；不存在时也返回成功，便于重复退出。
func (r *sessionRepository) Delete(ctx context.Context, hash string) error {
	return mapError(r.db.WithContext(ctx).Where("hash = ?", hash).Delete(&models.Session{}).Error)
}
