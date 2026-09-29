package authmysql

import (
	"context"
	"errors"
	"time"

	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/mapper"
	"github.com/miebyte/authkit/mysql/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// accountRepository 持久化账号及其凭证绑定。
type accountRepository struct{ db *gorm.DB }

// GetByEmail 返回绑定到规范化邮箱地址的账号。
func (r *accountRepository) GetByEmail(
	ctx context.Context,
	email string,
) (*authkit.Account, error) {
	binding, err := r.findBinding(ctx, authkit.MethodEmail, email, false)
	if err != nil {
		return nil, err
	}
	if binding.AccountID == nil {
		return nil, authkit.ErrNotFound
	}
	return r.findAccount(ctx, *binding.AccountID, false)
}

// GetByWechat 即使 OpenID 尚无所有者也会锁定它。
func (r *accountRepository) GetByWechat(
	ctx context.Context,
	openIDHash string,
) (*authkit.Account, error) {
	// 把键更新为自身会立即取得排他锁，避免并发的首次登录命中同一 OpenID 时升级共享锁。
	if err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"method"}),
	}).Create(&models.Binding{
		Method: authkit.MethodWechat, Identifier: openIDHash,
	}).Error; err != nil {
		return nil, mapError(err)
	}
	binding, err := r.findBinding(ctx, authkit.MethodWechat, openIDHash, true)
	if err != nil {
		return nil, err
	}
	if binding.AccountID == nil {
		return nil, authkit.ErrNotFound
	}
	return r.findAccount(ctx, *binding.AccountID, true)
}

// Create 插入账号及其初始登录凭证。
func (r *accountRepository) Create(
	ctx context.Context,
	account *authkit.Account,
	credential authkit.Credential,
) error {
	if err := mapError(r.db.WithContext(ctx).Create(accountModel(account)).Error); err != nil {
		return err
	}
	return r.createCredential(ctx, account.ID, credential)
}

// GetBySessionToken 仅在匹配会话仍然有效时返回账号。
func (r *accountRepository) GetBySessionToken(
	ctx context.Context,
	hash string,
	now time.Time,
) (*authkit.Account, error) {
	var m models.Account
	if err := r.db.WithContext(ctx).Model(&models.Account{}).
		Select("auth_accounts.*").
		Joins("JOIN auth_sessions ON auth_sessions.account_id = auth_accounts.id").
		Where("auth_sessions.hash = ? AND auth_sessions.expires > ?", hash, now.UTC()).
		Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return r.withEmail(ctx, &m)
}

// findAccount 加载账号，并可以在修改绑定前锁定该行。
func (r *accountRepository) findAccount(
	ctx context.Context,
	id string,
	lock bool,
) (*authkit.Account, error) {
	query := r.db.WithContext(ctx).Where("id = ?", id)
	if lock {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var m models.Account
	if err := query.Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return r.withEmail(ctx, &m)
}

// findBinding 加载一条凭证，并可以锁定它。
func (r *accountRepository) findBinding(
	ctx context.Context,
	method, identifier string,
	lock bool,
) (*models.Binding, error) {
	query := r.db.WithContext(ctx).Where("method = ? AND identifier = ?", method, identifier)
	if lock {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var binding models.Binding
	if err := query.Take(&binding).Error; err != nil {
		return nil, mapError(err)
	}
	return &binding, nil
}

// accountModel 把公开账号映射为数据行。空用户名存为 NULL。
func accountModel(account *authkit.Account) *models.Account {
	m := &models.Account{ID: account.ID}
	if account.Username != "" {
		username := account.Username
		m.Username = &username
	}
	return m
}

// withEmail 用账号的邮箱绑定填充邮箱投影。
func (r *accountRepository) withEmail(
	ctx context.Context,
	account *models.Account,
) (*authkit.Account, error) {
	var binding models.Binding
	err := r.db.WithContext(ctx).
		Where("account_id = ? AND method = ?", account.ID, authkit.MethodEmail).
		Take(&binding).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return mapper.AccountToDomain(account, ""), nil
	}
	if err != nil {
		return nil, mapError(err)
	}
	return mapper.AccountToDomain(account, binding.Identifier), nil
}

// createCredential 写入新账号的初始凭证，并认领查询微信身份时创建的锁定占位。
func (r *accountRepository) createCredential(
	ctx context.Context,
	accountID string,
	credential authkit.Credential,
) error {
	res := r.db.WithContext(ctx).Model(&models.Binding{}).
		Where(
			"method = ? AND identifier = ? AND account_id IS NULL",
			credential.Method,
			credential.Identifier,
		).
		Update("account_id", accountID)
	if res.Error != nil {
		return mapError(res.Error)
	}
	if res.RowsAffected == 1 {
		return nil
	}
	return mapError(r.db.WithContext(ctx).Create(&models.Binding{
		Method: credential.Method, Identifier: credential.Identifier, AccountID: &accountID,
	}).Error)
}

// challengeRepository 按邮箱串行化每一次签发和校验。
type challengeRepository struct{ db *gorm.DB }

// Get 锁定邮箱；尚无验证码时插入一条未就绪的占位记录。
func (r *challengeRepository) Get(ctx context.Context, email string) (*authkit.Challenge, error) {
	epoch := time.Unix(0, 0).UTC()
	if err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"email"}),
	}).Create(&models.Challenge{Email: email, Expires: epoch, Sent: epoch}).Error; err != nil {
		return nil, mapError(err)
	}
	return r.Find(ctx, email)
}

// Find 锁定已有验证挑战，不为未知邮箱分配行。
func (r *challengeRepository) Find(ctx context.Context, email string) (*authkit.Challenge, error) {
	var m models.Challenge
	if err := r.db.WithContext(ctx).
		Where("email = ?", email).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return mapper.ChallengeModelToDomain(&m), nil
}

// Save 显式写入零值和 false，同时保留已锁定的行。
func (r *challengeRepository) Save(ctx context.Context, c *authkit.Challenge) error {
	return mapError(r.db.WithContext(ctx).Model(&models.Challenge{}).
		Where("email = ?", c.Email).Updates(map[string]any{
		"hash":    c.Hash,
		"expires": c.Expires.UTC(), "sent": c.Sent.UTC(),
		"attempts": c.Attempts, "ready": c.Ready,
	}).Error)
}

// rateRepository 在固定的小时窗口内统计发送次数。
type rateRepository struct{ db *gorm.DB }

// Hit 在所属事务内原子地检查并递增一个限流桶。
func (r *rateRepository) Hit(ctx context.Context, id string, now time.Time, limit int) error {
	now = now.UTC()
	if err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"id"}),
	}).Create(&models.Rate{ID: id, Starts: now}).Error; err != nil {
		return mapError(err)
	}
	var m models.Rate
	if err := r.db.WithContext(ctx).
		Where("id = ?", id).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Take(&m).Error; err != nil {
		return mapError(err)
	}
	if now.Sub(m.Starts) >= time.Hour {
		m.Starts = now
		m.Hits = 0
	}
	if m.Hits >= limit {
		return authkit.ErrTooManyRequests
	}
	return mapError(r.db.WithContext(ctx).Model(&models.Rate{}).
		Where("id = ?", id).
		Updates(map[string]any{"starts": m.Starts, "hits": m.Hits + 1}).Error)
}

// sessionRepository 持久化并撤销应用会话摘要。
type sessionRepository struct{ db *gorm.DB }

// Create 插入会话，不持久化明文凭证。
func (r *sessionRepository) Create(ctx context.Context, s *authkit.Session) error {
	return mapError(r.db.WithContext(ctx).Create(mapper.SessionDomainToModel(s)).Error)
}

// Delete 撤销会话；会话已经撤销时同样成功。
func (r *sessionRepository) Delete(ctx context.Context, hash string) error {
	return mapError(r.db.WithContext(ctx).Where("hash = ?", hash).
		Delete(&models.Session{}).Error)
}
