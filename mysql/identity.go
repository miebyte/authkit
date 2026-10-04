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
	"gorm.io/gorm/logger"
)

// accountRepository 持久化账号及其凭证绑定。
type accountRepository struct{ db *gorm.DB }

// GetByID 返回指定账号及其当前邮箱绑定。
func (r *accountRepository) GetByID(ctx context.Context, id string) (*authkit.Account, error) {
	return r.findAccount(ctx, id, false)
}

// GetByPasswordIdentifier 按区分大小写的密码登录标识返回账号。
func (r *accountRepository) GetByPasswordIdentifier(ctx context.Context, identifier string) (*authkit.Account, error) {
	binding, err := r.findBinding(ctx, authkit.MethodPassword, identifier, false)
	if err != nil {
		return nil, err
	}
	if binding.AccountID == nil {
		return nil, authkit.ErrNotFound
	}
	return r.findAccount(ctx, *binding.AccountID, false)
}

// GetPasswordIdentifier 返回账号绑定的密码登录标识。
func (r *accountRepository) GetPasswordIdentifier(ctx context.Context, accountID string) (string, error) {
	var binding models.Binding
	if err := r.db.WithContext(ctx).
		Select("identifier").
		Where("account_id = ? AND method = ?", accountID, authkit.MethodPassword).
		Take(&binding).Error; err != nil {
		return "", mapError(err)
	}
	return binding.Identifier, nil
}

// GetPasswordHash 读取已锁定账号的密码摘要；没有可用密码时返回 ErrNotFound。
func (r *accountRepository) GetPasswordHash(ctx context.Context, accountID string) (string, error) {
	var binding models.Binding
	if err := r.db.WithContext(ctx).
		Select("password_hash").
		Where("account_id = ? AND method = ?", accountID, authkit.MethodPassword).
		Take(&binding).Error; err != nil {
		return "", mapError(err)
	}
	if binding.PasswordHash == nil || *binding.PasswordHash == "" {
		return "", authkit.ErrNotFound
	}
	return *binding.PasswordHash, nil
}

// SetPasswordHash 为已锁定的账号开通或重置密码，已有登录标识不可更改。
func (r *accountRepository) SetPasswordHash(ctx context.Context, accountID, identifier, hash string) error {
	if identifier == "" || hash == "" {
		return authkit.ErrInvalidInput
	}
	// 密码摘要不能进入宿主配置的 GORM SQL 日志；该 Session 仍使用同一个事务。
	db := r.db.WithContext(ctx).Session(&gorm.Session{Logger: logger.Discard})
	var account models.Account
	err := db.Select("id").
		Where("id = ?", accountID).
		Take(&account).Error
	if err != nil {
		return mapError(err)
	}
	var binding models.Binding
	err = db.Select("identifier").
		Where("account_id = ? AND method = ?", accountID, authkit.MethodPassword).
		Take(&binding).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 唯一冲突只返回错误，不能通过 upsert 修改另一账号的密码。
		return mapError(db.Create(&models.Binding{
			Method: authkit.MethodPassword, Identifier: identifier, AccountID: &accountID, PasswordHash: &hash,
		}).Error)
	}
	if err != nil {
		return mapError(err)
	}
	if binding.Identifier != identifier {
		return authkit.ErrConflict
	}
	return mapError(db.Model(&models.Binding{}).
		Where("account_id = ? AND method = ? AND identifier = ?", accountID, authkit.MethodPassword, identifier).
		Update("password_hash", hash).Error)
}

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
	err := r.db.WithContext(ctx).Create(accountModel(account)).Error
	if err != nil {
		return mapError(err)
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
	res := r.db.WithContext(ctx).
		Model(&models.Binding{}).
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

// Get 按摘要读取会话；不存在时返回 ErrNotFound。
func (r *sessionRepository) Get(ctx context.Context, hash string) (*authkit.Session, error) {
	var session models.Session
	if err := r.db.WithContext(ctx).Where("hash = ?", hash).Take(&session).Error; err != nil {
		return nil, mapError(err)
	}
	return mapper.SessionModelToDomain(&session), nil
}

// Create 插入会话，不持久化明文凭证。
func (r *sessionRepository) Create(ctx context.Context, s *authkit.Session) error {
	return mapError(r.db.WithContext(ctx).Create(mapper.SessionDomainToModel(s)).Error)
}

// Delete 撤销会话；会话已经撤销时同样成功。
func (r *sessionRepository) Delete(ctx context.Context, hash string) error {
	return mapError(r.db.WithContext(ctx).Where("hash = ?", hash).
		Delete(&models.Session{}).Error)
}

// DeleteByAccount 撤销指定账号的全部会话；调用方须先锁定账号。
func (r *sessionRepository) DeleteByAccount(ctx context.Context, accountID string) error {
	return mapError(r.db.WithContext(ctx).Where("account_id = ?", accountID).
		Delete(&models.Session{}).Error)
}

// accountModel 把公开账号映射为数据行。空展示名存为 NULL。
func accountModel(account *authkit.Account) *models.Account {
	m := &models.Account{ID: account.ID}
	if account.Username != "" {
		username := account.Username
		m.Username = &username
	}
	return m
}
