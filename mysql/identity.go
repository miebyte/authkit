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

// accountRepository persists accounts and their credential bindings.
type accountRepository struct{ db *gorm.DB }

// GetByEmail returns the account bound to a normalized email address.
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

// GetByID locks an account before changing its bindings.
func (r *accountRepository) GetByID(ctx context.Context, id string) (*authkit.Account, error) {
	return r.findAccount(ctx, id, true)
}

// GetByWechat locks an OpenID even when it has no owner yet.
func (r *accountRepository) GetByWechat(
	ctx context.Context,
	openIDHash string,
) (*authkit.Account, error) {
	// Updating the key to itself takes an exclusive lock immediately, avoiding
	// shared-lock upgrades when concurrent first logins find the same OpenID.
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

// BindWechat assigns a locked OpenID once. One account keeps a single WeChat credential.
func (r *accountRepository) BindWechat(ctx context.Context, openIDHash, accountID string) error {
	return r.bind(ctx, authkit.MethodWechat, openIDHash, accountID)
}

// HasWechat reports whether the account has an OpenID binding.
func (r *accountRepository) HasWechat(ctx context.Context, accountID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Binding{}).
		Where("account_id = ? AND method = ?", accountID, authkit.MethodWechat).
		Count(&count).Error
	return count > 0, mapError(err)
}

// BindEmail assigns an unused mailbox only to an account without an email.
func (r *accountRepository) BindEmail(ctx context.Context, accountID, email string) error {
	return r.bind(ctx, authkit.MethodEmail, email, accountID)
}

// Create inserts an account and its mailbox binding when an email is present.
func (r *accountRepository) Create(ctx context.Context, account *authkit.Account) error {
	if err := mapError(r.db.WithContext(ctx).Create(accountModel(account)).Error); err != nil {
		return err
	}
	if account.Email == "" {
		return nil
	}
	return r.BindEmail(ctx, account.ID, account.Email)
}

// GetBySessionToken returns an account only while its matching session is live.
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

// findAccount loads an account, optionally locking the row before a binding change.
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

// findBinding loads one credential, optionally locking it.
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

// accountModel maps the public account onto its row. An empty username is stored as NULL.
func accountModel(account *authkit.Account) *models.Account {
	m := &models.Account{ID: account.ID}
	if account.Username != "" {
		username := account.Username
		m.Username = &username
	}
	return m
}

// withEmail fills the mailbox projection from the account's email binding.
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

// bind claims an unbound credential or inserts one. Indexes keep each credential unique
// and each account limited to one credential of a method.
func (r *accountRepository) bind(ctx context.Context, method, identifier, accountID string) error {
	res := r.db.WithContext(ctx).Model(&models.Binding{}).
		Where("method = ? AND identifier = ? AND account_id IS NULL", method, identifier).
		Update("account_id", accountID)
	if err := bindingConflict(method, res.Error); err != nil {
		return err
	}
	if res.Error != nil {
		return mapError(res.Error)
	}
	if res.RowsAffected == 1 {
		return nil
	}
	if method == authkit.MethodWechat {
		return authkit.ErrWechatBound
	}
	err := r.db.WithContext(ctx).Create(&models.Binding{
		Method: method, Identifier: identifier, AccountID: &accountID,
	}).Error
	if err == nil {
		return nil
	}
	if !errors.Is(mapError(err), authkit.ErrConflict) {
		return mapError(err)
	}
	var count int64
	if countErr := r.db.WithContext(ctx).Model(&models.Binding{}).
		Where("account_id = ? AND method = ?", accountID, method).
		Count(&count).Error; countErr != nil {
		return mapError(countErr)
	}
	if count > 0 {
		return authkit.ErrEmailBound
	}
	return authkit.ErrEmailAccountConflict
}

// bindingConflict maps a uniqueness failure onto the credential's public error.
func bindingConflict(method string, err error) error {
	if !errors.Is(mapError(err), authkit.ErrConflict) {
		return nil
	}
	if method == authkit.MethodWechat {
		return authkit.ErrWechatBound
	}
	return authkit.ErrEmailAccountConflict
}

// challengeRepository serializes every issuance and verification by mailbox.
type challengeRepository struct{ db *gorm.DB }

// Get locks the mailbox, inserting an unready placeholder if it has no code.
func (r *challengeRepository) Get(ctx context.Context, email string) (*authkit.Challenge, error) {
	epoch := time.Unix(0, 0).UTC()
	if err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"email"}),
	}).Create(&models.Challenge{Email: email, Expires: epoch, Sent: epoch}).Error; err != nil {
		return nil, mapError(err)
	}
	return r.Find(ctx, email)
}

// Find locks an existing challenge without allocating rows for unknown mailboxes.
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

// Save explicitly writes zero and false values while retaining the locked row.
func (r *challengeRepository) Save(ctx context.Context, c *authkit.Challenge) error {
	return mapError(r.db.WithContext(ctx).Model(&models.Challenge{}).
		Where("email = ?", c.Email).Updates(map[string]any{
		"hash":    c.Hash,
		"expires": c.Expires.UTC(), "sent": c.Sent.UTC(),
		"attempts": c.Attempts, "ready": c.Ready,
	}).Error)
}

// rateRepository counts send attempts within a fixed hourly window.
type rateRepository struct{ db *gorm.DB }

// Hit atomically checks and increments a rate bucket within its transaction.
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

// sessionRepository persists and revokes application session digests.
type sessionRepository struct{ db *gorm.DB }

// Create inserts a session without persisting its plaintext credential.
func (r *sessionRepository) Create(ctx context.Context, s *authkit.Session) error {
	return mapError(r.db.WithContext(ctx).Create(mapper.SessionDomainToModel(s)).Error)
}

// Delete revokes a session and also succeeds when it has already been revoked.
func (r *sessionRepository) Delete(ctx context.Context, hash string) error {
	return mapError(r.db.WithContext(ctx).Where("hash = ?", hash).
		Delete(&models.Session{}).Error)
}
