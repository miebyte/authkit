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

// userRepository persists account and application-scoped identity relationships.
type userRepository struct{ db *gorm.DB }

// GetByEmail returns the account associated with a normalized email address.
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*authkit.User, error) {
	var m models.User
	if err := r.db.WithContext(ctx).Where("email = ?", email).Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return mapper.UserModelToDomain(&m), nil
}

// GetByID locks an account before changing its identities.
func (r *userRepository) GetByID(ctx context.Context, id string) (*authkit.User, error) {
	var m models.User
	if err := r.db.WithContext(ctx).
		Where("id = ?", id).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return mapper.UserModelToDomain(&m), nil
}

// GetByWechat locks an identity even when it has no owner yet.
func (r *userRepository) GetByWechat(
	ctx context.Context,
	appID, openIDHash string,
) (*authkit.User, error) {
	// Updating the key to itself takes an exclusive lock immediately, avoiding
	// shared-lock upgrades when concurrent first logins find the same identity.
	if err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"app_id"}),
	}).Create(&models.WechatAccount{AppID: appID, OpenIDHash: openIDHash}).Error; err != nil {
		return nil, mapError(err)
	}
	var m models.WechatAccount
	if err := r.db.WithContext(ctx).
		Where("app_id = ? AND openid_hash = ?", appID, openIDHash).
		Clauses(clause.Locking{Strength: "UPDATE"}).Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	if m.UserID == nil {
		return nil, authkit.ErrNotFound
	}
	return r.GetByID(ctx, *m.UserID)
}

// BindWechat assigns a locked placeholder once; indexes prevent duplicate owners.
func (r *userRepository) BindWechat(ctx context.Context, appID, openIDHash, userID string) error {
	res := r.db.WithContext(ctx).Model(&models.WechatAccount{}).
		Where("app_id = ? AND openid_hash = ? AND user_id IS NULL", appID, openIDHash).
		Update("user_id", userID)
	err := res.Error
	if errors.Is(mapError(err), authkit.ErrConflict) {
		return authkit.ErrWechatBound
	}
	if err != nil {
		return mapError(err)
	}
	if res.RowsAffected != 1 {
		return authkit.ErrWechatBound
	}
	return nil
}

// HasWechat reports whether any WeChat application has an identity for the account.
func (r *userRepository) HasWechat(ctx context.Context, userID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.WechatAccount{}).
		Where("user_id = ?", userID).Count(&count).Error
	return count > 0, mapError(err)
}

// BindEmail assigns an unused email only to an account without an email.
func (r *userRepository) BindEmail(ctx context.Context, userID, email string) error {
	res := r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND email IS NULL", userID).
		Update("email", email)
	err := res.Error
	if errors.Is(mapError(err), authkit.ErrConflict) {
		return authkit.ErrEmailAccountConflict
	}
	if err != nil {
		return mapError(err)
	}
	if res.RowsAffected != 1 {
		return authkit.ErrEmailBound
	}
	return nil
}

// Create inserts an account with a nullable email value.
func (r *userRepository) Create(ctx context.Context, u *authkit.User) error {
	return mapError(r.db.WithContext(ctx).Create(mapper.UserDomainToModel(u)).Error)
}

// GetBySessionToken returns an account only while its matching session is live.
func (r *userRepository) GetBySessionToken(
	ctx context.Context,
	hash string,
	now time.Time,
) (*authkit.User, error) {
	var m models.User
	if err := r.db.WithContext(ctx).Model(&models.User{}).
		Select("auth_users.*").
		Joins("JOIN auth_sessions ON auth_sessions.user_id = auth_users.id").
		Where("auth_sessions.hash = ? AND auth_sessions.expires > ?", hash, now.UTC()).
		Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return mapper.UserModelToDomain(&m), nil
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
		"hash": c.Hash, "registration_ref": c.RegistrationRef,
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
