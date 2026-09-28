package emailmysql

import (
	"context"
	"time"

	"github.com/miebyte/authkit/email"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type challengeRepository struct{ db *gorm.DB }

// Get 首次发码时插入未激活占位行，并借助冲突更新立即取得独占锁。
// 并发发码因此按邮箱串行化，后续再读取完整状态以检查重发间隔。
func (r *challengeRepository) Get(ctx context.Context, mailbox string) (*email.Challenge, error) {
	epoch := time.Unix(0, 0).UTC()
	if err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"email"}),
	}).Create(&Challenge{Email: mailbox, Expires: epoch, Sent: epoch}).Error; err != nil {
		return nil, mapError(err)
	}
	return r.Find(ctx, mailbox)
}

// Find 锁定已有验证码行；未知邮箱直接返回记录不存在，不分配占位行。
// 验证和激活阶段使用它，避免未发码邮箱的猜测请求制造数据库记录。
func (r *challengeRepository) Find(ctx context.Context, mailbox string) (*email.Challenge, error) {
	var m Challenge
	if err := r.db.WithContext(ctx).
		Where("email = ?", mailbox).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Take(&m).Error; err != nil {
		return nil, mapError(err)
	}
	return &email.Challenge{
		Email: m.Email, Hash: m.Hash, RegistrationRef: m.RegistrationRef,
		Expires: m.Expires, Sent: m.Sent, Attempts: m.Attempts, Ready: m.Ready,
	}, nil
}

// Save 显式写入零值与 false，确保验证码消费时 Ready=false 真正落库。
func (r *challengeRepository) Save(ctx context.Context, c *email.Challenge) error {
	return mapError(r.db.WithContext(ctx).Model(&Challenge{}).
		Where("email = ?", c.Email).Updates(map[string]any{
		"hash": c.Hash, "registration_ref": c.RegistrationRef,
		"expires": c.Expires.UTC(), "sent": c.Sent.UTC(),
		"attempts": c.Attempts, "ready": c.Ready,
	}).Error)
}

type rateRepository struct{ db *gorm.DB }

// Hit 用摘要键的占位插入和行锁串行化计数，从首次请求起维护固定一小时窗口。
// 同一事务内达到上限时返回错误，由调用方回滚本次发码的其他写入。
func (r *rateRepository) Hit(ctx context.Context, id string, now time.Time, limit int) error {
	now = now.UTC()
	if err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"id"}),
	}).Create(&Rate{ID: id, Starts: now}).Error; err != nil {
		return mapError(err)
	}
	var m Rate
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
		return email.ErrTooManyRequests
	}
	return mapError(r.db.WithContext(ctx).Model(&Rate{}).
		Where("id = ?", id).
		Updates(map[string]any{"starts": m.Starts, "hits": m.Hits + 1}).Error)
}
