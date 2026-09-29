// Package mapper 在 authkit 值与 MySQL 持久化模型之间转换。
package mapper

import (
	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
)

// AccountToDomain 把已存储的账号和可选邮箱映射为公开账号。
func AccountToDomain(m *models.Account, email string) *authkit.Account {
	if m == nil {
		return nil
	}
	account := &authkit.Account{ID: m.ID, Email: email}
	if m.Username != nil {
		account.Username = *m.Username
	}
	return account
}

// ChallengeModelToDomain 保留全部验证码状态，包括 false 和零值。
func ChallengeModelToDomain(m *models.Challenge) *authkit.Challenge {
	if m == nil {
		return nil
	}
	return &authkit.Challenge{
		Email: m.Email, Hash: m.Hash,
		Expires: m.Expires, Sent: m.Sent, Attempts: m.Attempts, Ready: m.Ready,
	}
}

// SessionDomainToModel 转换会话摘要和过期时间。
func SessionDomainToModel(s *authkit.Session) *models.Session {
	if s == nil {
		return nil
	}
	return &models.Session{Hash: s.Hash, AccountID: s.AccountID, Expires: s.Expires}
}
