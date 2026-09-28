// Package mapper translates between authkit values and MySQL persistence models.
package mapper

import (
	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
)

// AccountToDomain maps a stored account and optional mailbox onto the public account.
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

// ChallengeModelToDomain preserves every code state, including false and zero.
func ChallengeModelToDomain(m *models.Challenge) *authkit.Challenge {
	if m == nil {
		return nil
	}
	return &authkit.Challenge{
		Email: m.Email, Hash: m.Hash,
		Expires: m.Expires, Sent: m.Sent, Attempts: m.Attempts, Ready: m.Ready,
	}
}

// SessionDomainToModel translates the session digest and expiration.
func SessionDomainToModel(s *authkit.Session) *models.Session {
	if s == nil {
		return nil
	}
	return &models.Session{Hash: s.Hash, AccountID: s.AccountID, Expires: s.Expires}
}
