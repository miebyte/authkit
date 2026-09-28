// Package mapper translates between authkit values and MySQL persistence models.
package mapper

import (
	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
)

// UserModelToDomain maps nullable email to the public empty-email representation.
func UserModelToDomain(m *models.User) *authkit.User {
	if m == nil {
		return nil
	}
	u := &authkit.User{ID: m.ID}
	if m.Email != nil {
		u.Email = *m.Email
	}
	return u
}

// UserDomainToModel maps an absent email to SQL NULL for unique indexing.
func UserDomainToModel(u *authkit.User) *models.User {
	if u == nil {
		return nil
	}
	m := &models.User{ID: u.ID}
	if u.Email != "" {
		email := u.Email
		m.Email = &email
	}
	return m
}

// ChallengeModelToDomain preserves every code state, including false and zero.
func ChallengeModelToDomain(m *models.Challenge) *authkit.Challenge {
	if m == nil {
		return nil
	}
	return &authkit.Challenge{
		Email: m.Email, Hash: m.Hash, RegistrationRef: m.RegistrationRef,
		Expires: m.Expires, Sent: m.Sent, Attempts: m.Attempts, Ready: m.Ready,
	}
}

// SessionDomainToModel translates the session digest and expiration.
func SessionDomainToModel(s *authkit.Session) *models.Session {
	if s == nil {
		return nil
	}
	return &models.Session{Hash: s.Hash, UserID: s.UserID, Expires: s.Expires}
}
