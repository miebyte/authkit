// Package mapper 在 authkit 领域类型与 MySQL 持久化模型之间转换数据。
package mapper

import (
	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
)

// UserModelToDomain 将账号模型转换为只包含 ID 的领域账号，避免混入插件身份字段。
func UserModelToDomain(m *models.User) *authkit.User {
	if m == nil {
		return nil
	}
	return &authkit.User{ID: m.ID}
}

// UserDomainToModel 将领域账号转换为核心账号模型；身份另存于身份表。
func UserDomainToModel(u *authkit.User) *models.User {
	if u == nil {
		return nil
	}
	return &models.User{ID: u.ID}
}

// IdentityModelToDomain 将数据库可空的 UserID 转换为领域层的空字符串占位状态。
// 非空 UserID 则表示身份已归属账号，身份键的字节值保持不变。
func IdentityModelToDomain(m *models.Identity) *authkit.Identity {
	if m == nil {
		return nil
	}
	identity := &authkit.Identity{
		Key: authkit.IdentityKey{
			Namespace: m.Namespace,
			Scope:     m.Scope,
			Subject:   m.Subject,
		},
	}
	if m.UserID != nil {
		identity.UserID = *m.UserID
	}
	return identity
}

// SessionDomainToModel 保留会话摘要、账号 ID 和到期时间，不接触明文 Token。
func SessionDomainToModel(s *authkit.Session) *models.Session {
	if s == nil {
		return nil
	}
	return &models.Session{Hash: s.Hash, UserID: s.UserID, Expires: s.Expires}
}

// SessionModelToDomain 将持久化会话还原为领域会话，供认证和轮换时检查。
func SessionModelToDomain(m *models.Session) *authkit.Session {
	if m == nil {
		return nil
	}
	return &authkit.Session{Hash: m.Hash, UserID: m.UserID, Expires: m.Expires}
}
