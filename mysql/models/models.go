// Package models 定义 authkit 核心数据表结构；宿主应用需显式迁移这些模型。
package models

import "time"

// User 保存与登录方式无关的账号；邮箱、微信等身份归属保存在 Identity 中。
type User struct {
	// ID 是跨登录方式共享的账号标识，不随身份绑定或会话轮换而改变。
	ID string `gorm:"column:id;type:varbinary(64);primaryKey"`
}

// TableName 返回账号表名。
func (User) TableName() string { return "auth_users" }

// Identity 将命名空间、范围和主体组成的身份键唯一映射到账号。
// 复合主键防止同一身份归属多个账号；identity_owner 唯一索引防止一个账号
// 在同一命名空间和范围内绑定不同主体。UserID 可为 NULL，供首次登录先插入
// 占位行并加锁；MySQL 唯一索引允许多个 NULL，占位行不会互相占用账号配额。
// 身份键使用 VARBINARY 按字节比较，不受数据库默认大小写或重音排序规则影响。
type Identity struct {
	// Namespace 区分邮箱、微信等身份类别；不同验证方法可以共享同一类别。
	Namespace string `gorm:"column:namespace;type:varbinary(64);primaryKey;uniqueIndex:identity_owner,priority:1"`
	// Scope 划分应用等身份范围；无范围时使用非 NULL 的空字符串。
	Scope string `gorm:"column:scope;type:varbinary(255);primaryKey;uniqueIndex:identity_owner,priority:2"`
	// Subject 是插件规范化后的主体，例如邮箱地址或 OpenID 摘要。
	Subject string `gorm:"column:subject;type:varbinary(254);primaryKey"`
	// UserID 为空表示身份尚未归属账号；绑定后不得重新指派。
	UserID *string `gorm:"column:user_id;type:varbinary(64);uniqueIndex:identity_owner,priority:3;index:user_id"`
}

// TableName 返回身份归属表名。
func (Identity) TableName() string { return "auth_identities" }

// Session 保存应用会话摘要和到期时间，不保存明文 Token。
type Session struct {
	// Hash 是明文 Token 的摘要，也是会话主键。
	Hash string `gorm:"column:hash;type:varbinary(64);primaryKey"`
	// UserID 指向会话所属账号，不绑定某一种登录方式。
	UserID string `gorm:"column:user_id;type:varbinary(64);not null;index:user_id"`
	// Expires 使用微秒精度；到期时刻起会话不再有效。
	Expires time.Time `gorm:"column:expires;type:datetime(6);not null;index:expires"`
}

// TableName 返回应用会话表名。
func (Session) TableName() string { return "auth_sessions" }

// AllModels 返回供宿主显式迁移的三个核心模型实例。
// 各登录插件单独提供所需表结构，避免仅启用微信时仍创建邮箱表。
func AllModels() []any {
	return []any{&User{}, &Identity{}, &Session{}}
}
