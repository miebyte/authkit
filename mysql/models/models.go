// Package models 定义 authkit 的表结构。宿主显式迁移这些模型。
package models

import "time"

// Account 是登录主体。Username 只作展示，凭证存放在绑定表中。
type Account struct {
	ID        string    `gorm:"column:id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	Username  *string   `gorm:"column:username;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"`
	CreatedAt time.Time `gorm:"column:created_at;type:datetime(6)"`
	UpdatedAt time.Time `gorm:"column:updated_at;type:datetime(6)"`
}

// TableName 返回账号表名。
func (Account) TableName() string { return "auth_accounts" }

// Binding 把一条唯一凭证挂到账号上，例如邮箱、手机号或 OpenID。
// 所有者为空时，可在选定账号之前锁定该凭证。
type Binding struct {
	Method       string    `gorm:"column:method;type:varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey;uniqueIndex:account_method,priority:2"`
	Identifier   string    `gorm:"column:identifier;type:varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	AccountID    *string   `gorm:"column:account_id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;uniqueIndex:account_method,priority:1"`
	PasswordHash *string   `gorm:"column:password_hash;type:varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"                                          json:"-"`
	CreatedAt    time.Time `gorm:"column:created_at;type:datetime(6)"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:datetime(6)"`
}

// TableName 返回凭证绑定表名。
func (Binding) TableName() string { return "auth_bindings" }

// Challenge 持久化验证码摘要。
type Challenge struct {
	Email     string    `gorm:"column:email;type:varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	Hash      string    `gorm:"column:hash;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null"`
	Expires   time.Time `gorm:"column:expires;type:datetime(6);not null"`
	Sent      time.Time `gorm:"column:sent;type:datetime(6);not null"`
	Attempts  int       `gorm:"column:attempts;type:int;not null"`
	Ready     bool      `gorm:"column:ready;type:tinyint(1);not null"`
	CreatedAt time.Time `gorm:"column:created_at;type:datetime(6)"`
	UpdatedAt time.Time `gorm:"column:updated_at;type:datetime(6)"`
}

// TableName 返回验证挑战表名。
func (Challenge) TableName() string { return "auth_challenges" }

// Rate 为一条哈希标识持久化固定的小时窗口。
type Rate struct {
	ID        string    `gorm:"column:id;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	Starts    time.Time `gorm:"column:starts;type:datetime(6);not null"`
	Hits      int       `gorm:"column:hits;type:int;not null"`
	CreatedAt time.Time `gorm:"column:created_at;type:datetime(6)"`
	UpdatedAt time.Time `gorm:"column:updated_at;type:datetime(6)"`
}

// TableName 返回发送频率表名。
func (Rate) TableName() string { return "auth_rates" }

// Session 持久化应用会话摘要及登录方式，从不保存明文凭证。
type Session struct {
	ParentHash string    `gorm:"column:parent_hash;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;default:''"`
	Hash       string    `gorm:"column:hash;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	AccountID  string    `gorm:"column:account_id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;index:account_id"`
	Method     string    `gorm:"column:method;type:varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;default:''"`
	Expires    time.Time `gorm:"column:expires;type:datetime(6);not null;index:expires"`
	CreatedAt  time.Time `gorm:"column:created_at;type:datetime(6)"`
	UpdatedAt  time.Time `gorm:"column:updated_at;type:datetime(6)"`
}

// TableName 返回应用会话表名。
func (Session) TableName() string { return "auth_sessions" }

// Blacklist 串行化凭证禁用与登录检查，解除后保留占位行。
type Blacklist struct {
	ID         string    `gorm:"column:id;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	Method     string    `gorm:"column:method;type:varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;uniqueIndex:blacklist_credential,priority:1"`
	Identifier string    `gorm:"column:identifier;type:varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;uniqueIndex:blacklist_credential,priority:2"`
	Blocked    bool      `gorm:"column:blocked;type:tinyint(1);not null"`
	CreatedAt  time.Time `gorm:"column:created_at;type:datetime(6);not null"`
	UpdatedAt  time.Time `gorm:"column:updated_at;type:datetime(6)"`
}

// TableName 返回凭证黑名单表名。
func (Blacklist) TableName() string { return "auth_blacklist" }

// AllModels 返回新的模型值，供宿主显式调用 AutoMigrate。
func AllModels() []any {
	return []any{
		&Account{},
		&Binding{},
		&Challenge{},
		&Rate{},
		&Session{},
		&Blacklist{},
	}
}
