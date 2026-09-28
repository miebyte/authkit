// Package models defines the authkit schema. Hosts explicitly migrate these models.
package models

import "time"

// Account is the login subject. Credentials live in bindings, not on this row.
type Account struct {
	ID       string  `gorm:"column:id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	Username *string `gorm:"column:username;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;uniqueIndex:username"`
}

// TableName returns the account table.
func (Account) TableName() string { return "auth_accounts" }

// Binding attaches one unique credential, such as an email, phone or OpenID, to an account.
// A null owner locks the credential before an account has been selected.
type Binding struct {
	Method     string  `gorm:"column:method;type:varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey;uniqueIndex:account_method,priority:2"`
	Identifier string  `gorm:"column:identifier;type:varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	AccountID  *string `gorm:"column:account_id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;uniqueIndex:account_method,priority:1"`
}

// TableName returns the credential binding table.
func (Binding) TableName() string { return "auth_bindings" }

// Challenge persists code digests.
type Challenge struct {
	Email    string    `gorm:"column:email;type:varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	Hash     string    `gorm:"column:hash;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null"`
	Expires  time.Time `gorm:"column:expires;type:datetime(6);not null"`
	Sent     time.Time `gorm:"column:sent;type:datetime(6);not null"`
	Attempts int       `gorm:"column:attempts;type:int;not null"`
	Ready    bool      `gorm:"column:ready;type:tinyint(1);not null"`
}

// TableName returns the verification challenge table.
func (Challenge) TableName() string { return "auth_challenges" }

// Rate persists a fixed hourly window for one hashed identifier.
type Rate struct {
	ID     string    `gorm:"column:id;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	Starts time.Time `gorm:"column:starts;type:datetime(6);not null"`
	Hits   int       `gorm:"column:hits;type:int;not null"`
}

// TableName returns the send-rate table.
func (Rate) TableName() string { return "auth_rates" }

// Session persists application session digests, never plaintext credentials.
type Session struct {
	Hash      string    `gorm:"column:hash;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	AccountID string    `gorm:"column:account_id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;index:account_id"`
	Expires   time.Time `gorm:"column:expires;type:datetime(6);not null;index:expires"`
}

// TableName returns the application session table.
func (Session) TableName() string { return "auth_sessions" }

// AllModels returns fresh model values for an explicit host AutoMigrate call.
func AllModels() []any {
	return []any{&Account{}, &Binding{}, &Challenge{}, &Rate{}, &Session{}}
}
