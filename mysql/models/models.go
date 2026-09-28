// Package models defines the authkit schema. Hosts explicitly migrate these models.
package models

import "time"

// User persists an account; NULL permits multiple accounts without email addresses.
type User struct {
	ID    string  `gorm:"column:id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	Email *string `gorm:"column:email;type:varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;uniqueIndex:email"`
}

// TableName returns the account table.
func (User) TableName() string { return "auth_users" }

// WechatAccount serializes registration of each application-scoped identity.
// Its nullable owner locks the identity before an account has been selected.
type WechatAccount struct {
	AppID      string  `gorm:"column:app_id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey;uniqueIndex:app_user,priority:1"`
	OpenIDHash string  `gorm:"column:openid_hash;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	UserID     *string `gorm:"column:user_id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;uniqueIndex:app_user,priority:2;index:user_id"`
}

// TableName returns the WeChat identity table.
func (WechatAccount) TableName() string { return "auth_wechat_accounts" }

// Challenge persists code digests and non-secret host registration references.
type Challenge struct {
	Email           string    `gorm:"column:email;type:varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	Hash            string    `gorm:"column:hash;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null"`
	RegistrationRef string    `gorm:"column:registration_ref;type:text;not null"`
	Expires         time.Time `gorm:"column:expires;type:datetime(6);not null"`
	Sent            time.Time `gorm:"column:sent;type:datetime(6);not null"`
	Attempts        int       `gorm:"column:attempts;type:int;not null"`
	Ready           bool      `gorm:"column:ready;type:tinyint(1);not null"`
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
	Hash    string    `gorm:"column:hash;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	UserID  string    `gorm:"column:user_id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;index:user_id"`
	Expires time.Time `gorm:"column:expires;type:datetime(6);not null;index:expires"`
}

// TableName returns the application session table.
func (Session) TableName() string { return "auth_sessions" }

// AllModels returns fresh model values for an explicit host AutoMigrate call.
func AllModels() []any {
	return []any{&User{}, &WechatAccount{}, &Challenge{}, &Rate{}, &Session{}}
}
