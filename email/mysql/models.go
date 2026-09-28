// Package emailmysql 将邮箱验证码仓储接入宿主管理的 MySQL 连接。
package emailmysql

import "time"

// Challenge 保存规范化邮箱对应的当前验证码及投递状态。
// Hash 保存摘要，Ready 区分待投递与可校验状态，Attempts 记录错误尝试。
type Challenge struct {
	// Email 是规范化邮箱，作为每个邮箱唯一的验证码主键。
	Email string `gorm:"column:email;type:varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	// Hash 保存邮箱与验证码的摘要，不保存邮件中的明文验证码。
	Hash string `gorm:"column:hash;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null"`
	// RegistrationRef 是宿主提供的非秘密注册引用。
	RegistrationRef string `gorm:"column:registration_ref;type:text;not null"`
	// Expires 是验证码失效时间，校验只接受严格早于该时间的请求。
	Expires time.Time `gorm:"column:expires;type:datetime(6);not null"`
	// Sent 用于计算重发间隔，也用于识别被较新发码替换的记录。
	Sent time.Time `gorm:"column:sent;type:datetime(6);not null"`
	// Attempts 是该验证码已发生的错误尝试次数。
	Attempts int `gorm:"column:attempts;type:int;not null"`
	// Ready 仅在投递成功后置为 true，成功登录或绑定后置为 false。
	Ready bool `gorm:"column:ready;type:tinyint(1);not null"`
}

// TableName 返回邮箱验证码表名。
func (Challenge) TableName() string { return "auth_challenges" }

// Rate 按邮箱或 IP 的摘要键保存从首次请求开始的固定一小时限流窗口。
type Rate struct {
	// ID 是邮箱或 IP 标识的摘要，避免在限流表中保存原值。
	ID string `gorm:"column:id;type:char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;primaryKey"`
	// Starts 是本轮固定一小时窗口的起点。
	Starts time.Time `gorm:"column:starts;type:datetime(6);not null"`
	// Hits 是窗口内已接受的发码次数。
	Hits int `gorm:"column:hits;type:int;not null"`
}

// TableName 返回邮箱发码限流表名。
func (Rate) TableName() string { return "auth_rates" }

// Models 返回邮箱插件专用的验证码和限流表模型，由宿主按需迁移。
func Models() []any { return []any{&Challenge{}, &Rate{}} }
