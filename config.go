package authkit

import "time"

// PasswordAlgorithm 指定服务使用的唯一密码算法。
type PasswordAlgorithm string

const (
	PasswordAlgorithmArgon2id PasswordAlgorithm = "argon2id"
	PasswordAlgorithmBcrypt   PasswordAlgorithm = "bcrypt"
)

// Config 配置密码算法和新签发会话的有效时长。
type Config struct {
	PasswordAlgorithm PasswordAlgorithm
	// SessionTTL 指定会话有效时长，零值使用默认 30 天，负值无效。
	SessionTTL time.Duration
}

func normalizeConfig(configs []Config) (Config, error) {
	if len(configs) > 1 {
		return Config{}, ErrInvalidInput
	}
	config := Config{}
	if len(configs) == 1 {
		config = configs[0]
	}
	if config.PasswordAlgorithm == "" {
		config.PasswordAlgorithm = PasswordAlgorithmArgon2id
	}
	if config.SessionTTL == 0 {
		config.SessionTTL = SessionTTL
	}
	if (config.PasswordAlgorithm != PasswordAlgorithmArgon2id &&
		config.PasswordAlgorithm != PasswordAlgorithmBcrypt) || config.SessionTTL < 0 {
		return Config{}, ErrInvalidInput
	}
	return config, nil
}
