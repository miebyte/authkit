package authkit

// PasswordAlgorithm 指定服务使用的唯一密码算法。
type PasswordAlgorithm string

const (
	PasswordAlgorithmArgon2id PasswordAlgorithm = "argon2id"
	PasswordAlgorithmBcrypt   PasswordAlgorithm = "bcrypt"
)

// Config 配置密码创建、重设、登录及占位验证的算法。
type Config struct {
	PasswordAlgorithm PasswordAlgorithm
}

func normalizeConfig(configs []Config) (Config, error) {
	if len(configs) > 1 {
		return Config{}, ErrInvalidInput
	}
	config := Config{PasswordAlgorithm: PasswordAlgorithmArgon2id}
	if len(configs) == 1 && configs[0].PasswordAlgorithm != "" {
		config = configs[0]
	}
	if config.PasswordAlgorithm != PasswordAlgorithmArgon2id &&
		config.PasswordAlgorithm != PasswordAlgorithmBcrypt {
		return Config{}, ErrInvalidInput
	}
	return config, nil
}
