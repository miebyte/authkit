package authkit

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	passwordMemory = 19 * 1024
	passwordTime   = 2
	passwordPrefix = "$argon2id$v=19$m=19456,t=2,p=1$"
	// dummyPasswordHash 让不存在或未设密的账号执行同等参数的摘要验证。
	dummyPasswordHash = passwordPrefix + "AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	// 固定 cost 10 占位摘要，不在请求处理中生成 bcrypt。
	dummyBcryptPasswordHash = "$2a$10$hNpyXoDIOhsRTbhxav6H8e1LEnjTLgOqtnF8BF0m57eoqqm0g7uJe"
)

// NormalizeUsername 校验密码登录标识；邮箱统一转为小写，普通用户名保留大小写，不用于账号展示名称。
func NormalizeUsername(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "@") {
		return NormalizeEmail(value)
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 3 ||
		utf8.RuneCountInString(value) > 64 {
		return "", ErrInvalidInput
	}
	for _, character := range value {
		if character == '@' || unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", ErrInvalidInput
		}
	}
	return value, nil
}

// validPassword 限制密码字符数，不裁剪、规范化或截断密码。
func validPassword(password string, minimum int) bool {
	if len(password) > 128*utf8.UTFMax || !utf8.ValidString(password) {
		return false
	}
	length := utf8.RuneCountInString(password)
	return length >= minimum && length <= 128
}

// hashPassword 为每份密码生成独立随机盐，并保存固定参数的 Argon2id 摘要。
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, passwordTime, passwordMemory, 1, 32)
	return passwordPrefix + base64.RawStdEncoding.EncodeToString(
		salt,
	) + "$" + base64.RawStdEncoding.EncodeToString(
		hash,
	), nil
}

// IsLegacyPasswordHash 判断可安全导入的历史 bcrypt 摘要，不需要密码明文。
func IsLegacyPasswordHash(encoded string) bool {
	if len(encoded) != 60 || encoded[4] < '0' || encoded[4] > '9' || encoded[5] < '0' ||
		encoded[5] > '9' ||
		encoded[6] != '$' ||
		!(strings.HasPrefix(encoded, "$2a$") || strings.HasPrefix(encoded, "$2b$") || strings.HasPrefix(encoded, "$2y$")) {
		return false
	}
	cost, err := bcrypt.Cost([]byte(encoded))
	if err != nil || cost < bcrypt.MinCost || cost > 14 {
		return false
	}
	for _, character := range encoded[7:] {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '/') {
			return false
		}
	}
	return true
}

// verifyPassword 只验证默认 Argon2id 的固定参数。
func verifyPassword(password, encoded string) bool {
	if len(encoded) != len(dummyPasswordHash) {
		verifyPassword(password, dummyPasswordHash)
		return false
	}
	parts := strings.Split(strings.TrimPrefix(encoded, passwordPrefix), "$")
	if !strings.HasPrefix(encoded, passwordPrefix) || len(parts) != 2 || len(parts[0]) != 22 ||
		len(parts[1]) != 43 {
		verifyPassword(password, dummyPasswordHash)
		return false
	}
	salt, saltErr := base64.RawStdEncoding.DecodeString(parts[0])
	want, hashErr := base64.RawStdEncoding.DecodeString(parts[1])
	if saltErr != nil || hashErr != nil || len(salt) != 16 || len(want) != 32 {
		verifyPassword(password, dummyPasswordHash)
		return false
	}
	got := argon2.IDKey([]byte(password), salt, passwordTime, passwordMemory, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// passwordRejection 提交可预期的限流和黑名单拒绝，其他存储错误仍回滚。
func passwordRejection(err error) (Outcome, error) {
	if errors.Is(err, ErrTooManyRequests) || errors.Is(err, ErrBlacklisted) {
		return Outcome{Rejected: err}, nil
	}
	return Outcome{}, err
}

// rejectPasswordCredentials 为缺少有效密码凭据的请求执行占位验证。
func rejectPasswordCredentials(password string, algorithm PasswordAlgorithm) (Outcome, error) {
	algorithm.verifyPassword(password, algorithm.dummyPasswordHash())
	return Outcome{Rejected: ErrInvalidCredentials}, nil
}

// validPassword 按所选算法额外限制 bcrypt 的字节长度。
func (algorithm PasswordAlgorithm) validPassword(password string, minimum int) bool {
	return validPassword(password, minimum) &&
		(algorithm != PasswordAlgorithmBcrypt || len(password) <= 72)
}

func (algorithm PasswordAlgorithm) hashPassword(password string) (string, error) {
	if algorithm == PasswordAlgorithmBcrypt {
		if len(password) > 72 {
			return "", ErrInvalidInput
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		return string(hash), err
	}
	return hashPassword(password)
}

func (algorithm PasswordAlgorithm) verifyPassword(password, encoded string) bool {
	if algorithm == PasswordAlgorithmBcrypt {
		if !IsLegacyPasswordHash(encoded) || len(password) > 72 {
			bcrypt.CompareHashAndPassword([]byte(dummyBcryptPasswordHash), []byte(password))
			return false
		}
		return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password)) == nil
	}
	return verifyPassword(password, encoded)
}

func (algorithm PasswordAlgorithm) dummyPasswordHash() string {
	if algorithm == PasswordAlgorithmBcrypt {
		return dummyBcryptPasswordHash
	}
	return dummyPasswordHash
}
