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
)

const (
	passwordMemory = 19 * 1024
	passwordTime   = 2
	passwordPrefix = "$argon2id$v=19$m=19456,t=2,p=1$"
	// dummyPasswordHash 让不存在或未设密的账号执行同等参数的摘要验证。
	dummyPasswordHash = passwordPrefix + "AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// NormalizeUsername 校验用户名并去除首尾空白，保留大小写。
func NormalizeUsername(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 3 || utf8.RuneCountInString(value) > 64 {
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
	return passwordPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash), nil
}

// verifyPassword 只接受本版本生成的参数，避免损坏的摘要触发无界内存分配。
func verifyPassword(password, encoded string) bool {
	if len(encoded) != len(dummyPasswordHash) {
		verifyPassword(password, dummyPasswordHash)
		return false
	}
	parts := strings.Split(strings.TrimPrefix(encoded, passwordPrefix), "$")
	if !strings.HasPrefix(encoded, passwordPrefix) || len(parts) != 2 || len(parts[0]) != 22 || len(parts[1]) != 43 {
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
func rejectPasswordCredentials(password string) (Outcome, error) {
	verifyPassword(password, dummyPasswordHash)
	return Outcome{Rejected: ErrInvalidCredentials}, nil
}
