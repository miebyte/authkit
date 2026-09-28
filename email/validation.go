package email

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
)

// NormalizeEmail 仅接受纯邮箱地址，去除首尾空白并转小写后供发码和身份查找共用。
func NormalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || len(value) > 254 {
		return "", ErrInvalidEmail
	}
	return value, nil
}

// validCode 只排除空码与超长输入；其他错误验证码仍进入校验流程并计入尝试次数。
func validCode(code string) bool { return code != "" && len(code) <= 16 }

// newCode 用安全随机数等概率生成六位数字验证码，保留前导零。
func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// digest 对待比较或持久化的数据取 SHA-256 摘要。
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
