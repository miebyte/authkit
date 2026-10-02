package authkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"
)

// NormalizeEmail 校验裸邮箱地址，并做统一的查询规范化。
func NormalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || len(value) > 254 {
		return "", ErrInvalidEmail
	}
	return value, nil
}

// validDisplayName 允许空展示名称，限制字符数并拒绝控制字符。
func validDisplayName(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 64 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// validCode 允许有长度上限的错误证明，使失败猜测消耗一次尝试。
func validCode(code string) bool { return code != "" && len(code) <= 16 }

// validWechatCode 在发起外部请求前限制传输长度。
func validWechatCode(code string) bool { return strings.TrimSpace(code) != "" && len(code) <= 512 }

// validWechatIdentity 在写入持久化索引前限制服务商标识的长度。
func validWechatIdentity(identity WechatIdentity) bool {
	return strings.TrimSpace(identity.AppID) != "" && len(identity.AppID) <= 64 &&
		strings.TrimSpace(identity.OpenID) != "" && len(identity.OpenID) <= 128
}

// validToken 只接受本模块生成的凭证。
func validToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// newID 生成 256 位的账号标识或会话凭证。
func newID() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

// newCode 均匀抽取全部六位数字验证码，包含前导零。
func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// digest 在凭证越过持久化边界前计算其哈希。
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
