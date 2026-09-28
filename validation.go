package authkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// validVerifiedIdentity 检查插件传入的身份键与验证方式是否符合持久化字段限制。
// 身份键和 Method 分别校验；Scope 可以为空，Namespace、Subject 和 Method 必须非空。
// 此检查仅验证结构，不验证用户是否真正持有该身份，凭证校验仍由可信插件负责。
func validVerifiedIdentity(verified VerifiedIdentity) bool {
	key := verified.Identity
	return key.Namespace != "" && validIdentifier(key.Namespace, 64) &&
		validIdentifier(key.Scope, 255) && key.Subject != "" && validIdentifier(key.Subject, 254) &&
		verified.Method != "" && validIdentifier(verified.Method, 64)
}

// validIdentifier 按字节限制标识长度，并拒绝非法 UTF-8 和首尾空白。
// 它不会自动截断、去空白或转换大小写，避免核心悄悄改变插件确定的身份键。
func validIdentifier(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value
}

// validToken 检查 Token 是否具有本模块生成凭证的结构：64 个十六进制字符。
// 格式正确只代表可以继续查询会话，不能据此认定凭证有效。
func validToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// newID 使用密码学安全随机源生成 256 位随机值，并编码为 64 个十六进制字符。
// 账号 ID 和会话 Token 共用此生成方式；随机源失败时直接返回错误，不能降级为可预测值。
func newID() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

// digest 将凭证转换为固定长度的 SHA-256 十六进制摘要，用于持久化查询和撤销。
// 存储层只接收摘要，明文 Token 由签发结果交给客户端保存。
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
