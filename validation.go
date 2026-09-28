package authkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
)

// NormalizeEmail validates a bare mailbox address and applies the shared lookup normalization.
func NormalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || len(value) > 254 {
		return "", ErrInvalidEmail
	}
	return value, nil
}

// normalizeWechatInput ensures optional email proof is supplied as a complete pair.
func normalizeWechatInput(input WechatLoginInput) (string, error) {
	if (input.Email == "") != (input.EmailCode == "") {
		return "", ErrInvalidInput
	}
	if input.Email == "" {
		return "", nil
	}
	if !validEmailCode(input.EmailCode) {
		return "", ErrInvalidInput
	}
	return NormalizeEmail(input.Email)
}

// validEmailCode permits a bounded wrong proof so failed guesses spend an attempt.
func validEmailCode(code string) bool { return code != "" && len(code) <= 16 }

// validWechatCode applies transport bounds before any external request.
func validWechatCode(code string) bool { return strings.TrimSpace(code) != "" && len(code) <= 512 }

// validWechatIdentity bounds provider identifiers before they reach persistent indexes.
func validWechatIdentity(identity WechatIdentity) bool {
	return strings.TrimSpace(identity.AppID) != "" && len(identity.AppID) <= 64 &&
		strings.TrimSpace(identity.OpenID) != "" && len(identity.OpenID) <= 128
}

// validToken accepts only credentials produced by this module.
func validToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// newID creates a 256-bit account identifier or session credential.
func newID() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

// newCode samples all six-digit codes uniformly, including leading zeroes.
func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// digest hashes credentials before they cross the persistence boundary.
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
