package authkit

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestLegacyBcryptPasswordVerification(t *testing.T) {
	for _, password := range []string{"old123", "existing-password"} {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		original := string(hash)
		for _, prefix := range []string{"$2a$", "$2b$", "$2y$"} {
			encoded := prefix + original[4:]
			if !IsLegacyPasswordHash(encoded) ||
				!PasswordAlgorithmBcrypt.verifyPassword(password, encoded) {
				t.Fatalf("supported legacy digest rejected for %s", prefix)
			}
			if PasswordAlgorithmBcrypt.verifyPassword("incorrect", encoded) {
				t.Fatal("wrong legacy password accepted")
			}
		}
		if PasswordAlgorithmBcrypt.verifyPassword(strings.Repeat("x", 73), original) {
			t.Fatal("overlength bcrypt password accepted")
		}
		if string(hash) != original {
			t.Fatal("verification rewrote the stored digest")
		}
	}
}

func TestLegacyBcryptRejectsMalformedOrUnboundedHashes(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("old123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(hash)
	for _, invalid := range []string{"", encoded[:59], encoded[:6] + "!" + encoded[7:], "$2x$" + encoded[4:], encoded[:4] + "31" + encoded[6:], encoded[:7] + strings.Repeat("!", 53)} {
		if IsLegacyPasswordHash(invalid) ||
			PasswordAlgorithmBcrypt.verifyPassword("old123", invalid) {
			t.Fatal("unsupported legacy digest accepted")
		}
	}
}

func TestLegacyBcryptPasswordByteBoundary(t *testing.T) {
	for _, password := range []string{strings.Repeat("x", 72), strings.Repeat("界", 24)} {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		if !PasswordAlgorithmBcrypt.verifyPassword(password, string(hash)) {
			t.Fatal("72 byte password rejected")
		}
		if PasswordAlgorithmBcrypt.verifyPassword(password+"x", string(hash)) {
			t.Fatal("password longer than 72 bytes accepted")
		}
	}
}
