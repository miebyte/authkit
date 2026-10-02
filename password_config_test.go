package authkit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func configuredPasswordFixture(t *testing.T, configs ...Config) *blacklistFixture {
	t.Helper()
	f := newBlacklistFixture(t)
	service, err := NewService(f.store, f.mail, f.wechat, f.policy, configs...)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return f.now }
	f.service = service
	return f
}

func TestPasswordAlgorithmConfiguration(t *testing.T) {
	for _, test := range []struct {
		name    string
		configs []Config
		want    PasswordAlgorithm
	}{
		{name: "默认", want: PasswordAlgorithmArgon2id},
		{name: "空配置", configs: []Config{{}}, want: PasswordAlgorithmArgon2id},
		{name: "Argon2id", configs: []Config{{PasswordAlgorithm: PasswordAlgorithmArgon2id}}, want: PasswordAlgorithmArgon2id},
		{name: "bcrypt", configs: []Config{{PasswordAlgorithm: PasswordAlgorithmBcrypt}}, want: PasswordAlgorithmBcrypt},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := configuredPasswordFixture(t, test.configs...)
			if f.service.passwordAlgorithm != test.want || f.service.InTransaction(f.store, f.policy).passwordAlgorithm != test.want {
				t.Fatal("服务和宿主事务没有使用配置的密码算法")
			}
		})
	}
	f := newBlacklistFixture(t)
	for _, configs := range [][]Config{
		{{PasswordAlgorithm: "unknown"}},
		{{PasswordAlgorithm: "BCRYPT"}},
		{{}, {}},
		{{PasswordAlgorithm: PasswordAlgorithmBcrypt}, {PasswordAlgorithm: PasswordAlgorithmBcrypt}},
	} {
		if service, err := NewService(f.store, nil, nil, nil, configs...); !errors.Is(err, ErrInvalidInput) || service != nil {
			t.Fatal("未知算法或多个配置不应创建服务")
		}
	}
}

func TestSelectedPasswordAlgorithmCreateLoginAndReset(t *testing.T) {
	for _, algorithm := range []PasswordAlgorithm{PasswordAlgorithmArgon2id, PasswordAlgorithmBcrypt} {
		t.Run(string(algorithm), func(t *testing.T) {
			f := configuredPasswordFixture(t, Config{PasswordAlgorithm: algorithm})
			ctx := context.Background()
			account, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{
				Identifier: "alice", Username: "教师", Password: "original-password",
			})
			if err != nil {
				t.Fatal(err)
			}
			original := f.store.passwords[account.ID]
			assertSelectedPasswordHash(t, algorithm, original)
			outcome, err := f.service.InTransaction(f.store, f.policy).LoginPassword(ctx, PasswordLoginInput{
				Identifier: "alice", Password: "original-password",
			})
			if err != nil || outcome.Rejected != nil || outcome.Login == nil || outcome.Login.Account.ID != account.ID {
				t.Fatal("宿主事务没有使用所选算法登录")
			}
			if f.store.passwords[account.ID] != original {
				t.Fatal("登录不应改写密码摘要")
			}
			if err := f.service.SetPassword(ctx, SetPasswordInput{AccountID: account.ID, Password: "replacement-password"}); err != nil {
				t.Fatal(err)
			}
			assertSelectedPasswordHash(t, algorithm, f.store.passwords[account.ID])
			if f.store.passwords[account.ID] == original {
				t.Fatal("重设密码没有生成新摘要")
			}
			if _, err := f.service.Authenticate(ctx, outcome.Login.Token); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("重设密码未撤销旧会话")
			}
			if _, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: "alice", Password: "original-password"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatal("重设后仍接受原密码")
			}
			if _, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: "alice", Password: "replacement-password"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSelectedPasswordAlgorithmRejectsOtherAlgorithm(t *testing.T) {
	for _, algorithm := range []PasswordAlgorithm{PasswordAlgorithmArgon2id, PasswordAlgorithmBcrypt} {
		t.Run(string(algorithm), func(t *testing.T) {
			f := configuredPasswordFixture(t, Config{PasswordAlgorithm: algorithm})
			ctx := context.Background()
			account, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{Identifier: "alice", Password: "original-password"})
			if err != nil {
				t.Fatal(err)
			}
			original := f.store.passwords[account.ID]
			other := PasswordAlgorithmBcrypt
			if algorithm == PasswordAlgorithmBcrypt {
				other = PasswordAlgorithmArgon2id
			}
			otherService, err := NewService(f.store, nil, nil, f.policy, Config{PasswordAlgorithm: other})
			if err != nil {
				t.Fatal(err)
			}
			otherService.now = f.service.now
			if _, err := otherService.LoginPassword(ctx, PasswordLoginInput{Identifier: "alice", Password: "original-password"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatal("不应自动回退验证另一种算法")
			}
			if len(f.store.sessions) != 0 || f.store.passwords[account.ID] != original || f.store.rates[digest("password-account:"+account.ID)].Hits != 1 {
				t.Fatal("算法不匹配应保留限流计数，且不得签发会话或改摘要")
			}
			if err := f.service.AddBlacklist(ctx, Credential{Method: MethodPassword, Identifier: "alice"}); err != nil {
				t.Fatal(err)
			}
			if _, err := otherService.LoginPassword(ctx, PasswordLoginInput{Identifier: "alice", Password: "original-password"}); !errors.Is(err, ErrBlacklisted) {
				t.Fatal("算法选择不能绕过账号黑名单")
			}
		})
	}
}

func TestBcryptInputAndLegacyPasswordPolicy(t *testing.T) {
	f := configuredPasswordFixture(t, Config{PasswordAlgorithm: PasswordAlgorithmBcrypt})
	ctx := context.Background()
	for _, password := range []string{"old123", strings.Repeat("x", 73), strings.Repeat("界", 25)} {
		if _, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{Identifier: "invalid", Password: password}); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("bcrypt 新账号应拒绝短密码和超过 72 字节的密码")
		}
	}
	account, err := f.service.CreatePasswordAccount(ctx, CreatePasswordAccountInput{Identifier: "legacy", Password: strings.Repeat("界", 24)})
	if err != nil {
		t.Fatal("bcrypt 应接受 72 字节的 Unicode 密码")
	}
	if err := f.service.SetPassword(ctx, SetPasswordInput{AccountID: account.ID, Password: "old123"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("bcrypt 重设密码仍应要求至少 8 字符")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("old123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	f.store.passwords[account.ID] = string(hash)
	if _, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: "legacy", Password: "old123"}); err != nil {
		t.Fatal("bcrypt 应直接验证已有 6 字符密码")
	}
	if f.store.passwords[account.ID] != string(hash) {
		t.Fatal("历史密码登录改写了摘要")
	}
	if verifyPassword("old123", string(hash)) {
		t.Fatal("默认 Argon2id helper 不应接受 bcrypt")
	}
}

func TestSelectedPasswordDummyAndRejection(t *testing.T) {
	for _, algorithm := range []PasswordAlgorithm{PasswordAlgorithmArgon2id, PasswordAlgorithmBcrypt} {
		t.Run(string(algorithm), func(t *testing.T) {
			assertSelectedPasswordHash(t, algorithm, algorithm.dummyPasswordHash())
			f := configuredPasswordFixture(t, Config{PasswordAlgorithm: algorithm})
			ctx := context.Background()
			f.store.bind(strings.Repeat("a", 64), "no-password@example.com", "")
			f.store.bindings[blacklistCredentialKey(Credential{Method: MethodPassword, Identifier: "no-password@example.com"})] = strings.Repeat("a", 64)
			for _, identifier := range []string{"unknown", "no-password@example.com"} {
				if _, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: identifier, Password: "incorrect-password"}); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatal("未知或未设密账号应按所选算法执行占位后拒绝")
				}
			}
			f.store.rates[digest("password-account:"+strings.Repeat("a", 64))] = blacklistRate{Starts: f.now, Hits: PasswordAccountRateLimit}
			if _, err := f.service.LoginPassword(ctx, PasswordLoginInput{Identifier: "no-password@example.com", Password: "incorrect-password"}); !errors.Is(err, ErrTooManyRequests) {
				t.Fatal("所选算法的占位拒绝不能绕过限流")
			}
		})
	}
}

func assertSelectedPasswordHash(t *testing.T, algorithm PasswordAlgorithm, encoded string) {
	t.Helper()
	if algorithm == PasswordAlgorithmBcrypt {
		cost, err := bcrypt.Cost([]byte(encoded))
		if !IsLegacyPasswordHash(encoded) || err != nil || cost != bcrypt.DefaultCost {
			t.Fatal("新 bcrypt 摘要及占位摘要必须使用默认 cost 10")
		}
		return
	}
	if !strings.HasPrefix(encoded, passwordPrefix) {
		t.Fatal("默认算法应为固定参数的 Argon2id")
	}
}
