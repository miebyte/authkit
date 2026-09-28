package authkit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixture 为每个核心测试提供独立存储与可控时钟，便于精确验证过期和回滚边界。
type fixture struct {
	service *Service
	store   *memoryStore
	now     time.Time
}

// newFixture 创建空账号服务并固定初始时间；测试可以推进 now，而不必实际等待。
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{store: newMemoryStore(), now: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)}
	var err error
	f.service, err = NewService(f.store)
	if err != nil {
		t.Fatal(err)
	}
	f.service.now = func() time.Time { return f.now }
	return f
}

// proof 构造核心单测使用的可信身份，不执行真实凭证验证。
// 生产代码应使用插件产生该结果；这里直接构造以单独验证核心归属与会话规则。
func proof(namespace, scope, subject string) VerifiedIdentity {
	return VerifiedIdentity{
		Identity: IdentityKey{Namespace: namespace, Scope: scope, Subject: subject},
		Method:   namespace,
	}
}

// login 显式允许注册并完成一次独立登录，为绑定及会话测试准备已提交的账号。
func (f *fixture) login(t *testing.T, verified VerifiedIdentity) *LoginResult {
	t.Helper()
	result, err := f.service.LoginVerified(
		context.Background(),
		verified,
		RegistrationPolicyFunc(allowRegistration),
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// requireError 用 errors.Is 比较错误语义，允许实现保留错误包装信息。
func requireError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

// TestIdentityLifecycle 验证首次注册、相同身份通过不同验证方式登录、摘要存储及身份列表。
// 同时检查会话到期前一刻有效、到期时立即失效，以及重复退出的幂等性。
func TestIdentityLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	verified := proof("email", "", "alice@example.com")
	verified.Method = "email_code"
	first := f.login(t, verified)
	if !first.Created || first.User.ID == "" || len(first.Token) != 64 ||
		!first.Expires.Equal(f.now.Add(SessionTTL)) {
		t.Fatalf("unexpected result: %#v", first)
	}
	session := f.store.state.sessions[digest(first.Token)]
	if session.UserID != first.User.ID || session.Hash == first.Token {
		t.Fatal("session must persist only the credential digest")
	}
	// 验证方式可以变化，身份键保持一致时应复用账号，也不应再次执行注册准入。
	verified.Method = "test_other_verifier"
	repeat, err := f.service.LoginVerified(ctx, verified, nil)
	if err != nil || repeat.Created || repeat.User.ID != first.User.ID {
		t.Fatalf("repeat login = %v, %v", repeat, err)
	}
	identities, err := f.service.ListIdentities(ctx, first.User.ID)
	if err != nil || len(identities) != 1 || identities[0].Key != verified.Identity {
		t.Fatalf("identities = %v, %v", identities, err)
	}
	f.now = first.Expires.Add(-time.Nanosecond)
	if _, err := f.service.Authenticate(ctx, first.Token); err != nil {
		t.Fatal(err)
	}
	f.now = first.Expires
	_, err = f.service.Authenticate(ctx, first.Token)
	requireError(t, err, ErrUnauthorized)
	for i := 0; i < 2; i++ {
		if err := f.service.Logout(ctx, first.Token); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := f.store.state.sessions[digest(first.Token)]; ok {
		t.Fatal("logout left a stored session")
	}
}

// TestRegistrationAdmission 验证缺失策略或空策略函数默认拒绝注册，拒绝后没有残留写入。
// 自定义策略应收到完整注册上下文，已有账号登录应直接复用账号、不再触发准入。
func TestRegistrationAdmission(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	verified := proof("custom", "tenant", "subject")
	verified.Method, verified.RegistrationRef = "custom_oauth", "host-ref"
	for _, policy := range []RegistrationPolicy{nil, RegistrationPolicyFunc(nil)} {
		_, err := f.service.LoginVerified(ctx, verified, policy)
		requireError(t, err, ErrRegistrationDenied)
		if len(f.store.state.users) != 0 || len(f.store.state.identities) != 0 ||
			len(f.store.state.sessions) != 0 {
			t.Fatal("rejected registration left state")
		}
	}
	var seen Registration
	denied := errors.New("host rejected")
	policy := RegistrationPolicyFunc(func(_ context.Context, input Registration) error {
		seen = input
		return denied
	})
	_, err := f.service.LoginVerified(ctx, verified, policy)
	requireError(t, err, denied)
	if seen.User.ID == "" || seen.Identity != verified.Identity || seen.Method != verified.Method ||
		seen.Reference != verified.RegistrationRef || len(f.store.state.identities) != 0 {
		t.Fatalf("registration input or rollback incorrect: %#v", seen)
	}
	f.login(t, verified)
	seen = Registration{}
	if _, err := f.service.LoginVerified(ctx, verified, policy); err != nil || seen.User.ID != "" {
		t.Fatal("existing account unexpectedly ran registration policy", err)
	}
}

// TestBinding 分别从邮箱身份和微信身份创建账号，再绑定另一种身份，验证归属与流程对称。
// 覆盖当前 Token 轮换、其他设备会话保留、重复绑定，以及禁止替换身份和合并独立账号。
func TestBinding(t *testing.T) {
	ctx := context.Background()
	for _, firstNamespace := range []string{"email", "wechat"} {
		t.Run(firstNamespace, func(t *testing.T) {
			f := newFixture(t)
			firstProof, nextProof := proof(
				"email",
				"",
				"alice@example.com",
			), proof(
				"wechat",
				"app-one",
				"openid-digest",
			)
			if firstNamespace == "wechat" {
				firstProof, nextProof = nextProof, firstProof
			}
			first := f.login(t, firstProof)
			otherDevice := f.login(t, firstProof)
			bound, err := f.service.BindVerified(ctx, first.Token, nextProof)
			if err != nil || bound.User.ID != first.User.ID || bound.Created ||
				bound.Token == first.Token {
				t.Fatalf("bind = %v, %v", bound, err)
			}
			_, err = f.service.Authenticate(ctx, first.Token)
			requireError(t, err, ErrUnauthorized)
			for _, token := range []string{bound.Token, otherDevice.Token} {
				user, err := f.service.Authenticate(ctx, token)
				if err != nil || user.ID != first.User.ID {
					t.Fatalf("session = %v, %v", user, err)
				}
			}
			repeat, err := f.service.BindVerified(ctx, bound.Token, nextProof)
			if err != nil || repeat.User.ID != first.User.ID || len(f.store.state.identities) != 2 {
				t.Fatal("repeated binding changed identity ownership", err)
			}
			logged, err := f.service.LoginVerified(ctx, nextProof, nil)
			if err != nil || logged.User.ID != first.User.ID || logged.Created {
				t.Fatalf("bound login = %v, %v", logged, err)
			}
			replacement := nextProof
			replacement.Identity.Subject = "another-subject"
			_, err = f.service.BindVerified(ctx, repeat.Token, replacement)
			requireError(t, err, ErrIdentityBound)
			if len(f.store.state.identities) != 2 {
				t.Fatal("failed replacement left a placeholder")
			}
			independentProof := proof("other-provider", "", "another-person")
			independent := f.login(t, independentProof)
			_, err = f.service.BindVerified(ctx, repeat.Token, independentProof)
			requireError(t, err, ErrIdentityConflict)
			if len(f.store.state.users) != 2 || independent.User.ID == first.User.ID {
				t.Fatal("independently registered accounts were merged")
			}
			if _, err := f.service.Authenticate(ctx, repeat.Token); err != nil {
				t.Fatal("failed bind revoked its session", err)
			}
		})
	}
}

// TestIdentityScopeIsolation 验证相同主体在不同命名空间或范围内属于不同身份。
// 同一账号可以继续绑定其他范围的身份，不能把“每个范围一个”误实现为“每种插件一个”。
func TestIdentityScopeIsolation(t *testing.T) {
	f := newFixture(t)
	first := f.login(t, proof("provider", "one", "same-subject"))
	otherScope := f.login(t, proof("provider", "two", "same-subject"))
	otherNamespace := f.login(t, proof("another-provider", "one", "same-subject"))
	if first.User.ID == otherScope.User.ID || first.User.ID == otherNamespace.User.ID {
		t.Fatal("identity scopes collided")
	}
	bound, err := f.service.BindVerified(
		context.Background(),
		first.Token,
		proof("provider", "three", "subject"),
	)
	if err != nil || bound.User.ID != first.User.ID {
		t.Fatal("different scope should be bindable", err)
	}
}

// TestBindingRechecksSession 模拟预检查成功后、加锁读取前会话被撤销或到期。
// 绑定必须重新拒绝该请求并回滚身份和会话写入，不能沿用首次读取的授权结果。
func TestBindingRechecksSession(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"revoke", "expire"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			first := f.login(t, proof("one", "", "subject"))
			f.store.beforeSessionLock = func(state *memoryState, hash string) {
				if change == "revoke" {
					delete(state.sessions, hash)
				} else {
					f.now = first.Expires
				}
			}
			_, err := f.service.BindVerified(ctx, first.Token, proof("two", "", "subject"))
			requireError(t, err, ErrUnauthorized)
			if len(f.store.state.identities) != 1 || len(f.store.state.sessions) != 1 {
				t.Fatal("invalid session permitted binding writes")
			}
		})
	}
}

// TestHostTransactionRollback 验证核心登录成功后宿主业务失败，会撤销全部账号、身份和会话写入。
// 事务中的临时 Token 不可认证，且宿主未显式提供准入策略时仍应拒绝新注册。
func TestHostTransactionRollback(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	verified := proof("plugin", "", "subject")
	hostErr := errors.New("host operation failed")
	var provisional *LoginResult
	err := f.store.WithTransaction(ctx, func(repos Repositories) error {
		outcome, err := f.service.InTransaction(repos, RegistrationPolicyFunc(allowRegistration)).
			LoginVerified(ctx, verified)
		if err != nil {
			return err
		}
		provisional = outcome.Login
		return hostErr
	})
	requireError(t, err, hostErr)
	if provisional == nil || len(f.store.state.users) != 0 || len(f.store.state.identities) != 0 ||
		len(f.store.state.sessions) != 0 {
		t.Fatal("host rollback left identity writes")
	}
	_, err = f.service.Authenticate(ctx, provisional.Token)
	requireError(t, err, ErrUnauthorized)
	err = f.store.WithTransaction(ctx, func(repos Repositories) error {
		_, err := f.service.InTransaction(repos, nil).LoginVerified(ctx, verified)
		return err
	})
	requireError(t, err, ErrRegistrationDenied)
}

// TestCommitFailureDoesNotReturnToken 模拟最终提交失败，确保独立调用不会返回尚未生效的 Token。
func TestCommitFailureDoesNotReturnToken(t *testing.T) {
	f := newFixture(t)
	f.store.commitErr = errors.New("commit failed")
	result, err := f.service.LoginVerified(
		context.Background(),
		proof("plugin", "", "subject"),
		RegistrationPolicyFunc(allowRegistration),
	)
	requireError(t, err, f.store.commitErr)
	if result != nil || len(f.store.state.users) != 0 {
		t.Fatal("commit failure leaked credentials or account")
	}
}

// TestInvalidInputDoesNotAllocateState 覆盖缺失依赖、空身份字段、超长或非法编码、无效会话等输入。
// 这些请求必须在产生持久化账号、身份或会话之前被拒绝。
func TestInvalidInputDoesNotAllocateState(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if _, err := NewService(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil store accepted")
	}
	valid := proof("plugin", "", "subject")
	tests := []VerifiedIdentity{
		{},
		{Identity: valid.Identity},
		proof("", "", "subject"), proof("plugin", "", ""),
		proof(strings.Repeat("x", 65), "", "subject"),
		proof("plugin", strings.Repeat("x", 256), "subject"),
		proof("plugin", "", strings.Repeat("x", 255)),
		proof("plugin", "", " subject"),
		proof("plugin", "scope ", "subject"),
		proof("plugin", "", string([]byte{0xff})),
	}
	badMethod := valid
	badMethod.Method = strings.Repeat("x", 65)
	tests = append(tests, badMethod)
	for _, verified := range tests {
		_, err := f.service.LoginVerified(ctx, verified, RegistrationPolicyFunc(allowRegistration))
		requireError(t, err, ErrInvalidInput)
	}
	for _, token := range []string{"", "bad-token", strings.Repeat("a", 64)} {
		_, err := f.service.BindVerified(ctx, token, valid)
		requireError(t, err, ErrUnauthorized)
		if err := f.service.Logout(ctx, token); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.store.state.users) != 0 || len(f.store.state.identities) != 0 ||
		len(f.store.state.sessions) != 0 {
		t.Fatal("invalid request allocated state")
	}
}
