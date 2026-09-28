package wechat

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/miebyte/authkit"
)

// TestPluginExchange 验证同一 OpenID 在不同 AppID 下仍有独立身份范围，
// 且提供给核心的 Subject 只有摘要，验证方式由独立的 Method 字段表示。
func TestPluginExchange(t *testing.T) {
	ctx := context.Background()
	sum := sha256.Sum256([]byte("person"))
	for _, appID := range []string{"app-one", "app-two"} {
		plugin := &Service{
			exchanger: exchangeFunc(func(ctx context.Context, code string) (Identity, error) {
				if code != "provider-code" {
					t.Fatalf("code = %q", code)
				}
				return Identity{AppID: appID, OpenID: "person"}, nil
			}),
		}
		verified, err := plugin.ExchangeCode(ctx, "provider-code")
		if err != nil {
			t.Fatal(err)
		}
		want := authkit.VerifiedIdentity{
			Identity: authkit.IdentityKey{
				Namespace: Namespace,
				Scope:     appID,
				Subject:   hex.EncodeToString(sum[:]),
			},
			Method: Method,
		}
		if verified != want {
			t.Fatalf("verified = %#v, want %#v", verified, want)
		}
	}
}

// TestPluginInvalidProof 验证不完整、带空白和超长身份在登录与绑定入口都被拒绝。
// 测试不提供账号核心，因此也能确认非法提供方结果不会触发任何账号操作。
func TestPluginInvalidProof(t *testing.T) {
	for _, identity := range []Identity{
		// 完全空身份不具备所有权证明。
		{},
		// 缺少 OpenID 时不能只凭应用范围登录。
		{AppID: "app"},
		// 缺少 AppID 时无法确定身份隔离范围。
		{OpenID: "person"},
		// 异常 AppID 不能在静默修剪后成为另一应用范围。
		{AppID: " app", OpenID: "person"},
		// 异常 OpenID 不能在静默修剪后映射到另一个主体。
		{AppID: "app", OpenID: "person "},
		// AppID 的边界与微信客户端配置约束保持一致。
		{AppID: strings.Repeat("a", 65), OpenID: "person"},
		// 即使后续会哈希，仍先拒绝超过插件长度上限的 OpenID。
		{AppID: "app", OpenID: strings.Repeat("o", 129)},
	} {
		plugin := &Service{exchanger: exchangeFunc(func(context.Context, string) (Identity, error) {
			return identity, nil
		})}
		if result, err := plugin.Login(
			context.Background(),
			LoginInput{Code: "code"},
		); result != nil ||
			!errors.Is(err, ErrLogin) {
			t.Fatalf("identity %#v: result = %#v, error = %v", identity, result, err)
		}
		if result, err := plugin.Bind(
			context.Background(),
			"token",
			BindInput{Code: "code"},
		); result != nil ||
			!errors.Is(err, ErrLogin) {
			t.Fatalf("identity %#v: bind result = %#v, error = %v", identity, result, err)
		}
	}
}

// TestPluginInvalidCode 验证两个入口都在调用验证器之前拒绝无效 code，
// 避免网络副作用或账号状态写入。
func TestPluginInvalidCode(t *testing.T) {
	plugin := &Service{exchanger: exchangeFunc(func(context.Context, string) (Identity, error) {
		t.Fatal("invalid input contacted exchanger")
		return Identity{}, nil
	})}
	for _, code := range []string{"", " \t\n", strings.Repeat("c", 513)} {
		if result, err := plugin.Login(
			context.Background(),
			LoginInput{Code: code},
		); result != nil ||
			!errors.Is(err, ErrCode) {
			t.Fatalf("login result = %#v, error = %v", result, err)
		}
		if result, err := plugin.Bind(
			context.Background(),
			"token",
			BindInput{Code: code},
		); result != nil ||
			!errors.Is(err, ErrCode) {
			t.Fatalf("bind result = %#v, error = %v", result, err)
		}
	}
}

// TestPluginExchangeFailure 验证交换失败时丢弃同时返回的身份，
// 登录和绑定保留错误与取消原因，并且不会继续调用账号核心。
func TestPluginExchangeFailure(t *testing.T) {
	providerErr := errors.Join(ErrLogin, context.Canceled)
	plugin := &Service{exchanger: exchangeFunc(func(context.Context, string) (Identity, error) {
		return Identity{AppID: "app", OpenID: "person"}, providerErr
	})}
	verified, err := plugin.ExchangeCode(context.Background(), "code")
	if verified != (authkit.VerifiedIdentity{}) || !errors.Is(err, context.Canceled) ||
		!errors.Is(err, ErrLogin) {
		t.Fatalf("verified = %#v, error = %v", verified, err)
	}
	if result, err := plugin.Login(
		context.Background(),
		LoginInput{Code: "code"},
	); result != nil ||
		!errors.Is(err, providerErr) {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if result, err := plugin.Bind(
		context.Background(),
		"token",
		BindInput{Code: "code"},
	); result != nil ||
		!errors.Is(err, providerErr) {
		t.Fatalf("bind result = %#v, error = %v", result, err)
	}
}

// TestPluginTransactionOrder 记录交换与事务开始的顺序，
// 确认微信网络操作先完成，再进入可能持有数据库锁的账号事务。
func TestPluginTransactionOrder(t *testing.T) {
	var order []string
	transactionErr := errors.New("transaction unavailable")
	store := &transactionObserver{begin: func() error {
		order = append(order, "transaction")
		return transactionErr
	}}
	core, err := authkit.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := NewService(core, exchangeFunc(func(context.Context, string) (Identity, error) {
		order = append(order, "exchange")
		return Identity{AppID: "app", OpenID: "person"}, nil
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := plugin.Login(
		context.Background(),
		LoginInput{Code: "code"},
	); result != nil ||
		!errors.Is(err, transactionErr) {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if !reflect.DeepEqual(order, []string{"exchange", "transaction"}) {
		t.Fatalf("operation order = %v", order)
	}
}

// TestPluginDependencies 验证核心与验证器是必需依赖，
// 而 nil 注册策略是有意支持的“仅允许已有账号登录”配置。
func TestPluginDependencies(t *testing.T) {
	exchanger := exchangeFunc(
		func(context.Context, string) (Identity, error) { return Identity{}, nil },
	)
	if plugin, err := NewService(nil, exchanger, nil); plugin != nil || err == nil {
		t.Fatal("missing core accepted")
	}
	if plugin, err := NewService(
		&authkit.Service{},
		nil,
		nil,
	); plugin != nil ||
		!errors.Is(err, ErrUnavailable) {
		t.Fatal("missing exchanger accepted")
	}
	if plugin, err := NewService(&authkit.Service{}, exchanger, nil); plugin == nil || err != nil {
		t.Fatal("nil registration policy rejected")
	}
}

// exchangeFunc 将测试函数适配为验证器，便于记录调用或注入异常身份和错误。
type exchangeFunc func(context.Context, string) (Identity, error)

// ExchangeCode 直接执行测试函数，不发起真实微信请求。
func (f exchangeFunc) ExchangeCode(ctx context.Context, code string) (Identity, error) {
	return f(ctx, code)
}

// transactionObserver 在事务开始时返回指定错误，记录顺序但不执行仓储回调。
// 嵌入的仓储未赋值，可防止测试无意中依赖未声明的数据库行为。
type transactionObserver struct {
	authkit.Repositories
	// begin 记录事务开始事件，并提供测试要求的终止错误。
	begin func() error
}

// WithTransaction 只触发开始观察点，阻止回调进入实际仓储操作。
func (s *transactionObserver) WithTransaction(
	context.Context,
	func(authkit.Repositories) error,
) error {
	return s.begin()
}
