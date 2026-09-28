package wechat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestExchangeCode 验证微信请求参数、成功身份解析和错误分类，
// 并确保失败结果不携带身份、请求地址或提供方返回的敏感字段。
func TestExchangeCode(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		// 成功响应只返回应用身份，忽略 session_key 和未采用的 UnionID。
		{"success", 200, `{"openid":"wx-person","session_key":"private-key","unionid":"unused"}`, nil},
		// 无效 code 映射为凭据错误，不能向外传递提供方 errmsg。
		{"invalid-code", 200, `{"errcode":40029,"errmsg":"private-code"}`, ErrCode},
		// 已被消费的 code 不能重复登录。
		{"reused-code", 200, `{"errcode":40163}`, ErrCode},
		// 被微信限制的 code 同样归入凭据拒绝。
		{"blocked-code", 200, `{"errcode":40226}`, ErrCode},
		// 提供方系统繁忙是交换故障，错误正文中的密钥标记必须被丢弃。
		{"provider-busy", 200, `{"errcode":-1,"errmsg":"private-secret"}`, ErrLogin},
		// 服务端应用凭据错误不能被误判为已验证身份。
		{"invalid-credentials", 200, `{"errcode":40013}`, ErrLogin},
		// 微信侧限流通过稳定的交换错误返回。
		{"rate-limit", 200, `{"errcode":45011}`, ErrLogin},
		// 只有会话密钥而缺少 OpenID 的响应不能构成登录身份。
		{"missing-identity", 200, `{"session_key":"private-key"}`, ErrLogin},
		// 无法解析的正文不能产生身份结果。
		{"invalid-json", 200, `{`, ErrLogin},
		// 首个对象之后夹带额外 JSON 也必须拒绝。
		{"trailing-json", 200, `{"openid":"wx-person"}{}`, ErrLogin},
		// 合法 JSON 前的超大空白不能绕过正文大小限制。
		{"oversized-prefix", 200, strings.Repeat(" ", maxResponseBytes) + `{"openid":"wx-person"}`, ErrLogin},
		// 合法 JSON 后的超大空白同样必须触发上限。
		{"oversized-suffix", 200, `{"openid":"wx-person"}` + strings.Repeat(" ", maxResponseBytes), ErrLogin},
		// 过长 OpenID 在进入插件和数据库前拒绝。
		{"oversized-identity", 200, `{"openid":"` + strings.Repeat("a", 129) + `"}`, ErrLogin},
		// 不默默修剪提供方身份，以免把异常身份归入另一主体。
		{"whitespace-identity", 200, `{"openid":" wx-person"}`, ErrLogin},
		// 非成功 HTTP 状态即使带有 OpenID，也不能被当作交换成功。
		{"failed-status", 503, `{"openid":"wx-person"}`, ErrLogin},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Query().Get("appid") != "app" ||
						r.URL.Query().
							Get("secret") !=
							"private-secret" || r.URL.Query().Get("js_code") != "private-code" ||
						r.URL.Query().Get("grant_type") != "authorization_code" {
						t.Error("incorrect server-side code2Session request")
					}
					w.WriteHeader(test.status)
					fmt.Fprint(w, test.body)
				}),
			)
			defer server.Close()
			client := newTestClient(t, server.URL)
			identity, err := client.ExchangeCode(context.Background(), "private-code")
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if err == nil && (identity.AppID != "app" || identity.OpenID != "wx-person") {
				t.Fatalf("identity = %#v", identity)
			}
			if err != nil && identity != (Identity{}) {
				t.Fatalf("failure returned identity: %#v", identity)
			}
			assertSafeError(t, err, server.URL)
		})
	}
}

// TestExchangeCodeCancellation 分别覆盖客户端超时、上下文截止时间和主动取消，
// 确认请求及时结束、调用方取消原因可识别且返回错误不泄露请求凭据。
func TestExchangeCodeCancellation(t *testing.T) {
	for _, mode := range []string{"client-timeout", "context-deadline", "context-cancel"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(started)
					<-r.Context().Done()
				}),
			)
			defer server.Close()
			client := newTestClient(t, server.URL)
			ctx := context.Background()
			var cancel context.CancelFunc
			switch mode {
			case "client-timeout":
				// HTTP 客户端自己的超时必须终止请求，即使调用方上下文仍有效。
				client.http.Timeout = 50 * time.Millisecond
			case "context-deadline":
				// 调用方截止时间要早于默认 HTTP 超时生效，且保留 DeadlineExceeded。
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			case "context-cancel":
				// 确认请求已经开始后再取消，以覆盖传输过程中的主动中断。
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				go func() { <-started; cancel() }()
			}
			_, err := client.ExchangeCode(ctx, "private-code")
			if !errors.Is(err, ErrLogin) {
				t.Fatalf("error = %v", err)
			}
			if ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
				t.Fatalf("caller cancellation lost: %v", err)
			}
			assertSafeError(t, err, server.URL)
		})
	}
}

// TestExchangeCodeRedirect 验证收到重定向时拒绝登录，
// 且包含 Secret 和 code 的请求不会实际到达重定向目标。
func TestExchangeCodeRedirect(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed.Store(true)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()
	client := newTestClient(t, server.URL)
	if _, err := client.ExchangeCode(
		context.Background(),
		"private-code",
	); !errors.Is(
		err,
		ErrLogin,
	) {
		t.Fatalf("error = %v", err)
	}
	if followed.Load() {
		t.Fatal("followed provider redirect")
	}
}

// TestExchangeCodeTransportErrors 覆盖连接失败和非法请求地址，
// 确认底层 net/http URL 错误不会把带凭据的地址暴露给宿主。
func TestExchangeCodeTransportErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()
	for _, endpoint := range []string{server.URL, "http://%invalid-private-secret"} {
		client := newTestClient(t, endpoint)
		_, err := client.ExchangeCode(context.Background(), "private-code")
		if !errors.Is(err, ErrLogin) {
			t.Fatalf("error = %v", err)
		}
		assertSafeError(t, err, endpoint)
	}
}

// TestExchangeCodeInput 验证空值、纯空白和超长 code 在本地被拒绝，
// 避免无效输入发起微信网络请求。
func TestExchangeCodeInput(t *testing.T) {
	var contacted atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted.Store(true)
	}))
	defer server.Close()
	client := newTestClient(t, server.URL)
	for _, code := range []string{"", " \t\n", strings.Repeat("c", 513)} {
		if _, err := client.ExchangeCode(
			context.Background(),
			code,
		); !errors.Is(
			err,
			ErrCode,
		) {
			t.Fatalf("error = %v", err)
		}
	}
	if contacted.Load() {
		t.Fatal("invalid code reached provider")
	}
}

// TestConfig 验证缺失字段、首尾空白、长度限制及禁用配置的语义，
// 并确认启用的客户端保留默认 8 秒超时。
func TestConfig(t *testing.T) {
	for _, config := range []Config{
		{AppID: "app"},
		{Secret: "secret"},
		{AppID: " app", Secret: "secret"},
		{AppID: "app", Secret: "secret "},
		{AppID: strings.Repeat("a", 65), Secret: "secret"},
	} {
		if config.Validate() == nil {
			t.Fatal("invalid credentials accepted")
		}
		if client, err := New(config); err == nil || client != nil {
			t.Fatal("invalid client constructed")
		}
	}
	if err := (Config{}).Validate(); err != nil || (Config{}).Enabled() {
		t.Fatal("disabled host configuration rejected or enabled")
	}
	if client, err := New(
		Config{},
	); !errors.Is(err, ErrUnavailable) ||
		client != nil {
		t.Fatal("disabled adapter constructed")
	}
	client := newTestClient(t, code2SessionURL)
	if !client.config.Enabled() || client.http.Timeout != 8*time.Second {
		t.Fatal("configured adapter lacks default timeout")
	}
}

// newTestClient 保留生产构造器的超时和重定向策略，仅将请求地址替换为测试服务。
func newTestClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	client, err := New(Config{AppID: "app", Secret: "private-secret"})
	if err != nil {
		t.Fatal(err)
	}
	client.endpoint = endpoint
	return client
}

// assertSafeError 检查错误文本中没有测试凭据标记或请求地址，防止错误脱敏退化。
func assertSafeError(t *testing.T, err error, endpoint string) {
	t.Helper()
	if err != nil &&
		(strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), endpoint)) {
		t.Fatalf("provider credentials leaked: %v", err)
	}
}
