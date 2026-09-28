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

	"github.com/miebyte/authkit"
)

// TestExchangeCode covers the provider contract and excludes provider secrets from results.
func TestExchangeCode(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"success", 200, `{"openid":"wx-person","session_key":"private-key","unionid":"unused"}`, nil},
		{"invalid-code", 200, `{"errcode":40029,"errmsg":"private-code"}`, authkit.ErrWechatCode},
		{"reused-code", 200, `{"errcode":40163}`, authkit.ErrWechatCode},
		{"blocked-code", 200, `{"errcode":40226}`, authkit.ErrWechatCode},
		{"provider-busy", 200, `{"errcode":-1,"errmsg":"private-secret"}`, authkit.ErrWechatLogin},
		{"invalid-credentials", 200, `{"errcode":40013}`, authkit.ErrWechatLogin},
		{"rate-limit", 200, `{"errcode":45011}`, authkit.ErrWechatLogin},
		{"missing-identity", 200, `{"session_key":"private-key"}`, authkit.ErrWechatLogin},
		{"invalid-json", 200, `{`, authkit.ErrWechatLogin},
		{"trailing-json", 200, `{"openid":"wx-person"}{}`, authkit.ErrWechatLogin},
		{"oversized-prefix", 200, strings.Repeat(" ", maxResponseBytes) + `{"openid":"wx-person"}`, authkit.ErrWechatLogin},
		{"oversized-suffix", 200, `{"openid":"wx-person"}` + strings.Repeat(" ", maxResponseBytes), authkit.ErrWechatLogin},
		{"oversized-identity", 200, `{"openid":"` + strings.Repeat("a", 129) + `"}`, authkit.ErrWechatLogin},
		{"whitespace-identity", 200, `{"openid":" wx-person"}`, authkit.ErrWechatLogin},
		{"failed-status", 503, `{"openid":"wx-person"}`, authkit.ErrWechatLogin},
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
			if err != nil && identity != (authkit.WechatIdentity{}) {
				t.Fatalf("failure returned identity: %#v", identity)
			}
			assertSafeError(t, err, server.URL)
		})
	}
}

// TestExchangeCodeCancellation verifies HTTP deadlines and caller cancellation.
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
				client.http.Timeout = 50 * time.Millisecond
			case "context-deadline":
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			case "context-cancel":
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				go func() { <-started; cancel() }()
			}
			_, err := client.ExchangeCode(ctx, "private-code")
			if !errors.Is(err, authkit.ErrWechatLogin) {
				t.Fatalf("error = %v", err)
			}
			if ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
				t.Fatalf("caller cancellation lost: %v", err)
			}
			assertSafeError(t, err, server.URL)
		})
	}
}

// TestExchangeCodeRedirect ensures the credential-bearing request is not redirected.
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
		authkit.ErrWechatLogin,
	) {
		t.Fatalf("error = %v", err)
	}
	if followed.Load() {
		t.Fatal("followed provider redirect")
	}
}

// TestExchangeCodeTransportErrors prevents a net/http URL error from escaping to hosts.
func TestExchangeCodeTransportErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()
	for _, endpoint := range []string{server.URL, "http://%invalid-private-secret"} {
		client := newTestClient(t, endpoint)
		_, err := client.ExchangeCode(context.Background(), "private-code")
		if !errors.Is(err, authkit.ErrWechatLogin) {
			t.Fatalf("error = %v", err)
		}
		assertSafeError(t, err, endpoint)
	}
}

// TestExchangeCodeInput rejects unusable codes before contacting WeChat.
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
			authkit.ErrWechatCode,
		) {
			t.Fatalf("error = %v", err)
		}
	}
	if contacted.Load() {
		t.Fatal("invalid code reached provider")
	}
}

// TestConfig validates optional host configuration and rejects constructing disabled clients.
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
	); !errors.Is(err, authkit.ErrWechatUnavailable) ||
		client != nil {
		t.Fatal("disabled adapter constructed")
	}
	client := newTestClient(t, code2SessionURL)
	if !client.config.Enabled() || client.http.Timeout != 8*time.Second {
		t.Fatal("configured adapter lacks default timeout")
	}
}

// newTestClient preserves production HTTP policy while pointing requests at a test server.
func newTestClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	client, err := New(Config{AppID: "app", Secret: "private-secret"})
	if err != nil {
		t.Fatal(err)
	}
	client.endpoint = endpoint
	return client
}

// assertSafeError rejects request URLs and provider secrets in returned error text.
func assertSafeError(t *testing.T, err error, endpoint string) {
	t.Helper()
	if err != nil &&
		(strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), endpoint)) {
		t.Fatalf("provider credentials leaked: %v", err)
	}
}
