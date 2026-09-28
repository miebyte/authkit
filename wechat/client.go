// Package wechat exchanges WeChat mini-program login codes for server-verified identities.
package wechat

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miebyte/authkit"
)

const (
	code2SessionURL  = "https://api.weixin.qq.com/sns/jscode2session"
	maxResponseBytes = 8192
)

// Config holds server-side mini-program credentials; never send it to clients.
type Config struct {
	AppID  string `json:"app_id"`
	Secret string `json:"secret"`
}

// Enabled reports whether both credentials are present; Validate checks their format.
func (c Config) Enabled() bool { return c.AppID != "" && c.Secret != "" }

// Validate accepts a disabled integration and rejects incomplete credentials.
func (c Config) Validate() error {
	if c.AppID == "" && c.Secret == "" {
		return nil
	}
	if !c.Enabled() || strings.TrimSpace(c.AppID) != c.AppID ||
		strings.TrimSpace(c.Secret) != c.Secret || len(c.AppID) > 64 {
		return errors.New(
			"authkit/wechat: app_id and secret must be configured together without surrounding whitespace",
		)
	}
	return nil
}

// Client uses a bounded HTTP exchange and returns no provider credential material.
type Client struct {
	config   Config
	http     *http.Client
	endpoint string
}

var _ authkit.WechatExchanger = (*Client)(nil)

// New validates a configured integration and creates an eight-second HTTP client.
// A host disabling WeChat should inject a nil exchanger instead.
func New(config Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !config.Enabled() {
		return nil, authkit.ErrWechatUnavailable
	}
	return &Client{config: config, endpoint: code2SessionURL, http: &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// ExchangeCode verifies a temporary wx.login code before a host opens a transaction.
// Raw HTTP errors and response bodies may contain credentials and are never returned.
func (c *Client) ExchangeCode(ctx context.Context, code string) (authkit.WechatIdentity, error) {
	if strings.TrimSpace(code) == "" || len(code) > 512 {
		return authkit.WechatIdentity{}, authkit.ErrWechatCode
	}
	query := url.Values{
		"appid": {c.config.AppID}, "secret": {c.config.Secret},
		"js_code": {code}, "grant_type": {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return authkit.WechatIdentity{}, authkit.ErrWechatLogin
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return authkit.WechatIdentity{}, exchangeError(ctx)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return authkit.WechatIdentity{}, authkit.ErrWechatLogin
	}
	// Reading one extra byte detects an oversized body even when it begins with valid JSON.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return authkit.WechatIdentity{}, exchangeError(ctx)
	}
	if len(body) > maxResponseBytes {
		return authkit.WechatIdentity{}, authkit.ErrWechatLogin
	}
	var result struct {
		OpenID  string `json:"openid"`
		ErrCode int    `json:"errcode"`
	}
	if err = json.Unmarshal(body, &result); err != nil {
		return authkit.WechatIdentity{}, authkit.ErrWechatLogin
	}
	switch result.ErrCode {
	case 40029, 40163, 40226:
		return authkit.WechatIdentity{}, authkit.ErrWechatCode
	case 0:
		if result.OpenID == "" || strings.TrimSpace(result.OpenID) != result.OpenID ||
			len(result.OpenID) > 128 {
			return authkit.WechatIdentity{}, authkit.ErrWechatLogin
		}
		return authkit.WechatIdentity{AppID: c.config.AppID, OpenID: result.OpenID}, nil
	default:
		return authkit.WechatIdentity{}, authkit.ErrWechatLogin
	}
}

// exchangeError preserves caller cancellation without retaining secret-bearing URL errors.
func exchangeError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(authkit.ErrWechatLogin, err)
	}
	return authkit.ErrWechatLogin
}
