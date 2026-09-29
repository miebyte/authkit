// Package wechat 把微信小程序登录 code 换取为经服务端核验的身份。
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

// Config 保存服务端小程序凭证；绝不能下发给客户端。
type Config struct {
	AppID  string `json:"app_id"`
	Secret string `json:"secret"`
}

// Enabled 报告两项凭证是否都已提供；Validate 检查它们的格式。
func (c Config) Enabled() bool { return c.AppID != "" && c.Secret != "" }

// Validate 接受未启用的集成，并拒绝不完整的凭证。
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

// Client 使用有界的 HTTP 换取，并且不返回服务商凭证材料。
type Client struct {
	config   Config
	http     *http.Client
	endpoint string
}

var _ authkit.WechatExchanger = (*Client)(nil)

// New 校验已配置的集成，并创建超时为八秒的 HTTP 客户端。
// 宿主关闭微信时应注入 nil 交换器，而不是构造未启用的客户端。
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

// ExchangeCode 在宿主开启事务之前核验临时的 wx.login code。
// 原始 HTTP 错误和响应体可能包含凭证，因此绝不返回。
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
	// 多读一个字节，以便在正文以合法 JSON 开头时仍能发现超长内容。
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

// exchangeError 保留调用方取消，且不保留可能携带密钥的 URL 错误。
func exchangeError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(authkit.ErrWechatLogin, err)
	}
	return authkit.ErrWechatLogin
}
