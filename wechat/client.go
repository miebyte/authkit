// Package wechat 为 authkit 账号提供微信小程序登录与身份绑定插件。
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
)

const (
	// code2SessionURL 是微信小程序凭临时 code 换取身份的固定服务端接口。
	code2SessionURL = "https://api.weixin.qq.com/sns/jscode2session"
	// maxResponseBytes 将响应正文限制为 8 KiB，避免异常响应造成无界内存读取。
	maxResponseBytes = 8192
)

// Identity 表示经微信服务端验证、限定在一个小程序下的身份。
// 只能使用服务端交换 code 的结果，禁止用客户端提交的 OpenID 构造已验证身份。
type Identity struct {
	// AppID 来自服务端配置，用于区分不同小程序的身份范围。
	AppID string
	// OpenID 来自微信验证结果；插件会先取摘要，再传给账号核心。
	OpenID string
}

// Exchanger 在数据库事务开始前验证 wx.login 返回的临时 code。
// 自定义实现也必须完成服务端验证，不能仅把客户端身份字段透传为验证结果。
type Exchanger interface {
	// ExchangeCode 消费临时 code，返回服务端验证后的应用身份或验证错误。
	ExchangeCode(context.Context, string) (Identity, error)
}

// Config 保存微信小程序的服务端凭据，禁止将密钥下发给客户端。
type Config struct {
	// AppID 指定发起身份交换的小程序，同时作为核心身份的 Scope。
	AppID string `json:"app_id"`
	// Secret 是服务端应用密钥，不应记录到日志或出现在对外错误中。
	Secret string `json:"secret"`
}

// Enabled 判断 AppID 和 Secret 是否都已配置；具体格式仍需由 Validate 校验。
func (c Config) Enabled() bool { return c.AppID != "" && c.Secret != "" }

// Validate 允许两个字段同时留空以表示宿主未启用微信，
// 但拒绝不完整配置、首尾空白和超长 AppID；New 不会据此创建未启用的客户端。
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

// Client 通过限制超时、响应大小和重定向的 HTTP 请求交换微信身份。
// 返回值只保留身份字段，不暴露微信 session_key、响应正文或带密钥的请求地址。
type Client struct {
	// config 固定当前客户端的应用范围和服务端密钥。
	config Config
	// http 统一执行总超时和禁止重定向策略。
	http *http.Client
	// endpoint 默认指向微信服务，测试时替换为本地模拟服务。
	endpoint string
}

var _ Exchanger = (*Client)(nil)

// New 校验启用状态与凭据，并创建总超时为 8 秒的 HTTP 客户端。
// 禁止跟随重定向，避免包含 Secret 和 code 的请求被转发到其他地址。
// 未启用微信时宿主应省略整个插件，而不是构造空配置客户端。
func New(config Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !config.Enabled() {
		return nil, ErrUnavailable
	}
	return &Client{config: config, endpoint: code2SessionURL, http: &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// ExchangeCode 在宿主开启数据库事务前交换一次性 wx.login code。
// code 会作为请求参数发送给微信；格式错误时在本地拒绝，交换失败时只返回稳定错误。
// 原始 HTTP 错误和响应正文可能包含 Secret、code 或会话密钥，不能直接向宿主返回。
func (c *Client) ExchangeCode(ctx context.Context, code string) (Identity, error) {
	if strings.TrimSpace(code) == "" || len(code) > 512 {
		return Identity{}, ErrCode
	}
	query := url.Values{
		"appid": {c.config.AppID}, "secret": {c.config.Secret},
		"js_code": {code}, "grant_type": {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return Identity{}, ErrLogin
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Identity{}, exchangeError(ctx)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Identity{}, ErrLogin
	}
	// 多读一个字节可检测完整响应是否超限；即使开头是合法 JSON，超大尾部也不能被忽略。
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return Identity{}, exchangeError(ctx)
	}
	if len(body) > maxResponseBytes {
		return Identity{}, ErrLogin
	}
	var result struct {
		// 只解析必要身份和状态码，不保留 session_key、UnionID 或错误正文。
		OpenID  string `json:"openid"`
		ErrCode int    `json:"errcode"`
	}
	if err = json.Unmarshal(body, &result); err != nil {
		return Identity{}, ErrLogin
	}
	switch result.ErrCode {
	case 40029, 40163, 40226:
		// 无效、已使用或受限的 code 统一归为凭据错误，宿主可要求客户端重新获取。
		return Identity{}, ErrCode
	case 0:
		if result.OpenID == "" || strings.TrimSpace(result.OpenID) != result.OpenID ||
			len(result.OpenID) > 128 {
			return Identity{}, ErrLogin
		}
		return Identity{AppID: c.config.AppID, OpenID: result.OpenID}, nil
	default:
		// 配置错误、微信限流和系统故障均归为交换失败，不透出可能含秘密的 errmsg。
		return Identity{}, ErrLogin
	}
}

// exchangeError 保留调用方的取消或截止时间错误，使 errors.Is 仍可判断取消原因，
// 同时丢弃可能包含 Secret 和 code 的底层 URL 错误。
func exchangeError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrLogin, err)
	}
	return ErrLogin
}
