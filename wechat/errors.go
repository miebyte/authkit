package wechat

import "errors"

// 稳定错误供宿主使用 errors.Is 匹配，再映射为自己的 HTTP 响应。
var (
	// ErrUnavailable 表示未配置可用的微信客户端或验证器，不能创建启用的插件。
	ErrUnavailable = errors.New("authkit/wechat: login is not configured")
	// ErrLogin 表示网络、提供方故障或异常响应导致交换失败，不包含底层敏感信息。
	ErrLogin = errors.New("authkit/wechat: exchange failed")
	// ErrCode 表示本地格式不合法，或微信明确拒绝该临时 code。
	ErrCode = errors.New("authkit/wechat: invalid code")
)
