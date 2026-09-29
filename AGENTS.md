# 注释语言

编写或修改代码时，注释使用中文。

- 包、类型、函数的说明以被说明的名字开头，后面接中文总结。
- 协议名、错误码、表名和编译指令保持原文，例如 `OpenID`、`ErrNotFound`、`//go:embed`。
- 只在关键处写行内注释，并使用中文说明原因。

```go
// SendCode 先持久化待发送验证码，在事务外发送，再只激活同一条验证码。
func (s *Service) SendCode(ctx context.Context, input SendCodeInput) error {
	// MySQL 以微秒持久化时间；比较签发时间需要经过存储往返。
	now := s.now().UTC().Truncate(time.Microsecond)
}
```
