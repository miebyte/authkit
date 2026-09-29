# authkit

`authkit` 是嵌入 Go 服务的身份模块，提供邮箱验证码登录、微信小程序登录、账号绑定和会话管理。宿主负责业务 HTTP 接口、邮件投递、注册准入和业务权限；模块不依赖特定 Web 框架。可选的 `admin` 包提供内置超管后台页面。

- 模块路径：`github.com/miebyte/authkit`
- Go 版本：`1.27.1`（以 `go.mod` 为准）
- 默认存储：基于宿主 `*gorm.DB` 的 MySQL 适配器；也可实现 `ports.go` 中的仓储接口

## 已实现的功能

| 功能 | 行为 |
| --- | --- |
| 邮箱验证码 | 邮箱规范化、发码限流、邮件投递后激活验证码、验证并登录或注册 |
| 微信小程序登录 | 服务端用 `wx.login` code 调用 `code2Session`，按 OpenID 识别账号 |
| 账号绑定 | 首次微信登录可凭邮箱验证码复用已有邮箱账号；微信账号可绑定尚未被占用的邮箱 |
| 注册准入 | 创建新账号前调用宿主策略，可在同一事务内验证或消费邀请等业务数据 |
| 会话 | 创建、认证、退出单个会话；数据库仅保存 Token 摘要 |
| 宿主事务 | 身份写入可与邀请消费、入组等宿主业务写入一起提交或回滚 |

核心模块不提供业务路由、Cookie/Bearer 管理、邮件模板、邀请表、角色表或资源权限判断。`Authenticate` 只确认账号身份，业务授权仍由宿主处理。

## 接入 MySQL

宿主创建并管理 MySQL 的 `*gorm.DB`，连接参数应包含 `parseTime=true&loc=UTC`。迁移由宿主显式执行；`authmysql.NewStore` 不打开连接，也不自动迁移。

```go
import (
    "github.com/miebyte/authkit"
    "github.com/miebyte/authkit/mysql"
    "github.com/miebyte/authkit/wechat"
    "gorm.io/gorm"
)

func newAuthService(
    db *gorm.DB,
    sender authkit.CodeSender,
    policy authkit.RegistrationPolicy,
    appID, appSecret string,
) (*authkit.Service, error) {
    if err := db.AutoMigrate(authmysql.Models()...); err != nil {
        return nil, err
    }
    store, err := authmysql.NewStore(db)
    if err != nil {
        return nil, err
    }

    var exchanger authkit.WechatExchanger
    if appID != "" || appSecret != "" {
        exchanger, err = wechat.New(wechat.Config{AppID: appID, Secret: appSecret})
        if err != nil {
            return nil, err
        }
    }
    return authkit.NewService(store, sender, exchanger, policy)
}
```

`sender` 必须实现 `SendCode(ctx context.Context, email, code string) error`，由宿主决定邮件内容和供应商。`policy` 实现 `Authorize(ctx context.Context, registration authkit.Registration) error`；仅创建新账号时调用。`Registration` 包含新账号 `Account` 和 `Method`（`"email"` 或 `"wechat"`）。传入 `nil` 会拒绝新注册（`ErrRegistrationDenied`），已有账号仍可登录。若宿主确实允许开放注册，可显式传入返回 `nil` 的 `authkit.RegistrationPolicyFunc`。不启用微信时，将 `exchanger` 设为 `nil`。

### 邮箱登录与会话

以下是发送验证码、登录和已登录请求中的关键调用；错误处理与 HTTP 响应由宿主完成。

```go
sendErr := service.SendCode(ctx, authkit.SendCodeInput{
    Email: email,
    IP:    clientIP,
})

login, loginErr := service.LoginEmail(ctx, authkit.EmailLoginInput{
    Email: email,
    Code:  code,
})

user, authErr := service.Authenticate(ctx, tokenFromRequest)
logoutErr := service.Logout(ctx, tokenFromRequest)
```

`SendCodeInput.IP` 由宿主根据可信代理配置取得；空值会让这类请求共用同一个 IP 限流桶。`LoginResult` 包含 `Account`、明文 `Token`、`Expires` 和 `Created`。账号 ID 和 Token 均为 256 位随机值，编码成 64 个十六进制字符。Token 只在创建或轮换会话时返回；`Logout` 仅撤销传入的会话，重复退出可安全重试。

### 微信登录与绑定邮箱

小程序把 `wx.login` 返回的 code 传给宿主，宿主调用：

```go
login, err := service.LoginWechat(ctx, wxCode, authkit.WechatLoginInput{})
```

需要邮箱证明时，先向邮箱发送验证码，再将 `Email` 和 `EmailCode` 一起传入 `WechatLoginInput`。首次微信登录可据此复用已有邮箱账号；已有微信账号若尚未绑定邮箱，可据此绑定。已独立注册的微信账号不会与另一个邮箱账号合并。也可以用当前会话 Token 单独绑定邮箱：

```go
login, err := service.BindEmail(ctx, currentToken, authkit.BindEmailInput{
    Email: email,
    Code:  code,
})
```

只有拥有微信身份的账号可以调用 `BindEmail`，已绑定的邮箱不可替换。`BindEmail` 成功后账号 ID 不变，返回新 Token，原 `currentToken` 失效；其他设备的会话保留。尚未绑定邮箱的微信账号，其 `Account.Email` 为空字符串。不要把客户端提供的 OpenID 当作已验证身份；需要在宿主事务中登录时，先调用 `service.ExchangeWechat(ctx, wxCode)`。

## 验证码、身份与错误

- 邮箱会去除首尾空白并转小写。验证码是六位数字，有效期 10 分钟；同一邮箱只保留当前验证码，最多允许 5 次错误尝试。
- 60 秒内不能向同一邮箱重发。自首次请求起的固定一小时窗口内，每邮箱最多发送 10 次、每 IP 最多 30 次。
- 验证码先保存为不可用状态；邮件发送成功后才激活。投递失败的验证码不能登录，但发码次数与重发冷却仍保留。
- 微信只把 OpenID 当作登录凭证，入库前取摘要，不保存 AppID、UnionID 或 `session_key`。同一个 OpenID 只能绑定一个账号。
- 会话有效期为 30 天，不自动续期；过期会话不能认证。过期数据的清理由宿主安排。

错误可用 `errors.Is` 匹配。常见错误包括 `ErrInvalidEmail` / `ErrInvalidInput`、`ErrResendTooSoon` / `ErrTooManyRequests`、`ErrChallengeInvalid` / `ErrChallengeMismatch`、`ErrRegistrationDenied`、`ErrUnauthorized`，以及微信和绑定相关的 `ErrWechatCode`、`ErrWechatLogin`、`ErrEmailAccountConflict` 等。错误全集见 [`errors.go`](errors.go)。宿主负责把它们映射到自己的 HTTP 响应。

## 与宿主业务共用事务

普通 `Service` 方法自行管理事务。注册时若需同时消费邀请、建立业务关系等，宿主应开启 **READ COMMITTED** 事务，将同一个 `tx` 交给 `authmysql.Bind(tx)` 和业务仓储，再调用 `service.InTransaction(repos, policy)`。这里的 `policy` 替代服务创建时传入的策略，也必须使用同一个事务处理写入。

`Transaction.LoginEmail`、`LoginWechat`、`BindEmail` 返回 `(authkit.Outcome, error)`：

1. `error != nil`：回滚事务。
2. `Outcome.Rejected != nil`：跳过其他业务写入并提交事务，以保留错误验证码的尝试次数；提交后向客户端返回拒绝原因。
3. `Outcome.Login != nil`：完成宿主业务写入并提交；**只在提交成功后**交付 `Outcome.Login.Token`。

微信流程先在事务外调用 `ExchangeWechat`，再将返回的 `WechatIdentity` 传给 `Transaction.LoginWechat`，避免持锁期间请求微信接口。完整可编译示例见 [`examples/hosttx/login.go`](examples/hosttx/login.go)。`InTransaction` 本身不开启或提交事务。

## 内置超管后台

宿主先创建一个已有邮箱绑定的账号，再把它在 `auth_accounts` 中的 ID 作为配置传入。后台沿用邮箱验证码登录，不创建独立密码或超管角色表。所有管理 API 都在服务端用会话 Token 验证账号 ID；登录页面本身可公开访问。ID 为空或格式不符时，`NewHTTPHandler` 会报错；宿主可以选择不挂载后台。

```go
import (
    "net/http"

    "github.com/miebyte/authkit/admin"
)

// service 使用上文创建的实例；adminAccountID 从宿主配置读取。
adminHandler, err := admin.NewHTTPHandler(service, adminAccountID)
if err != nil { return err }
mux := http.NewServeMux()
mux.Handle("/ops/", http.StripPrefix("/ops", adminHandler))
// 将 mux 挂到宿主 HTTP 服务后，访问 /ops/。
```

`http.Handler` 是 Go 接口，无需使用 `*http.Handler`。挂载路径由宿主决定；上例使用 `/ops/`。MySQL 管理查询使用 `service` 已持有的存储，不需要单独创建后台 Store。自定义存储可在同一个存储对象上实现可选的 `authkit.AdminRepository`；未实现时构造后台会返回 `ErrAdminUnavailable`。

后台可查询账号、邮箱及微信绑定状态和有效会话；可解绑非超管账号的邮箱或微信凭据、撤销单个或全部会话。解绑会同时撤销该账号的全部会话，邮箱解绑还会清除待验证的邮箱验证码；不能移除最后一种登录方式。微信 OpenID 的摘要不会显示在页面或管理 API 中。后台不会自行迁移数据库，仍须由宿主执行 `authmysql.Models()` 迁移。建议通过 HTTPS 提供页面；浏览器仅在当前标签会话中保存管理 Token。

## 数据表与开发

默认 Schema 包含 `auth_accounts`、`auth_bindings`、`auth_challenges`、`auth_rates`、`auth_sessions`。账号保存 ID 和可选的 `username`。邮箱和微信 OpenID 都记在 `auth_bindings` 里，用 `method` 区分。模型位于 [`mysql/models`](mysql/models)，宿主通过 `authmysql.Models()` 显式迁移。自定义存储除了实现 [`ports.go`](ports.go) 中的接口，还需满足其锁、唯一性、零值写入及事务语义。

```sh
make check        # go test ./... 和 go vet ./...
make integration  # 启动一次性 MySQL，运行带 race 的集成测试
```

`make integration` 需要本机安装 `mysqld`、`mysqladmin`，会运行 MySQL 与后台的集成测试。普通 `go test ./...` 在未设置 `AUTHKIT_MYSQL_DSN` 时跳过真实 MySQL 测试；也可以把该环境变量指向具有创建和删除测试数据库权限的专用 MySQL 实例，再运行 `go test -race -count=1 ./mysql/... ./admin/...`。
