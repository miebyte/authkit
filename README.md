# authkit

`authkit` 是嵌入 Go 服务的身份模块，提供账号密码登录、邮箱验证码登录、微信小程序登录、账号创建和会话管理。宿主负责业务 HTTP 接口、邮件投递、注册准入和业务权限；模块不依赖特定 Web 框架。可选的 `admin` 包提供内置超管后台页面。

- 模块路径：`github.com/miebyte/authkit`
- Go 版本：`1.27.1`（以 `go.mod` 为准）
- 默认存储：基于宿主 `*gorm.DB` 的 MySQL 适配器；也可实现 `ports.go` 中的仓储接口

## 已实现的功能

| 功能 | 行为 |
| --- | --- |
| 账号密码 | 宿主创建或给已有账号设置密码，使用用户名或已绑定邮箱登录 |
| 邮箱验证码 | 邮箱规范化、发码限流、邮件投递后激活验证码、验证并登录或注册 |
| 微信小程序登录 | 服务端用 `wx.login` code 调用 `code2Session`，按 OpenID 识别账号 |
| 账号创建 | 新账号在创建时写入密码、邮箱或微信初始登录凭证，不合并不同登录方式的账号 |
| 注册准入 | 创建新账号前调用宿主策略，可在同一事务内验证或消费邀请等业务数据 |
| 会话 | 创建、认证、退出单个会话；数据库仅保存 Token 摘要 |
| 黑名单 | 按用户名、邮箱或微信 OpenID 限制发码、注册、登录及会话认证，可在超管后台管理 |
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

`sender` 实现 `SendCode(ctx context.Context, email, code string) error`，由宿主决定邮件内容和供应商。不启用邮箱发码时可传入 `nil`，此时 `SendCode` 返回 `ErrEmailUnavailable`。`policy` 实现 `Authorize(ctx context.Context, registration authkit.Registration) error`；仅创建新账号时调用。`Registration` 包含新账号 `Account` 和 `Method`（`"password"`、`"email"` 或 `"wechat"`）。传入 `nil` 会拒绝新注册（`ErrRegistrationDenied`），已有账号仍可登录。若宿主确实允许开放注册，可显式传入返回 `nil` 的 `authkit.RegistrationPolicyFunc`。不启用微信时，将 `exchanger` 设为 `nil`。

### 账号密码登录

账号创建和设密由已完成授权的宿主流程调用，不应直接作为公开注册或重置密码接口暴露。创建账号会执行注册准入，不创建会话：

```go
account, err := service.CreatePasswordAccount(ctx, authkit.CreatePasswordAccountInput{
    Username: "alice",
    Password: initialPassword,
})
```

给已有邮箱或微信账号首次开通密码时，提供用户名；用户名确定后不可修改。重置密码可省略用户名，填写时必须与原用户名一致。开通或重置都会撤销账号的全部会话：

```go
err := service.SetPassword(ctx, authkit.SetPasswordInput{
    AccountID: existingAccountID,
    Username:  "alice",
    Password:  initialPassword,
})
err = service.SetPassword(ctx, authkit.SetPasswordInput{
    AccountID: existingAccountID,
    Password:  newPassword,
})

login, err := service.LoginPassword(ctx, authkit.PasswordLoginInput{
    Identifier: "alice",
    Password:   password,
    IP:         clientIP,
})
```

用户名去除首尾空白后必须为 3–64 个 Unicode 字符，不允许内部空白、控制字符或 `@`，区分大小写且全局唯一；解绑密码后仍保留用户名。密码必须为 8–128 个 Unicode 字符，保留输入原文，不要求字符组合。存储使用 Argon2id（19 MiB 内存、2 次迭代、并行度 1），随机盐与版本、参数一同写入摘要；密码和摘要不进入账号对象、管理 API 或日志。

`Identifier` 含 `@` 时按邮箱规范化并查找已有邮箱绑定，否则按用户名查找。邮箱只是该账号的登录别名，必须已通过现有邮箱验证码流程验证并绑定；`SetPassword` 不添加邮箱绑定，也不合并账号。解绑邮箱后，该邮箱立即失去密码登录能力。未知账号、未开通密码和密码错误统一返回 `ErrInvalidCredentials`。

密码登录不自动注册。独立的固定一小时限流窗口内，每账号最多尝试 20 次、每 IP 最多 100 次；成功和失败均计数，用户名与邮箱别名共用账号额度。`PasswordLoginInput.IP` 由宿主根据可信代理配置取得；空值会共用一个 IP 限流桶。HTTP 接入示例提供 `POST /auth/password/login`，请求体为 `{ "identifier": "alice", "password": "..." }`，见 [`examples/api`](examples/api)。

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

`SendCodeInput.IP` 由宿主根据可信代理配置取得；空值会让这类请求共用同一个 IP 限流桶。`LoginResult` 包含 `Account`、明文 `Token`、`Expires` 和 `Created`。账号 ID 和 Token 均为 256 位随机值，编码成 64 个十六进制字符。Token 只在创建会话时返回；`Logout` 仅撤销传入的会话，重复退出可安全重试。

### 微信登录

小程序把 `wx.login` 返回的 code 传给宿主，宿主调用：

```go
login, err := service.LoginWechat(ctx, wxCode)
```

微信首次登录会创建独立账号，其 `Account.Email` 为空字符串。邮箱账号与微信账号不会自动合并。不要把客户端提供的 OpenID 当作已验证身份；需要在宿主事务中登录时，先调用 `service.ExchangeWechat(ctx, wxCode)`。

### 用户名、邮箱与微信黑名单

超管后台的“黑名单”页面支持添加、分页查看和解除限制，也可以由宿主在完成管理员鉴权后直接调用：

```go
err := service.AddBlacklist(ctx, authkit.Credential{
    Method:     authkit.MethodEmail,
    Identifier: "blocked@example.com",
})
err = service.AddBlacklist(ctx, authkit.Credential{
    Method:     authkit.MethodPassword,
    Identifier: "alice",
})
err = service.AddBlacklist(ctx, authkit.Credential{
    Method:     authkit.MethodWechat,
    Identifier: openID, // 传入原始 OpenID，模块会计算摘要。
})
entries, err := service.ListBlacklist(ctx, 1, 20)
if err == nil && len(entries.Items) > 0 {
    err = service.RemoveBlacklist(ctx, entries.Items[0].ID)
}
```

用户名沿用密码登录的规范化规则，以 `MethodPassword` 表示；邮箱沿用登录时的去空白、转小写规则；OpenID 区分大小写，必须与微信服务端返回的值完全一致，不按 AppID 划分。可以提前拉黑尚未注册的凭证。加入黑名单会清除该邮箱的验证码并撤销关联账号的全部会话；账号任一凭据被拉黑后，也不能通过其他方式登录或认证已有会话。核心检查覆盖 `Service` 和宿主事务中的 `Transaction` 登录入口。操作重复执行可安全重试，解除后需重新获取验证码或登录，已撤销的会话不会恢复。

登录、发码或认证命中黑名单时可用 `errors.Is(err, authkit.ErrBlacklisted)` 判断，建议映射为 HTTP 403。被撤销的旧 Token 返回 `ErrUnauthorized`。微信 OpenID 仅以摘要持久化，列表隐藏该摘要，通过条目 ID 解除。后台禁止拉黑配置的管理员账号，返回 `ErrProtectedAccount`；宿主直接调用 `AddBlacklist` 时自行决定管理权限。

升级后需再次执行 `db.AutoMigrate(authmysql.Models()...)`，创建 `auth_blacklist` 表。自定义存储需实现 `Repositories.Blacklist()` 和 `BlacklistRepository`：凭证检查与添加必须共用排他锁，账号检查与会话撤销必须锁定同一账号行，全部写入遵守调用方事务，避免并发登录留下可在解除后恢复的旧会话。未被拉黑的占位记录仅用于串行化检查，不显示在黑名单列表中。

## 验证码、身份与错误

- 邮箱会去除首尾空白并转小写。验证码是六位数字，有效期 10 分钟；同一邮箱只保留当前验证码，最多允许 5 次错误尝试。
- 60 秒内不能向同一邮箱重发。自首次请求起的固定一小时窗口内，每邮箱最多发送 10 次、每 IP 最多 30 次。
- 验证码先保存为不可用状态；邮件发送成功后才激活。投递失败的验证码不能登录，但发码次数与重发冷却仍保留。
- 微信只把 OpenID 当作登录凭证，入库前取摘要，不保存 AppID、UnionID 或 `session_key`。同一个 OpenID 只能绑定一个账号。
- 会话有效期为 30 天，不自动续期；过期会话不能认证。过期数据的清理由宿主安排。

错误可用 `errors.Is` 匹配。常见错误包括 `ErrInvalidEmail` / `ErrInvalidInput`、`ErrInvalidCredentials`、`ErrResendTooSoon` / `ErrTooManyRequests`、`ErrChallengeInvalid` / `ErrChallengeMismatch`、`ErrRegistrationDenied`、`ErrBlacklisted`、`ErrUnauthorized`、`ErrEmailUnavailable`、`ErrWechatCode` 和 `ErrWechatLogin`。建议将 `ErrInvalidCredentials` 映射为 HTTP 401，将 `ErrEmailUnavailable` 映射为 HTTP 503；完整示例见 [`examples/api/http.go`](examples/api/http.go)。错误全集见 [`errors.go`](errors.go)。

## 与宿主业务共用事务

普通 `Service` 方法自行管理事务。注册时若需同时消费邀请、建立业务关系等，宿主应开启 **READ COMMITTED** 事务，将同一个 `tx` 交给 `authmysql.Bind(tx)` 和业务仓储，再调用 `service.InTransaction(repos, policy)`。这里的 `policy` 替代服务创建时传入的策略，也必须使用同一个事务处理写入。

`Transaction.LoginEmail`、`LoginWechat`、`LoginPassword` 返回 `(authkit.Outcome, error)`：

1. `error != nil`：回滚事务。
2. `Outcome.Rejected != nil`：跳过其他业务写入并提交事务，以保留错误验证码的尝试次数或密码登录限流计数；提交后向客户端返回拒绝原因。
3. `Outcome.Login != nil`：完成宿主业务写入并提交；**只在提交成功后**交付 `Outcome.Login.Token`。

`Transaction.CreatePasswordAccount` 和 `SetPassword` 与对应 `Service` 方法具有相同输入与返回值，可把可信账号创建、设密和宿主写入一起提交或回滚。微信流程先在事务外调用 `ExchangeWechat`，再将返回的 `WechatIdentity` 传给 `Transaction.LoginWechat`，避免持锁期间请求微信接口。完整可编译示例见 [`examples/hosttx/login.go`](examples/hosttx/login.go)。`InTransaction` 本身不开启或提交事务。

## 内置超管后台

宿主先创建一个可通过密码或邮箱验证码登录的账号，再把它在 `auth_accounts` 中的 ID 作为配置传入。后台登录页支持“账号密码”和“邮箱验证码”切换，复用账号现有凭据，不创建超管角色表。密码登录接口为 `POST /api/password/login`，请求体为 `{ "identifier": "alice", "password": "..." }`，路径随后台挂载前缀变化。`AdminLoginPassword` 在创建会话前核对配置的超管 ID；普通账号返回 `ErrInvalidCredentials`，保留限流计数且不创建会话。所有管理 API 都在服务端用会话 Token 验证账号 ID；登录页面本身可公开访问。ID 为空或格式不符时，`NewHTTPHandler` 会报错；宿主可以选择不挂载后台。

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

`http.Handler` 是 Go 接口，无需使用 `*http.Handler`。挂载路径由宿主决定；上例使用 `/ops/`。MySQL 管理查询使用 `service` 已持有的存储，不需要单独创建后台 Store。`authkit.Store` 必须实现 `authkit.AdminRepository`，自定义存储需在同一个存储对象上提供管理能力。

左上角品牌名默认是 `AuthKit`。需要显示宿主名称时，可传入 `admin.Config{Title: "我的应用"}` 作为 `NewHTTPHandler` 的第三个参数；登录页、侧栏和浏览器标签标题会使用该名称。

超管界面使用 Vue 3 和 TypeScript，源码位于 `admin/frontend`。概览、账号管理与黑名单分别对应 `/ops/overview`、`/ops/accounts`、`/ops/blacklist`，可直接打开和刷新；实际前缀随宿主挂载路径变化。构建资源位于 `admin/assets`，随 Go 包内嵌，使用 Go 包时无需安装 Node.js。修改前端后使用 Node.js 22.12 或更新版本运行 `make admin-ui`，并提交更新后的内嵌资源。

后台可查询账号、密码开通状态、邮箱及微信绑定状态和有效会话；可解绑非超管账号的密码、邮箱或微信凭据、撤销单个或全部会话。解绑会同时撤销该账号的全部会话，密码解绑保留用户名，邮箱解绑还会清除待验证的邮箱验证码；不能移除最后一种登录方式。后台不提供设密、改密或忘记密码页面。微信 OpenID 和密码摘要不会显示在页面或管理 API 中。后台不会自行迁移数据库，仍须由宿主执行 `authmysql.Models()` 迁移。建议通过 HTTPS 提供页面；浏览器仅在当前标签会话中保存管理 Token。

## 数据表与开发

默认 Schema 包含 `auth_accounts`、`auth_bindings`、`auth_challenges`、`auth_rates`、`auth_sessions`、`auth_blacklist`。账号保存 ID 和可选的 `username`。密码、邮箱和微信 OpenID 都记在 `auth_bindings` 里，用 `method` 区分；密码绑定以用户名为 `identifier`，摘要写入可空 `password_hash` 列。升级密码登录功能前，宿主须执行 `db.AutoMigrate(authmysql.Models()...)`；已有账号不会自动获得密码。

模型位于 [`mysql/models`](mysql/models)。自定义存储需实现 [`ports.go`](ports.go) 中的账号 ID／用户名查询、首次用户名赋值、按账号撤销会话和管理接口；密码摘要读写由 `AccountRepository.GetPasswordHash` 与 `SetPasswordHash` 提供。仓储必须满足其锁、唯一性、零值写入及事务语义。密码登录、设密和解绑需锁定同一账号行，先锁黑名单凭证再锁账号；锁内重新读取邮箱绑定与密码摘要，验证后创建会话，保证重置、解绑或拉黑并发时不能遗留有效旧会话。

```sh
make check        # go test ./... 和 go vet ./...
make integration  # 启动一次性 MySQL，运行带 race 的集成测试
```

`make integration` 需要本机安装 `mysqld`、`mysqladmin`，会运行 MySQL 与后台的集成测试。普通 `go test ./...` 在未设置 `AUTHKIT_MYSQL_DSN` 时跳过真实 MySQL 测试；也可以把该环境变量指向具有创建和删除测试数据库权限的专用 MySQL 实例，再运行 `go test -race -count=1 ./mysql/... ./admin/...`。
