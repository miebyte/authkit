# authkit

`authkit` 是嵌入 Go 服务的账号认证模块。核心管理账号、登录身份和会话；邮箱验证码、微信小程序各自作为插件接入。宿主负责 HTTP 路由、邮件投递、注册准入和业务授权。

- 模块路径：`github.com/miebyte/authkit`
- Go 版本：`1.27.1`（以 `go.mod` 为准）
- 默认存储：宿主管理的 MySQL `*gorm.DB`；也可以实现仓储接口

本次重构采用新的 API 和 Schema，不提供旧版接口兼容层或旧数据迁移。已有数据库需要由宿主先制定迁移方案，不能把 `AutoMigrate` 当作旧身份数据的转换工具。

## 账号、身份和验证方式

`User` 只有稳定的 `ID`。`Identity` 用 `IdentityKey{Namespace, Scope, Subject}` 关联账号；`Method` 描述本次如何验证身份。

| 登录方式 | Namespace | Scope | Subject | Method |
| --- | --- | --- | --- | --- |
| 邮箱验证码 | `email` | 空字符串 | 规范化邮箱 | `email_code` |
| 微信小程序 | `wechat` | AppID | OpenID 的 SHA-256 十六进制摘要 | `wechat` |
| 将来的邮箱密码插件 | `email` | 空字符串 | 同一个规范化邮箱 | `password` |

身份与验证方式独立，因此将来邮箱验证码和邮箱密码可以指向同一账号。“内部 / 外部”可以用于界面分类，核心无需据此选择不同的账号逻辑。当前只实现邮箱验证码和微信插件。

同一个身份只能归属一个账号；每个账号在同一 `Namespace + Scope` 内只能绑定一个身份。身份键区分大小写，由插件统一规范化。微信按 AppID 隔离，不使用 UnionID 自动合并账号。

## 按需接入插件

宿主创建 MySQL 连接，连接参数应包含 `parseTime=true&loc=UTC`。`NewStore` 只包装连接，迁移由宿主显式执行。

| 启用配置 | 构造对象 | 迁移模型 |
| --- | --- | --- |
| 仅邮箱 | 核心 + 邮箱存储 + 邮件发送器 + 邮箱插件 | `authmysql.Models()`、`emailmysql.Models()` |
| 仅微信 | 核心 + 微信客户端 + 微信插件 | `authmysql.Models()` |
| 两者共同启用 | 共用一个核心，分别构造两个插件 | `authmysql.Models()`、`emailmysql.Models()` |

下面三个函数可按启动配置组合。仅为启用的插件注册对应 HTTP 路由；不需要中央方法分派器。

```go
import (
    "context"

    "github.com/miebyte/authkit"
    "github.com/miebyte/authkit/email"
    emailmysql "github.com/miebyte/authkit/email/mysql"
    authmysql "github.com/miebyte/authkit/mysql"
    "github.com/miebyte/authkit/wechat"
    "gorm.io/gorm"
)

func newCore(db *gorm.DB) (*authkit.Service, error) {
    if err := db.AutoMigrate(authmysql.Models()...); err != nil {
        return nil, err
    }
    store, err := authmysql.NewStore(db)
    if err != nil {
        return nil, err
    }
    return authkit.NewService(store)
}

func enableEmail(
    db *gorm.DB,
    core *authkit.Service,
    sender email.CodeSender,
    policy authkit.RegistrationPolicy,
) (*email.Service, error) {
    if err := db.AutoMigrate(emailmysql.Models()...); err != nil {
        return nil, err
    }
    store, err := emailmysql.NewStore(db)
    if err != nil {
        return nil, err
    }
    return email.NewService(core, store, sender, policy)
}

func enableWechat(
    core *authkit.Service,
    config wechat.Config,
    policy authkit.RegistrationPolicy,
) (*wechat.Service, error) {
    client, err := wechat.New(config)
    if err != nil {
        return nil, err
    }
    return wechat.NewService(core, client, policy)
}
```

例如仅邮箱时依次调用 `newCore` 和 `enableEmail`；仅微信时调用 `newCore` 和 `enableWechat`。共同启用时两个插件传入同一个核心，邮箱存储使用该核心所连接的同一数据库。无需配置或初始化未启用插件的发送器、客户端和数据表。

`email.CodeSender` 实现 `SendCode(ctx context.Context, address, code string) error`，邮件模板和供应商由宿主管理。`wechat.Config{AppID, Secret}` 只在服务端保存；未启用微信时不构造微信插件。

### 注册准入

两个插件分别持有自己的 `authkit.RegistrationPolicy`。只有首次创建账号时才调用 `Authorize(ctx, registration)`；`Registration` 包含新账号 `User`、规范化 `Identity`、本次验证 `Method` 和宿主 `Reference`。

传 `nil` 会拒绝新注册并返回 `authkit.ErrRegistrationDenied`，已有身份仍可登录。明确允许开放注册时，可传入：

```go
policy := authkit.RegistrationPolicyFunc(
    func(context.Context, authkit.Registration) error { return nil },
)
```

`RegistrationRef` 只传递非秘密引用，例如邀请摘要或审批记录 ID。邮箱登录显式传入非空引用时，覆盖发码时保存的引用。宿主负责限制引用长度并重新校验，不应把引用本身当作已通过的授权。需要消费邀请等业务写入时，使用下面的宿主事务接入。

## 登录、绑定和会话

HTTP 入口接收各插件的强类型输入。以下独立函数展示关键调用，宿主将错误映射为自己的响应：

```go
func sendEmailCode(ctx context.Context, plugin *email.Service, address, ip string) error {
    return plugin.SendCode(ctx, email.SendCodeInput{Email: address, IP: ip})
}

func loginEmail(ctx context.Context, plugin *email.Service, address, code string) (*authkit.LoginResult, error) {
    return plugin.Login(ctx, email.LoginInput{Email: address, Code: code})
}

func loginWechat(ctx context.Context, plugin *wechat.Service, code string) (*authkit.LoginResult, error) {
    return plugin.Login(ctx, wechat.LoginInput{Code: code})
}
```

`Login` 首次登录时按策略注册，之后复用该身份的账号。`LoginResult` 包含 `User`、明文 `Token`、`Expires`、`Created`；独立调用成功返回时事务已经提交。微信输入只有 `wx.login` 得到的临时 code，插件在服务端交换并验证身份。

### 显式绑定另一种登录方式

需要两种方式共用一个账号时，**先用已有方式登录，再调用另一插件的 `Bind`**：

```go
func bindWechat(ctx context.Context, plugin *wechat.Service, currentToken, code string) (*authkit.LoginResult, error) {
    return plugin.Bind(ctx, currentToken, wechat.BindInput{Code: code})
}

func bindEmail(ctx context.Context, plugin *email.Service, currentToken, address, code string) (*authkit.LoginResult, error) {
    return plugin.Bind(ctx, currentToken, email.BindInput{Email: address, Code: code})
}
```

邮箱账号可绑定微信，微信账号可在收取验证码后绑定邮箱。绑定成功保持 UserID，返回新 Token 并撤销传入的旧 Token，其他设备会话保留。重复绑定同一身份也会轮换当前会话，但不会新增身份记录。

分别通过两种方式注册，会产生两个独立账号，之后绑定返回 `authkit.ErrIdentityConflict`，不会自动合并。账号已拥有另一个同范围身份时返回 `authkit.ErrIdentityBound`，不能直接替换。当前不提供解绑、身份替换和账号合并。

### 查询当前账号与身份

```go
func currentIdentities(ctx context.Context, core *authkit.Service, token string) ([]authkit.Identity, error) {
    user, err := core.Authenticate(ctx, token)
    if err != nil {
        return nil, err
    }
    return core.ListIdentities(ctx, user.ID)
}

func logout(ctx context.Context, core *authkit.Service, token string) error {
    return core.Logout(ctx, token)
}
```

`User.Email` 已移除；需要邮箱时，从 `ListIdentities` 返回值中查找 `Key.Namespace == "email"` 且 `Key.Scope == ""` 的身份，读取 `Key.Subject`。`ListIdentities` 不检查访问权限，宿主必须验证调用者有权查看目标账号。

`Authenticate` 只确认登录身份，业务权限仍由宿主检查。账号 ID 与 Token 都是 256 位随机值，编码成 64 个十六进制字符；数据库仅保存 Token 摘要。会话有效期为 30 天，不自动续期。`Logout` 只撤销传入会话，重复调用可安全重试。

## 与宿主业务共用事务

需要账号、会话、邀请消费和业务写入一起提交时，宿主开启 **READ COMMITTED** 事务，再使用：

- 核心：`core.InTransaction(authmysql.Bind(tx), policy)`。
- 邮箱：`emailPlugin.InTransaction(coreTx, emailmysql.Bind(tx))` 的 `Login` 或 `Bind`。
- 微信：在事务外先调用 `wechatPlugin.ExchangeCode(ctx, code)`，将验证结果及 `RegistrationRef` 传给 `coreTx.LoginVerified`，或传给 `coreTx.BindVerified`。

核心与邮箱仓储、业务仓储及注册策略必须绑定同一个 `tx`。此时注册策略必须显式传给 `core.InTransaction`；不会继承插件的独立调用策略，传 `nil` 仍然拒绝新注册。`InTransaction` 本身不开启、提交或回滚事务。

事务方法返回 `(authkit.Outcome, error)`，宿主必须遵守：

1. `error != nil`：回滚全部写入。
2. `Outcome.Rejected != nil`：跳过其他业务写入，提交验证码失败次数，然后向客户端返回拒绝原因。
3. 成功结果：完成宿主业务写入并提交，**只在提交成功后**交付 `Outcome.Login.Token`。

完整可编译示例见 [`examples/hosttx/login.go`](examples/hosttx/login.go)。邮箱适配器在独立调用时也保证验证码校验、消费与核心写入处于同一事务；微信网络请求始终先于核心事务。

`VerifiedIdentity` 是可信后端插件的调用协议，不是签名凭证。**禁止直接从 HTTP 请求解码它，或把客户端提供的 OpenID、邮箱当作已验证身份调用 `LoginVerified` / `BindVerified`。** 客户端必须通过插件入口提供验证码、授权 code 等证明。

## 错误和验证规则

使用 `errors.Is` 匹配错误；通用账号错误在核心包，验证方式自己的错误在插件包：

| 包 | 常见错误 |
| --- | --- |
| `authkit` | `ErrInvalidInput`、`ErrUnauthorized`、`ErrRegistrationDenied`、`ErrIdentityConflict`、`ErrIdentityBound`、`ErrConflict` |
| `email` | `ErrInvalidEmail`、`ErrResendTooSoon`、`ErrTooManyRequests`、`ErrChallengeInvalid`、`ErrChallengeMismatch`、`ErrChallengeUpdated`、`ErrMailFailed` |
| `wechat` | `ErrUnavailable`、`ErrCode`、`ErrLogin` |

- 邮箱去除首尾空白并转小写。验证码为六位数字，有效期 10 分钟，同一邮箱只保留当前验证码，最多允许 5 次错误尝试。
- 同一邮箱重发间隔 60 秒。自首次请求起的固定一小时窗口内，每邮箱最多发送 10 次，每 IP 最多 30 次。`SendCodeInput.IP` 由宿主按可信代理配置取得，空 IP 会共用一个限流桶。
- 邮件发送成功后才激活验证码。投递失败保留冷却和发码计数，验证码不可用；正确验证码遇到注册拒绝、绑定冲突或业务回滚时不会被消费。
- 微信 HTTP 交换有超时、响应大小限制和错误脱敏，不保存 `session_key`；OpenID 只以摘要形式进入核心。微信授权 code 已在外部消费后，数据库回滚无法恢复该 code，重试需获取新的 code。
- 过期会话、验证码和限流数据的清理由宿主安排。

## 扩展新的登录插件

新增插件只需要实现自己的强类型输入、凭证验证和身份规范化，验证成功后调用核心的 `LoginVerified` / `BindVerified`。无需修改核心方法、中央路由或核心表结构。

选择稳定的 `Namespace + Scope + Subject` 表示身份，单独用 `Method` 表示验证方式。同一邮箱的其他验证方式应复用 `email` 命名空间、空 Scope 和 `email.NormalizeEmail`；外部提供方使用自己的命名空间，以应用或租户等作为需要隔离的 Scope。Namespace、Scope、Subject 的最大字节长度分别为 64、255、254，Method 最长 64 字节；文本须为合法 UTF-8，不能有首尾空白。

外部网络验证应在数据库事务外完成，再传入可信结果。若插件有必须原子消费的本地凭证，则仿照邮箱插件，让存储事务回调同时提供核心与插件仓储；不要把事务藏进 `context` 或 `any`。插件单独维护自己的凭证表、错误和验证规则。手机号、密码、Google 等验证尚未实现。

## 数据表与开发验证

核心 `authmysql.Models()` 只包含 `auth_users`、`auth_identities`、`auth_sessions`。邮箱 `emailmysql.Models()` 额外包含 `auth_challenges`、`auth_rates`。微信插件不需要专用身份表。

`auth_identities` 按 `(namespace, scope, subject)` 唯一，并按 `(user_id, namespace, scope)` 限制每个账号同范围只能绑定一个身份。Scope 不允许为 `NULL`，邮箱使用空字符串；尚未归属的身份占位行使用可空 UserID。MySQL 身份键使用 `VARBINARY` 以保持精确匹配。并发首次登录通过身份占位行锁串行化，核心加锁顺序为身份、账号、会话。

自定义存储需满足 [`ports.go`](ports.go) 的锁、唯一约束及事务契约。邮箱存储接口见 [`email/ports.go`](email/ports.go)。

```sh
make check        # go test ./... 和 go vet ./...
make integration  # 一次性 MySQL 实例，运行带 race 的并发集成测试
```

`make integration` 需要本机安装 `mysqld`、`mysqladmin`。未设置 `AUTHKIT_MYSQL_DSN` 时，普通测试会跳过真实 MySQL 测试。也可让该变量指向具有创建、删除测试数据库权限的专用实例，再运行 `go test -race -count=1 ./mysql/...`。
