package wechat

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/miebyte/authkit"
)

const (
	// Namespace 是微信身份的命名空间，与 AppID 和 OpenID 摘要共同确定身份。
	Namespace = "wechat"
	// Method 标记本次通过微信 code 验证身份，供注册策略和宿主业务判断。
	Method = "wechat"
)

// LoginInput 是微信登录的强类型输入，身份必须通过临时 code 在服务端换取。
type LoginInput struct {
	// Code 是客户端通过 wx.login 获取的临时证明，不能用 OpenID 替代。
	Code string
	// RegistrationRef 传递非秘密业务引用，仅在注册时交给宿主策略重新校验。
	RegistrationRef string
}

// BindInput 提供待绑定微信身份的证明，账号归属由独立传入的当前会话确定。
type BindInput struct {
	// Code 用于证明新微信身份，不承载要绑定到哪个账号的决定。
	Code string
}

// Service 先验证微信凭据，再调用共享账号核心完成注册、登录或绑定。
// 插件负责微信验证和身份规范化，账号归属、唯一约束与会话生命周期由核心维护。
type Service struct {
	// core 统一维护身份归属和会话，并完成数据库事务。
	core *authkit.Service
	// exchanger 完成事务外的微信服务端验证。
	exchanger Exchanger
	// registration 仅用于独立 Login 调用；宿主事务需要向核心显式传入自己的策略。
	registration authkit.RegistrationPolicy
}

// NewService 使用账号核心、微信验证器和独立注册策略构造启用的插件。
// core 和 exchanger 必须存在；policy 为 nil 时只允许已有身份登录，首次注册会被拒绝。
func NewService(
	core *authkit.Service,
	exchanger Exchanger,
	policy authkit.RegistrationPolicy,
) (*Service, error) {
	if core == nil {
		return nil, errors.New("authkit/wechat: account service is required")
	}
	if exchanger == nil {
		return nil, ErrUnavailable
	}
	return &Service{core: core, exchanger: exchanger, registration: policy}, nil
}

// ExchangeCode 在数据库事务外验证微信 code，并返回供核心使用的可信身份。
// 宿主可将结果传入 Transaction.LoginVerified 或 BindVerified，以组合自己的事务。
// Scope 使用 AppID 隔离应用，Subject 仅保留 OpenID 的 SHA-256 十六进制摘要。
// VerifiedIdentity 不是签名凭证，禁止直接接收客户端构造的值作为身份所有权证明。
func (s *Service) ExchangeCode(ctx context.Context, code string) (authkit.VerifiedIdentity, error) {
	if strings.TrimSpace(code) == "" || len(code) > 512 {
		return authkit.VerifiedIdentity{}, ErrCode
	}
	identity, err := s.exchanger.ExchangeCode(ctx, code)
	if err != nil {
		return authkit.VerifiedIdentity{}, err
	}
	if !validIdentity(identity) {
		return authkit.VerifiedIdentity{}, ErrLogin
	}
	// 原始 OpenID 只停留在验证边界内；摘要可稳定定位身份，AppID 则保证跨应用隔离。
	sum := sha256.Sum256([]byte(identity.OpenID))
	return authkit.VerifiedIdentity{
		Identity: authkit.IdentityKey{
			Namespace: Namespace,
			Scope:     identity.AppID,
			Subject:   hex.EncodeToString(sum[:]),
		},
		Method: Method,
	}, nil
}

// Login 先交换微信 code，再通过核心事务登录已有账号或按插件策略注册新账号。
// 只有数据库提交成功才返回会话 Token；数据库回滚无法恢复已被微信消费的 code。
func (s *Service) Login(ctx context.Context, input LoginInput) (*authkit.LoginResult, error) {
	verified, err := s.ExchangeCode(ctx, input.Code)
	if err != nil {
		return nil, err
	}
	verified.RegistrationRef = input.RegistrationRef
	return s.core.LoginVerified(ctx, verified, s.registration)
}

// Bind 证明新微信身份后，将其绑定到 currentToken 对应的账号。
// 核心会重新确认会话有效性，拒绝跨账号合并或同范围身份替换；成功时只轮换当前会话。
func (s *Service) Bind(
	ctx context.Context,
	currentToken string,
	input BindInput,
) (*authkit.LoginResult, error) {
	verified, err := s.ExchangeCode(ctx, input.Code)
	if err != nil {
		return nil, err
	}
	return s.core.BindVerified(ctx, currentToken, verified)
}

// validIdentity 校验提供方身份的必要字段、字节长度与首尾空白。
// 即使使用自定义 Exchanger，也要在计算摘要和写入核心索引前拒绝异常身份。
func validIdentity(identity Identity) bool {
	return identity.AppID != "" && len(identity.AppID) <= 64 &&
		strings.TrimSpace(identity.AppID) == identity.AppID &&
		identity.OpenID != "" && len(identity.OpenID) <= 128 &&
		strings.TrimSpace(identity.OpenID) == identity.OpenID
}
