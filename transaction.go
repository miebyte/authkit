package authkit

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"
)

// Transaction 在调用方拥有的事务内执行身份操作。
// 结果，尤其是明文令牌，在调用方提交之前都只是暂定的。
type Transaction struct {
	repos             Repositories
	registration      RegistrationPolicy
	now               func() time.Time
	passwordAlgorithm PasswordAlgorithm
	sessionTTL        time.Duration
}

// codeLogin 表示一次验证码登录，与投递渠道无关。
type codeLogin struct {
	method string
	target string
	code   string
}

// emailCodeLogin 把邮箱登录规范化为共用的验证码登录输入。
func emailCodeLogin(input EmailLoginInput) (codeLogin, error) {
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return codeLogin{}, err
	}
	return codeLogin{method: MethodEmail, target: email, code: input.Code}, nil
}

// LoginEmail 消费有效的邮箱证明，并为已准入的账号开启会话。
func (t *Transaction) LoginEmail(ctx context.Context, input EmailLoginInput) (Outcome, error) {
	login, err := emailCodeLogin(input)
	if err != nil {
		return Outcome{}, err
	}
	return t.loginCode(ctx, login)
}

// loginCode 消费有效的验证码证明，并为已准入的账号开启会话。
func (t *Transaction) loginCode(ctx context.Context, input codeLogin) (Outcome, error) {
	if !validCode(input.code) {
		return Outcome{}, ErrInvalidInput
	}
	if err := t.repos.Blacklist().
		Check(ctx, Credential{Method: input.method, Identifier: input.target}); err != nil {
		return Outcome{}, err
	}
	// 先锁账号再锁验证码，与后台解绑及拉黑操作保持相同顺序。
	if err := checkEmailAccount(ctx, t.repos, input.target); err != nil {
		return Outcome{}, err
	}
	now := t.now().UTC()
	challenge, rejected, err := t.verifyCode(ctx, input.target, input.code, now)
	if err != nil || rejected != nil {
		return Outcome{Rejected: rejected}, err
	}
	user, err := t.findCodeAccount(ctx, input)
	created := errors.Is(err, ErrNotFound)
	if err != nil && !created {
		return Outcome{}, err
	}
	passwordAccount, passwordErr := t.repos.Accounts().GetByPasswordIdentifier(ctx, input.target)
	if passwordErr != nil && !errors.Is(passwordErr, ErrNotFound) {
		return Outcome{}, passwordErr
	}
	if passwordAccount != nil && (created || passwordAccount.ID != user.ID) {
		return Outcome{}, ErrConflict
	}
	// 如果账号不存在，则创建账号
	if created {
		var account *Account
		account, err = newCodeAccount(input)
		if err == nil {
			user, err = t.createAccount(
				ctx,
				account,
				Credential{
					Method:     input.method,
					Identifier: input.target,
				},
			)
		}
	}
	if err != nil {
		return Outcome{}, err
	}
	return t.finishLogin(ctx, user, input.method, challenge, created, now)
}

// findCodeAccount 加载已经绑定到该验证码目标的账号。
func (t *Transaction) findCodeAccount(ctx context.Context, input codeLogin) (*Account, error) {
	switch input.method {
	case MethodEmail:
		return t.repos.Accounts().GetByEmail(ctx, input.target)
	default:
		return nil, ErrInvalidInput
	}
}

// newCodeAccount 为尚无所有者的验证码渠道构造一个未保存的账号。
func newCodeAccount(input codeLogin) (*Account, error) {
	switch input.method {
	case MethodEmail:
		return &Account{Email: input.target}, nil
	default:
		return nil, ErrInvalidInput
	}
}

// LoginWechat 使用经服务端核验的身份登录或创建账号。
func (t *Transaction) LoginWechat(
	ctx context.Context,
	subject WechatIdentity,
) (Outcome, error) {
	if !validWechatIdentity(subject) {
		return Outcome{}, ErrWechatLogin
	}
	now := t.now().UTC()
	openIDHash := digest(subject.OpenID)
	if err := t.repos.Blacklist().
		Check(ctx, Credential{Method: MethodWechat, Identifier: openIDHash}); err != nil {
		return Outcome{}, err
	}
	user, err := t.repos.Accounts().GetByWechat(ctx, openIDHash)
	created := errors.Is(err, ErrNotFound)
	if err != nil && !created {
		return Outcome{}, err
	}
	if created {
		user, err = t.createAccount(ctx, &Account{}, Credential{
			Method: MethodWechat, Identifier: openIDHash,
		})
		if err != nil {
			return Outcome{}, err
		}
	}
	return t.finishLogin(ctx, user, MethodWechat, nil, created, now)
}

// verifyCode 把预期的证明失败单独返回，以便尝试次数能够提交。
func (t *Transaction) verifyCode(
	ctx context.Context,
	target, code string,
	now time.Time,
) (*Challenge, error, error) {
	challenge, err := t.repos.Challenges().Find(ctx, target)
	if errors.Is(err, ErrNotFound) {
		// 未知邮箱没有尝试次数需要提交，回滚凭证检查产生的占位。
		return nil, nil, ErrChallengeInvalid
	}
	if err != nil {
		return nil, nil, err
	}
	if !challenge.Ready || !now.Before(challenge.Expires) || challenge.Attempts >= MaxAttempts {
		return nil, ErrChallengeInvalid, nil
	}
	challenge.Attempts++
	if subtle.ConstantTimeCompare([]byte(challenge.Hash), []byte(digest(target+code))) != 1 {
		return nil, ErrChallengeMismatch, t.repos.Challenges().Save(ctx, challenge)
	}
	return challenge, nil, nil
}

// createAccount 在持久化账号之前要求明确的准入决定。
func (t *Transaction) createAccount(
	ctx context.Context,
	account *Account,
	credential Credential,
) (*Account, error) {
	if t.registration == nil {
		return nil, ErrRegistrationDenied
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}

	account.ID = id
	err = t.registration.Authorize(ctx, Registration{Account: *account, Method: credential.Method})
	if err != nil {
		return nil, err
	}

	err = t.repos.Accounts().Create(ctx, account, credential)
	if err != nil {
		return nil, err
	}

	return account, nil
}

// CreatePasswordAccount 在宿主事务内创建密码账号，返回值须在提交后使用。
func (t *Transaction) CreatePasswordAccount(
	ctx context.Context,
	input CreatePasswordAccountInput,
) (*Account, error) {
	identifier, err := NormalizeUsername(input.Identifier)
	if err != nil || !t.passwordAlgorithm.validPassword(input.Password, 8) ||
		!validDisplayName(input.Username) {
		return nil, ErrInvalidInput
	}

	hash, err := t.passwordAlgorithm.hashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	if err := t.checkPasswordEmailOwner(ctx, identifier, ""); err != nil {
		return nil, err
	}
	credential := Credential{Method: MethodPassword, Identifier: identifier}
	if err := t.repos.Blacklist().Check(ctx, credential); err != nil {
		return nil, err
	}

	account, err := t.createAccount(ctx, &Account{Username: input.Username}, credential)
	if err != nil {
		return nil, err
	}

	err = t.repos.Accounts().SetPasswordHash(ctx, account.ID, identifier, hash)
	if err != nil {
		return nil, err
	}
	return account, nil
}

// SetPassword 在宿主事务内维护密码绑定，不修改展示名称；调用方负责账号操作权限。
func (t *Transaction) SetPassword(ctx context.Context, input SetPasswordInput) error {
	if !validToken(input.AccountID) || !t.passwordAlgorithm.validPassword(input.Password, 8) {
		return ErrInvalidInput
	}
	accountID := strings.ToLower(input.AccountID)
	_, err := t.repos.Accounts().GetByID(ctx, accountID)
	if err != nil {
		return err
	}
	identifier := input.Identifier
	if identifier == "" {
		identifier, err = t.repos.Accounts().GetPasswordIdentifier(ctx, accountID)
		if errors.Is(err, ErrNotFound) {
			return ErrInvalidInput
		}
		if err != nil {
			return err
		}
	}
	identifier, err = NormalizeUsername(identifier)
	if err != nil {
		return err
	}

	hash, err := t.passwordAlgorithm.hashPassword(input.Password)
	if err != nil {
		return err
	}

	if err := t.checkPasswordEmailOwner(ctx, identifier, accountID); err != nil {
		return err
	}

	// 检查密码黑名单
	err = t.repos.Blacklist().Check(
		ctx,
		Credential{
			Method:     MethodPassword,
			Identifier: identifier,
		})
	if err != nil {
		return err
	}

	err = t.repos.Blacklist().CheckAccount(ctx, accountID)
	if err != nil {
		return err
	}

	if input.Identifier == "" {
		// 自动读取的绑定可能已被并发解绑，重置不能重新开通密码。
		current, err := t.repos.Accounts().GetPasswordIdentifier(ctx, accountID)
		if errors.Is(err, ErrNotFound) {
			return ErrInvalidInput
		}
		if err != nil {
			return err
		}
		if current != identifier {
			return ErrConflict
		}
	}

	// 账号锁内再次检查密码绑定，防止并发首次设密覆盖另一登录标识。
	err = t.repos.Accounts().SetPasswordHash(ctx, accountID, identifier, hash)
	if err != nil {
		return err
	}

	return t.repos.Sessions().DeleteByAccount(ctx, accountID)
}

// checkPasswordEmailOwner 与邮箱注册共用凭证锁，拒绝把同邮箱的两种登录方式分配给不同账号。
func (t *Transaction) checkPasswordEmailOwner(
	ctx context.Context,
	identifier, accountID string,
) error {
	if !strings.Contains(identifier, "@") {
		return nil
	}
	if err := t.repos.Blacklist().
		Check(ctx, Credential{Method: MethodEmail, Identifier: identifier}); err != nil {
		return err
	}
	account, err := t.repos.Accounts().GetByEmail(ctx, identifier)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if account.ID != accountID {
		return ErrConflict
	}
	return nil
}

// LoginPassword 在宿主事务内验证密码；Rejected 必须提交以保留尝试次数。
func (t *Transaction) LoginPassword(
	ctx context.Context,
	input PasswordLoginInput,
) (Outcome, error) {
	return t.loginPassword(ctx, input, "")
}

// loginPassword 在账号锁内读取并验证当前密码，再创建允许交付的会话。
func (t *Transaction) loginPassword(
	ctx context.Context,
	input PasswordLoginInput,
	requiredAccountID string,
) (Outcome, error) {
	if !validPassword(input.Password, 1) || len(input.IP) > 512 {
		return Outcome{}, ErrInvalidInput
	}
	identifier, err := NormalizeUsername(input.Identifier)
	if err != nil {
		return Outcome{}, err
	}
	credential := Credential{Method: MethodPassword, Identifier: identifier}
	account, err := t.repos.Accounts().GetByPasswordIdentifier(ctx, identifier)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Outcome{}, err
	}
	// 已有密码绑定按账号 ID 限流，未知标识也保留自己的尝试次数。
	rateKey := "password-identifier:" + credential.Method + ":" + credential.Identifier
	if account != nil {
		rateKey = "password-account:" + account.ID
	}
	now := t.now().UTC()
	if err := t.repos.Rates().
		Hit(ctx, digest("password-ip:"+input.IP), now, PasswordIPRateLimit); err != nil {
		return passwordRejection(err)
	}
	if err := t.repos.Rates().Hit(ctx, digest(rateKey), now, PasswordAccountRateLimit); err != nil {
		return passwordRejection(err)
	}
	if err := t.repos.Blacklist().Check(ctx, credential); err != nil {
		return passwordRejection(err)
	}
	if account == nil {
		return rejectPasswordCredentials(input.Password, t.passwordAlgorithm)
	}
	if err := t.repos.Blacklist().CheckAccount(ctx, account.ID); err != nil {
		return passwordRejection(err)
	}
	account, err = t.repos.Accounts().GetByID(ctx, account.ID)
	if errors.Is(err, ErrNotFound) {
		return rejectPasswordCredentials(input.Password, t.passwordAlgorithm)
	}
	if err != nil {
		return Outcome{}, err
	}
	identifier, err = t.repos.Accounts().GetPasswordIdentifier(ctx, account.ID)
	if errors.Is(err, ErrNotFound) {
		return rejectPasswordCredentials(input.Password, t.passwordAlgorithm)
	}
	if err != nil {
		return Outcome{}, err
	}
	if identifier != credential.Identifier {
		return rejectPasswordCredentials(input.Password, t.passwordAlgorithm)
	}
	hash, err := t.repos.Accounts().GetPasswordHash(ctx, account.ID)
	if errors.Is(err, ErrNotFound) {
		return rejectPasswordCredentials(input.Password, t.passwordAlgorithm)
	}
	if err != nil {
		return Outcome{}, err
	}
	if !t.passwordAlgorithm.verifyPassword(input.Password, hash) ||
		requiredAccountID != "" && account.ID != requiredAccountID {
		return Outcome{Rejected: ErrInvalidCredentials}, nil
	}
	return t.finishLogin(ctx, account, MethodPassword, nil, false, now)
}

// finishLogin 消费可选的邮箱证明，并持久化令牌摘要和登录绑定方式。
func (t *Transaction) finishLogin(
	ctx context.Context,
	account *Account,
	method string,
	challenge *Challenge,
	created bool,
	now time.Time,
) (Outcome, error) {
	if err := t.repos.Blacklist().CheckAccount(ctx, account.ID); err != nil {
		return Outcome{}, err
	}
	if challenge != nil {
		challenge.Ready = false
		if err := t.repos.Challenges().Save(ctx, challenge); err != nil {
			return Outcome{}, err
		}
	}
	login, err := t.createSession(ctx, account, method, "", now.Add(t.sessionTTL), created)
	return Outcome{Login: login}, err
}

// createSession 为普通登录和代登录统一生成令牌并持久化摘要及绑定方式。
func (t *Transaction) createSession(
	ctx context.Context,
	account *Account,
	method, parentHash string,
	expires time.Time,
	created bool,
) (*LoginResult, error) {
	token, err := newID()
	if err != nil {
		return nil, err
	}
	if err := t.repos.Sessions().Create(ctx, &Session{
		Hash: digest(
			token,
		),
		AccountID:  account.ID,
		Method:     method,
		Expires:    expires,
		ParentHash: parentHash,
	}); err != nil {
		return nil, err
	}
	return &LoginResult{Account: *account, Token: token, Expires: expires, Created: created}, nil
}

// AuthenticateSession 在宿主事务内验证会话及其父会话，返回绑定方式及宿主授权所需的账号。
func (t *Transaction) AuthenticateSession(
	ctx context.Context,
	token string,
) (*AuthenticatedSession, error) {
	return authenticateSession(ctx, t.repos, token, t.now().UTC())
}

// LoginAs 在宿主事务内签发代登录会话；调用前须由宿主完成管理员授权。
// 派生会话不能再次派生，且期限不能超过父会话；调用后授权失败须回滚事务。
func (t *Transaction) LoginAs(
	ctx context.Context,
	parentToken, accountID string,
) (*LoginResult, error) {
	if !validToken(accountID) {
		return nil, ErrInvalidInput
	}
	now := t.now().UTC()
	parent, err := authenticateSession(ctx, t.repos, parentToken, now)
	if err != nil {
		return nil, err
	}
	if parent.Actor != nil {
		return nil, ErrUnauthorized
	}
	account, err := t.repos.Accounts().GetByID(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if err := t.repos.Blacklist().CheckAccount(ctx, account.ID); err != nil {
		return nil, err
	}
	expires := now.Add(t.sessionTTL)
	if parent.Expires.Before(expires) {
		expires = parent.Expires
	}
	return t.createSession(ctx, account, parent.Method, digest(parentToken), expires, false)
}

// authenticateSession 对格式错误的凭证跳过数据库查询，并限制父子关系只有一层。
func authenticateSession(
	ctx context.Context,
	repos Repositories,
	token string,
	now time.Time,
) (*AuthenticatedSession, error) {
	if !validToken(token) {
		return nil, ErrUnauthorized
	}
	session, account, err := activeSession(ctx, repos, digest(token), now)
	if err != nil {
		return nil, err
	}
	result := &AuthenticatedSession{
		Account: *account,
		Method:  session.Method,
		Expires: session.Expires,
	}
	if session.ParentHash != "" {
		parent, actor, err := activeSession(ctx, repos, session.ParentHash, now)
		if err != nil {
			return nil, err
		}
		if parent.ParentHash != "" {
			return nil, ErrUnauthorized
		}
		result.Actor = actor
		if parent.Expires.Before(result.Expires) {
			result.Expires = parent.Expires
		}
	}
	return result, nil
}

// activeSession 校验摘要对应会话、账号和账号黑名单。
func activeSession(
	ctx context.Context,
	repos Repositories,
	hash string,
	now time.Time,
) (*Session, *Account, error) {
	session, err := repos.Sessions().Get(ctx, hash)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, ErrUnauthorized
	}
	if err != nil {
		return nil, nil, err
	}
	if session == nil || !session.Expires.After(now) {
		return nil, nil, ErrUnauthorized
	}
	account, err := repos.Accounts().GetBySessionToken(ctx, hash, now)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, ErrUnauthorized
	}
	if err != nil {
		return nil, nil, err
	}
	if err := repos.Blacklist().CheckAccount(ctx, account.ID); err != nil {
		return nil, nil, err
	}
	return session, account, nil
}
