package authkit

import (
	"context"
	"errors"
	"time"
)

// Transaction 在调用方提供的事务内执行账号、身份和会话操作。
// 此对象不管理事务生命周期；即使方法已经返回 Token，整个宿主事务提交前也不能交付给客户端。
type Transaction struct {
	// repos 中的各仓储必须共享同一个事务，才能保证多张表的写入原子性。
	repos Repositories
	// registration 只在创建新账号时调用；nil 表示拒绝新注册。
	registration RegistrationPolicy
	now          func() time.Time
}

// LoginVerified 使用已验证身份查找或创建账号，并在当前事务中签发新会话。
// 先锁定身份占位记录，使同一身份的并发注册依次执行；成功建号后，后续请求复用账号并跳过准入。
// 凭证验证由插件在调用前完成；本方法只检查身份格式并处理账号归属。
func (t *Transaction) LoginVerified(
	ctx context.Context,
	verified VerifiedIdentity,
) (Outcome, error) {
	if !validVerifiedIdentity(verified) {
		return Outcome{}, ErrInvalidInput
	}
	// 尚未注册的身份也要先取得独占锁，不能以无锁的“查询不存在”作为新建账号依据。
	identity, err := t.repos.Identities().Lock(ctx, verified.Identity)
	if err != nil {
		return Outcome{}, err
	}
	created := identity.UserID == ""
	var user *User
	if created {
		user, err = t.createUser(ctx, verified)
		if err == nil {
			err = t.repos.Identities().Bind(ctx, verified.Identity, user.ID)
		}
	} else {
		user, err = t.repos.Users().Lock(ctx, identity.UserID)
	}
	if err != nil {
		return Outcome{}, err
	}
	return t.issueSession(ctx, user, created)
}

// BindVerified 将已验证身份显式绑定到当前会话的账号，保持账号 ID 不变。
// 身份已归其他账号或账号已有不同的同范围身份时返回冲突，禁止自动合并与替换。
// 按身份、账号、当前会话的顺序加锁，再次检查会话后完成绑定及 Token 轮换。
// 重复绑定原身份不会创建重复记录，但仍会轮换当前会话；失败时调用方必须回滚。
func (t *Transaction) BindVerified(
	ctx context.Context,
	currentToken string,
	verified VerifiedIdentity,
) (Outcome, error) {
	if !validVerifiedIdentity(verified) {
		return Outcome{}, ErrInvalidInput
	}
	// 预检查使用无锁读取，只用于提前拒绝无效请求，不代替后面持锁后的会话复核。
	current, err := t.Authenticate(ctx, currentToken)
	if err != nil {
		return Outcome{}, err
	}
	identity, err := t.repos.Identities().Lock(ctx, verified.Identity)
	if err != nil {
		return Outcome{}, err
	}
	user, err := t.repos.Users().Lock(ctx, current.ID)
	if err != nil {
		return Outcome{}, err
	}
	// 等待身份锁或账号锁期间，Token 可能已被退出请求撤销，或已被另一次绑定轮换。
	// 此处读取锁定后的最新会话，并使用当前时间检查过期，防止复用失效的会话授权。
	session, err := t.repos.Sessions().GetForUpdate(ctx, digest(currentToken))
	if errors.Is(err, ErrNotFound) {
		return Outcome{}, ErrUnauthorized
	}
	if err != nil {
		return Outcome{}, err
	}
	if session.UserID != user.ID || !t.now().UTC().Before(session.Expires) {
		return Outcome{}, ErrUnauthorized
	}
	if identity.UserID != "" && identity.UserID != user.ID {
		return Outcome{}, ErrIdentityConflict
	}
	if identity.UserID == "" {
		// 账号锁串行化同一账号的并发绑定；数据库唯一约束还需独立保证每个范围只有一个身份。
		identities, err := t.repos.Identities().ListByUser(ctx, user.ID)
		if err != nil {
			return Outcome{}, err
		}
		for _, bound := range identities {
			if bound.Key.Namespace == verified.Identity.Namespace &&
				bound.Key.Scope == verified.Identity.Scope {
				return Outcome{}, ErrIdentityBound
			}
		}
		if err = t.repos.Identities().Bind(ctx, verified.Identity, user.ID); err != nil {
			return Outcome{}, err
		}
	}
	// 新会话的创建和旧会话的撤销必须同事务完成，任一步失败都不能保留部分轮换结果。
	outcome, err := t.issueSession(ctx, user, false)
	if err != nil {
		return Outcome{}, err
	}
	if err = t.repos.Sessions().Delete(ctx, digest(currentToken)); err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

// Authenticate 供插件在校验新身份凭证前检查当前会话，避免无效会话消耗邮箱验证码等证明。
// 它只做无锁读取，保持后续“先身份、后账号、再会话”的加锁顺序；BindVerified 会持锁复核。
func (t *Transaction) Authenticate(ctx context.Context, token string) (*User, error) {
	return authenticate(ctx, t.repos, token, t.now().UTC())
}

// createUser 生成账号 ID 后调用注册准入策略，通过后才在当前事务中插入账号。
// 策略可以利用预先分配的账号 ID 处理宿主数据，但这些写入必须随当前事务一起提交或回滚。
// 未配置策略时明确拒绝注册，策略返回的错误原样向上传递。
func (t *Transaction) createUser(ctx context.Context, verified VerifiedIdentity) (*User, error) {
	if t.registration == nil {
		return nil, ErrRegistrationDenied
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	user := &User{ID: id}
	if err = t.registration.Authorize(ctx, Registration{
		User:      *user,
		Identity:  verified.Identity,
		Method:    verified.Method,
		Reference: verified.RegistrationRef,
	}); err != nil {
		return nil, err
	}
	if err = t.repos.Users().Create(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// issueSession 生成独立的随机 Token，将其摘要和固定过期时间写入会话仓储。
// 明文 Token 只存在于返回结果中；created 表示是否新建账号，不能用于判断是否新建会话。
// 当前事务尚未提交，调用方后续失败时必须连同这条会话一起回滚。
func (t *Transaction) issueSession(ctx context.Context, user *User, created bool) (Outcome, error) {
	token, err := newID()
	if err != nil {
		return Outcome{}, err
	}
	expires := t.now().UTC().Add(SessionTTL)
	if err = t.repos.Sessions().Create(ctx, &Session{
		Hash: digest(token), UserID: user.ID, Expires: expires,
	}); err != nil {
		return Outcome{}, err
	}
	return Outcome{Login: &LoginResult{
		User: *user, Token: token, Expires: expires, Created: created,
	}}, nil
}

// authenticate 无锁读取会话和账号，供普通认证及绑定预检查共用。
// 它先检查 Token 格式，再用摘要查询；缺失或过期统一视为未授权，其他存储错误原样返回。
// 保持无锁读取可避免绑定流程在锁定身份之前，先持有账号锁或会话锁。
func authenticate(
	ctx context.Context,
	repos Repositories,
	token string,
	now time.Time,
) (*User, error) {
	if !validToken(token) {
		return nil, ErrUnauthorized
	}
	session, err := repos.Sessions().Get(ctx, digest(token))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if !now.Before(session.Expires) {
		return nil, ErrUnauthorized
	}
	user, err := repos.Users().GetByID(ctx, session.UserID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrUnauthorized
	}
	return user, err
}
