package email

import (
	"context"
	"sync"
	"time"

	"github.com/miebyte/authkit"
)

// memoryState 汇集测试中的账号、身份、会话和邮箱证明状态，便于检查原子提交。
type memoryState struct {
	users      map[string]authkit.User
	identities map[authkit.IdentityKey]authkit.Identity
	sessions   map[string]authkit.Session
	challenges map[string]Challenge
	rates      map[string]memoryRate
}

type memoryRate struct {
	starts time.Time
	hits   int
}

func newMemoryState() *memoryState {
	return &memoryState{
		users: map[string]authkit.User{}, identities: map[authkit.IdentityKey]authkit.Identity{},
		sessions: map[string]authkit.Session{}, challenges: map[string]Challenge{},
		rates: map[string]memoryRate{},
	}
}

func copyMap[K comparable, V any](input map[K]V) map[K]V {
	result := make(map[K]V, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func (s *memoryState) clone() *memoryState {
	return &memoryState{
		users: copyMap(s.users), identities: copyMap(s.identities),
		sessions: copyMap(s.sessions), challenges: copyMap(s.challenges), rates: copyMap(s.rates),
	}
}

// memory 用互斥锁串行化测试事务，回调失败时丢弃快照以模拟回滚。
type memory struct {
	mu    sync.Mutex
	state *memoryState
}

// transact 只在回调成功时替换持久快照，避免失败路径泄漏账号或消费验证码。
func (m *memory) transact(ctx context.Context, fn func(*memoryRepositories) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	tx := &memoryRepositories{state: m.state.clone()}
	if err := fn(tx); err != nil {
		return err
	}
	m.state = tx.state
	return nil
}

// coreStore 将核心仓储绑定到当前内存状态或事务快照。
type coreStore struct{ *memory }

func (s *coreStore) WithTransaction(
	ctx context.Context,
	fn func(authkit.Repositories) error,
) error {
	return s.transact(ctx, func(tx *memoryRepositories) error { return fn(tx) })
}

func (s *coreStore) Users() authkit.UserRepository { return memoryUsers{s.state} }
func (s *coreStore) Identities() authkit.IdentityRepository {
	return memoryIdentities{s.state}
}
func (s *coreStore) Sessions() authkit.SessionRepository { return memorySessions{s.state} }

// emailStore 在一次回调中提供共享快照的核心与邮箱仓储。
type emailStore struct{ *memory }

func (s *emailStore) WithTransaction(
	ctx context.Context,
	fn func(authkit.Repositories, Repositories) error,
) error {
	return s.transact(ctx, func(tx *memoryRepositories) error { return fn(tx, tx) })
}

type memoryRepositories struct{ state *memoryState }

func (r *memoryRepositories) Users() authkit.UserRepository { return memoryUsers{r.state} }
func (r *memoryRepositories) Identities() authkit.IdentityRepository {
	return memoryIdentities{r.state}
}
func (r *memoryRepositories) Sessions() authkit.SessionRepository { return memorySessions{r.state} }

func (r *memoryRepositories) Challenges() ChallengeRepository { return memoryChallenges{r.state} }
func (r *memoryRepositories) Rates() RateRepository           { return memoryRates{r.state} }

type memoryUsers struct{ state *memoryState }

func (r memoryUsers) GetByID(_ context.Context, id string) (*authkit.User, error) {
	user, ok := r.state.users[id]
	if !ok {
		return nil, authkit.ErrNotFound
	}
	return &user, nil
}

func (r memoryUsers) Lock(ctx context.Context, id string) (*authkit.User, error) {
	return r.GetByID(ctx, id)
}

func (r memoryUsers) Create(_ context.Context, user *authkit.User) error {
	if _, exists := r.state.users[user.ID]; exists {
		return authkit.ErrConflict
	}
	r.state.users[user.ID] = *user
	return nil
}

// memoryIdentities 模拟身份键唯一、以及每账号每命名空间和范围只能绑定一次。
type memoryIdentities struct{ state *memoryState }

func (r memoryIdentities) Lock(
	_ context.Context,
	key authkit.IdentityKey,
) (*authkit.Identity, error) {
	identity, ok := r.state.identities[key]
	if !ok {
		identity = authkit.Identity{Key: key}
		r.state.identities[key] = identity
	}
	return &identity, nil
}

func (r memoryIdentities) Bind(_ context.Context, key authkit.IdentityKey, userID string) error {
	identity := r.state.identities[key]
	if identity.UserID != "" && identity.UserID != userID {
		return authkit.ErrConflict
	}
	for otherKey, other := range r.state.identities {
		if other.UserID == userID && otherKey.Namespace == key.Namespace &&
			otherKey.Scope == key.Scope && otherKey != key {
			return authkit.ErrConflict
		}
	}
	identity.Key, identity.UserID = key, userID
	r.state.identities[key] = identity
	return nil
}

func (r memoryIdentities) ListByUser(_ context.Context, userID string) ([]authkit.Identity, error) {
	var identities []authkit.Identity
	for _, identity := range r.state.identities {
		if identity.UserID == userID {
			identities = append(identities, identity)
		}
	}
	return identities, nil
}

type memorySessions struct{ state *memoryState }

func (r memorySessions) Get(_ context.Context, hash string) (*authkit.Session, error) {
	session, ok := r.state.sessions[hash]
	if !ok {
		return nil, authkit.ErrNotFound
	}
	return &session, nil
}

func (r memorySessions) GetForUpdate(ctx context.Context, hash string) (*authkit.Session, error) {
	return r.Get(ctx, hash)
}

func (r memorySessions) Create(_ context.Context, session *authkit.Session) error {
	if _, exists := r.state.sessions[session.Hash]; exists {
		return authkit.ErrConflict
	}
	r.state.sessions[session.Hash] = *session
	return nil
}

func (r memorySessions) Delete(_ context.Context, hash string) error {
	delete(r.state.sessions, hash)
	return nil
}

// memoryChallenges 将首次发码分配占位与未知邮箱验证查询区分开。
type memoryChallenges struct{ state *memoryState }

func (r memoryChallenges) Get(_ context.Context, email string) (*Challenge, error) {
	challenge, ok := r.state.challenges[email]
	if !ok {
		challenge.Email = email
		r.state.challenges[email] = challenge
	}
	return &challenge, nil
}

func (r memoryChallenges) Find(_ context.Context, email string) (*Challenge, error) {
	challenge, ok := r.state.challenges[email]
	if !ok {
		return nil, authkit.ErrNotFound
	}
	return &challenge, nil
}

func (r memoryChallenges) Save(_ context.Context, challenge *Challenge) error {
	r.state.challenges[challenge.Email] = *challenge
	return nil
}

type memoryRates struct{ state *memoryState }

func (r memoryRates) Hit(_ context.Context, id string, now time.Time, limit int) error {
	rate, ok := r.state.rates[id]
	if !ok || now.Sub(rate.starts) >= time.Hour {
		rate = memoryRate{starts: now}
	}
	if rate.hits >= limit {
		return ErrTooManyRequests
	}
	rate.hits++
	r.state.rates[id] = rate
	return nil
}

// capturedMail 捕获验证码；hook 可在邮件送达期间模拟另一轮发码。
type capturedMail struct {
	email string
	code  string
	err   error
	hook  func()
}

func (m *capturedMail) SendCode(_ context.Context, email, code string) error {
	m.email, m.code = email, code
	if m.hook != nil {
		m.hook()
	}
	return m.err
}
