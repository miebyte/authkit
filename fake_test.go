package authkit

import (
	"context"
	"sync"
)

// memoryState 保存测试仓储的全部状态，映射中的记录均为可直接复制的值类型。
// 事务先复制映射，只有提交成功才替换原状态，从而验证回滚不会泄漏写入。
type memoryState struct {
	users      map[string]User
	identities map[IdentityKey]Identity
	sessions   map[string]Session
}

// memoryStore 以整事务互斥和快照模拟存储；真实数据库的细粒度锁由 MySQL 集成测试验证。
type memoryStore struct {
	mu sync.Mutex
	*memoryRepositories
	// commitErr 模拟事务回调成功、最终提交却失败的情况。
	commitErr error
}

// memoryRepositories 将三个测试仓储绑定到同一份状态快照。
type memoryRepositories struct {
	state *memoryState
	// beforeSessionLock 模拟无锁预检查后、会话加锁读取前的状态变化，用于验证必须重新检查会话。
	beforeSessionLock func(*memoryState, string)
}

type (
	// memoryUsers 在当前快照中实现账号读写。
	memoryUsers struct{ state *memoryState }
	// memoryIdentities 在当前快照中模拟身份占位和双向唯一约束。
	memoryIdentities struct{ state *memoryState }
	// memorySessions 通过所在仓储访问会话快照，并在加锁读取时执行测试钩子。
	memorySessions struct{ repos *memoryRepositories }
)

// newMemoryStore 为每个测试创建隔离的空存储，避免测试之间共享账号或会话。
func newMemoryStore() *memoryStore {
	return &memoryStore{memoryRepositories: &memoryRepositories{state: &memoryState{
		users:      map[string]User{},
		identities: map[IdentityKey]Identity{},
		sessions:   map[string]Session{},
	}}}
}

// copyMap 复制映射容器；当前记录均为值类型，因此逐项复制足以隔离事务写入。
func copyMap[K comparable, V any](input map[K]V) map[K]V {
	result := make(map[K]V, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

// WithTransaction 在独立快照上执行回调，回调和模拟提交都成功时才发布新状态。
// 回调返回错误或 commitErr 非空时丢弃快照，保留事务之前的数据。
func (s *memoryStore) WithTransaction(ctx context.Context, fn func(Repositories) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	tx := &memoryRepositories{state: &memoryState{
		users: copyMap(
			s.state.users,
		),
		identities: copyMap(s.state.identities),
		sessions:   copyMap(s.state.sessions),
	}, beforeSessionLock: s.beforeSessionLock}
	if err := fn(tx); err != nil {
		return err
	}
	if s.commitErr != nil {
		return s.commitErr
	}
	s.state = tx.state
	return nil
}

// Users 返回绑定到当前快照的账号仓储。
func (r *memoryRepositories) Users() UserRepository { return memoryUsers{r.state} }

// Identities 返回绑定到当前快照的身份仓储。
func (r *memoryRepositories) Identities() IdentityRepository { return memoryIdentities{r.state} }

// Sessions 返回使用当前快照和会话测试钩子的会话仓储。
func (r *memoryRepositories) Sessions() SessionRepository { return memorySessions{r} }

// GetByID 返回账号的值副本；缺失记录按生产仓储契约返回 ErrNotFound。
func (r memoryUsers) GetByID(_ context.Context, id string) (*User, error) {
	user, ok := r.state.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &user, nil
}

// Lock 复用账号读取；外层事务已经持有互斥锁，无需在内存仓储中再次模拟行锁。
func (r memoryUsers) Lock(ctx context.Context, id string) (*User, error) {
	return r.GetByID(ctx, id)
}

// Create 拒绝重复账号 ID，成功时仅修改当前事务快照。
func (r memoryUsers) Create(_ context.Context, user *User) error {
	if _, exists := r.state.users[user.ID]; exists {
		return ErrConflict
	}
	r.state.users[user.ID] = *user
	return nil
}

// Lock 为尚不存在的身份创建未归属占位记录，复现首次登录时的仓储返回语义。
func (r memoryIdentities) Lock(_ context.Context, key IdentityKey) (*Identity, error) {
	identity, ok := r.state.identities[key]
	if !ok {
		identity = Identity{Key: key}
		r.state.identities[key] = identity
	}
	return &identity, nil
}

// Bind 模拟两组唯一约束：身份不可转移给其他账号，一个账号同范围不可绑定不同主体。
// 重复绑定到同一个账号保持原记录，允许核心继续执行当前会话轮换。
func (r memoryIdentities) Bind(_ context.Context, key IdentityKey, userID string) error {
	identity, ok := r.state.identities[key]
	if !ok {
		return ErrNotFound
	}
	if identity.UserID != "" && identity.UserID != userID {
		return ErrIdentityConflict
	}
	for otherKey, other := range r.state.identities {
		if other.UserID == userID && otherKey != key &&
			otherKey.Namespace == key.Namespace && otherKey.Scope == key.Scope {
			return ErrIdentityBound
		}
	}
	identity.UserID = userID
	r.state.identities[key] = identity
	return nil
}

// ListByUser 收集当前快照中归属指定账号的身份，用于绑定约束和身份列表断言。
func (r memoryIdentities) ListByUser(_ context.Context, userID string) ([]Identity, error) {
	result := []Identity{}
	for _, identity := range r.state.identities {
		if identity.UserID == userID {
			result = append(result, identity)
		}
	}
	return result, nil
}

// Get 按 Token 摘要读取会话副本；过期判断留给核心服务。
func (r memorySessions) Get(_ context.Context, hash string) (*Session, error) {
	session, ok := r.repos.state.sessions[hash]
	if !ok {
		return nil, ErrNotFound
	}
	return &session, nil
}

// GetForUpdate 先执行状态变化钩子，再读取最新快照，验证绑定不能复用预检查的旧结果。
func (r memorySessions) GetForUpdate(ctx context.Context, hash string) (*Session, error) {
	if r.repos.beforeSessionLock != nil {
		r.repos.beforeSessionLock(r.repos.state, hash)
	}
	return r.Get(ctx, hash)
}

// Create 在快照中保存会话摘要；摘要已存在时模拟数据库唯一约束冲突。
func (r memorySessions) Create(_ context.Context, session *Session) error {
	if _, exists := r.repos.state.sessions[session.Hash]; exists {
		return ErrConflict
	}
	r.repos.state.sessions[session.Hash] = *session
	return nil
}

// Delete 按摘要撤销会话，重复删除不存在的会话仍然成功。
func (r memorySessions) Delete(_ context.Context, hash string) error {
	delete(r.repos.state.sessions, hash)
	return nil
}

// allowRegistration 仅供测试显式开放注册，避免把无策略误认为默认允许注册。
func allowRegistration(context.Context, Registration) error { return nil }
