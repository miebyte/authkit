package authkit

import (
	"context"
	"errors"
	"sync"
	"time"
)

// memoryState contains the durable data used by the transactional test double.
type memoryState struct {
	users      map[string]User
	wechat     map[string]string
	challenges map[string]Challenge
	rates      map[string]memoryRate
	sessions   map[string]Session
}

// memoryRate records a fixed hourly counter.
type memoryRate struct {
	window time.Time
	count  int
}

// memoryStore serializes transactions and discards their writes on an error.
type memoryStore struct {
	mu sync.Mutex
	*memoryRepositories
	inTransaction bool
}

// memoryRepositories binds each repository to one state snapshot.
type memoryRepositories struct{ state *memoryState }

// memoryUsers implements identity persistence against a snapshot.
type memoryUsers struct{ state *memoryState }

// memoryChallenges implements mailbox persistence against a snapshot.
type memoryChallenges struct{ state *memoryState }

// memoryRates implements fixed-window rate limits against a snapshot.
type memoryRates struct{ state *memoryState }

// memorySessions implements session persistence against a snapshot.
type memorySessions struct{ state *memoryState }

// newMemoryStore constructs empty durable state for each test.
func newMemoryStore() *memoryStore {
	return &memoryStore{memoryRepositories: &memoryRepositories{state: &memoryState{
		users: map[string]User{}, wechat: map[string]string{}, challenges: map[string]Challenge{},
		rates: map[string]memoryRate{}, sessions: map[string]Session{},
	}}}
}

// copyMap copies the value-only entries used by memoryState.
func copyMap[K comparable, V any](input map[K]V) map[K]V {
	result := make(map[K]V, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

// clone copies all persisted values so a rolled-back transaction cannot leak writes.
func (s *memoryState) clone() *memoryState {
	return &memoryState{
		users: copyMap(s.users), wechat: copyMap(s.wechat),
		challenges: copyMap(s.challenges), rates: copyMap(s.rates), sessions: copyMap(s.sessions),
	}
}

// WithTransaction commits a snapshot only when the callback succeeds.
func (s *memoryStore) WithTransaction(ctx context.Context, fn func(Repositories) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	tx := &memoryRepositories{state: s.state.clone()}
	s.inTransaction = true
	err := fn(tx)
	s.inTransaction = false
	if err == nil {
		s.state = tx.state
	}
	return err
}

// Users returns identities bound to the current snapshot.
func (r *memoryRepositories) Users() UserRepository { return memoryUsers{r.state} }

// Challenges returns mailboxes bound to the current snapshot.
func (r *memoryRepositories) Challenges() ChallengeRepository { return memoryChallenges{r.state} }

// Rates returns counters bound to the current snapshot.
func (r *memoryRepositories) Rates() RateRepository { return memoryRates{r.state} }

// Sessions returns sessions bound to the current snapshot.
func (r *memoryRepositories) Sessions() SessionRepository { return memorySessions{r.state} }

// GetByEmail resolves an existing nonempty mailbox.
func (r memoryUsers) GetByEmail(_ context.Context, email string) (*User, error) {
	for _, user := range r.state.users {
		if user.Email == email && email != "" {
			return &user, nil
		}
	}
	return nil, ErrNotFound
}

// GetByID resolves a persisted account.
func (r memoryUsers) GetByID(_ context.Context, id string) (*User, error) {
	user, ok := r.state.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &user, nil
}

// GetByWechat resolves the identity scoped to its application.
func (r memoryUsers) GetByWechat(ctx context.Context, appID, openIDHash string) (*User, error) {
	return r.GetByID(ctx, r.state.wechat[appID+"/"+openIDHash])
}

// BindWechat enforces a unique identity and one WeChat identity per user/application.
func (r memoryUsers) BindWechat(_ context.Context, appID, openIDHash, userID string) error {
	key := appID + "/" + openIDHash
	if current, ok := r.state.wechat[key]; ok && current != userID {
		return ErrConflict
	}
	for existingKey, existingUser := range r.state.wechat {
		if existingUser == userID && existingKey != key && len(existingKey) > len(appID) &&
			existingKey[:len(appID)+1] == appID+"/" {
			return ErrWechatBound
		}
	}
	r.state.wechat[key] = userID
	return nil
}

// HasWechat reports whether an account has any associated WeChat identity.
func (r memoryUsers) HasWechat(_ context.Context, userID string) (bool, error) {
	for _, id := range r.state.wechat {
		if id == userID {
			return true, nil
		}
	}
	return false, nil
}

// BindEmail rejects reassignment and independently owned mailboxes.
func (r memoryUsers) BindEmail(ctx context.Context, userID, email string) error {
	user, err := r.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.Email != "" {
		return ErrEmailBound
	}
	if _, err := r.GetByEmail(ctx, email); err == nil {
		return ErrEmailAccountConflict
	}
	user.Email = email
	r.state.users[userID] = *user
	return nil
}

// Create enforces unique IDs and nonempty mailboxes while permitting WeChat-only users.
func (r memoryUsers) Create(ctx context.Context, user *User) error {
	if _, exists := r.state.users[user.ID]; exists {
		return ErrConflict
	}
	if _, err := r.GetByEmail(ctx, user.Email); err == nil {
		return ErrConflict
	}
	r.state.users[user.ID] = *user
	return nil
}

// GetBySessionToken only resolves unexpired sessions.
func (r memoryUsers) GetBySessionToken(
	ctx context.Context,
	hash string,
	now time.Time,
) (*User, error) {
	session, exists := r.state.sessions[hash]
	if !exists || !now.Before(session.Expires) {
		return nil, ErrNotFound
	}
	return r.GetByID(ctx, session.UserID)
}

// Get allocates a mailbox placeholder while serializing its first issuance.
func (r memoryChallenges) Get(_ context.Context, email string) (*Challenge, error) {
	challenge, exists := r.state.challenges[email]
	if !exists {
		challenge.Email = email
		r.state.challenges[email] = challenge
	}
	return &challenge, nil
}

// Find resolves existing proof state without allocating rows for unissued mailboxes.
func (r memoryChallenges) Find(_ context.Context, email string) (*Challenge, error) {
	challenge, exists := r.state.challenges[email]
	if !exists {
		return nil, ErrNotFound
	}
	return &challenge, nil
}

// Save persists all challenge state, including committed verification failures.
func (r memoryChallenges) Save(_ context.Context, challenge *Challenge) error {
	r.state.challenges[challenge.Email] = *challenge
	return nil
}

// Hit enforces the same fixed hourly-window semantics as the production port.
func (r memoryRates) Hit(_ context.Context, id string, now time.Time, limit int) error {
	window := now.UTC().Truncate(time.Hour)
	rate := r.state.rates[id]
	if !rate.window.Equal(window) {
		rate = memoryRate{window: window}
	}
	if rate.count >= limit {
		return ErrTooManyRequests
	}
	rate.count++
	r.state.rates[id] = rate
	return nil
}

// Create records a newly issued digest without retaining its plaintext token.
func (r memorySessions) Create(_ context.Context, session *Session) error {
	if _, exists := r.state.sessions[session.Hash]; exists {
		return ErrConflict
	}
	r.state.sessions[session.Hash] = *session
	return nil
}

// Delete revokes a digest and is idempotent for already-revoked sessions.
func (r memorySessions) Delete(_ context.Context, hash string) error {
	delete(r.state.sessions, hash)
	return nil
}

// capturedMail records only test messages and allows deterministic delivery failure.
type capturedMail struct {
	email string
	code  string
	err   error
	hook  func()
}

// SendCode captures the outgoing challenge and optional host-controlled action.
func (m *capturedMail) SendCode(_ context.Context, email, code string) error {
	m.email, m.code = email, code
	if m.hook != nil {
		m.hook()
	}
	return m.err
}

// fakeWechat supplies server-verified identities without network calls.
type fakeWechat struct {
	identity                WechatIdentity
	err                     error
	store                   *memoryStore
	calledInsideTransaction bool
}

// ExchangeCode records ordering so tests can detect external calls within a transaction.
func (w *fakeWechat) ExchangeCode(_ context.Context, _ string) (WechatIdentity, error) {
	if w.store != nil {
		w.calledInsideTransaction = w.store.inTransaction
	}
	return w.identity, w.err
}

// allowRegistration explicitly enables account creation in ordinary fixture tests.
func allowRegistration(context.Context, Registration) error { return nil }

var errPolicyFailure = errors.New("host admission rejected")
