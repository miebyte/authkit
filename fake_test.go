package authkit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// memoryState contains the durable data used by the transactional test double.
type memoryState struct {
	accounts   map[string]Account
	bindings   map[string]string
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

// memoryAccounts implements identity persistence against a snapshot.
type memoryAccounts struct{ state *memoryState }

// memoryChallenges implements mailbox persistence against a snapshot.
type memoryChallenges struct{ state *memoryState }

// memoryRates implements fixed-window rate limits against a snapshot.
type memoryRates struct{ state *memoryState }

// memorySessions implements session persistence against a snapshot.
type memorySessions struct{ state *memoryState }

// newMemoryStore constructs empty durable state for each test.
func newMemoryStore() *memoryStore {
	return &memoryStore{memoryRepositories: &memoryRepositories{state: &memoryState{
		accounts:   map[string]Account{},
		bindings:   map[string]string{},
		challenges: map[string]Challenge{},
		rates:      map[string]memoryRate{},
		sessions:   map[string]Session{},
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
		accounts: copyMap(s.accounts), bindings: copyMap(s.bindings),
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

// Accounts returns identities bound to the current snapshot.
func (r *memoryRepositories) Accounts() AccountRepository { return memoryAccounts{r.state} }

// Challenges returns mailboxes bound to the current snapshot.
func (r *memoryRepositories) Challenges() ChallengeRepository { return memoryChallenges{r.state} }

// Rates returns counters bound to the current snapshot.
func (r *memoryRepositories) Rates() RateRepository { return memoryRates{r.state} }

// Sessions returns sessions bound to the current snapshot.
func (r *memoryRepositories) Sessions() SessionRepository { return memorySessions{r.state} }

// bindingKey identifies one credential independently of its owner.
func bindingKey(method, identifier string) string { return method + "/" + identifier }

// GetByEmail resolves an existing nonempty mailbox.
func (r memoryAccounts) GetByEmail(ctx context.Context, email string) (*Account, error) {
	if email == "" {
		return nil, ErrNotFound
	}
	return r.accountForBinding(ctx, bindingKey(MethodEmail, email))
}

// GetByID resolves a persisted account and its mailbox projection.
func (r memoryAccounts) GetByID(_ context.Context, id string) (*Account, error) {
	account, ok := r.state.accounts[id]
	if !ok {
		return nil, ErrNotFound
	}
	account.Email = r.emailOf(id)
	return &account, nil
}

// GetByWechat locks the OpenID, inserting an unbound placeholder when it is new.
func (r memoryAccounts) GetByWechat(ctx context.Context, openIDHash string) (*Account, error) {
	key := bindingKey(MethodWechat, openIDHash)
	if _, ok := r.state.bindings[key]; !ok {
		r.state.bindings[key] = ""
	}
	return r.accountForBinding(ctx, key)
}

// BindWechat assigns a locked OpenID once. One account keeps a single WeChat credential.
func (r memoryAccounts) BindWechat(_ context.Context, openIDHash, accountID string) error {
	key := bindingKey(MethodWechat, openIDHash)
	if current, ok := r.state.bindings[key]; ok && current != "" && current != accountID {
		return ErrWechatBound
	}
	prefix := MethodWechat + "/"
	for existingKey, existingAccount := range r.state.bindings {
		if strings.HasPrefix(existingKey, prefix) && existingAccount == accountID &&
			existingKey != key {
			return ErrWechatBound
		}
	}
	r.state.bindings[key] = accountID
	return nil
}

// HasWechat reports whether an account has an OpenID binding.
func (r memoryAccounts) HasWechat(_ context.Context, accountID string) (bool, error) {
	prefix := MethodWechat + "/"
	for key, id := range r.state.bindings {
		if id == accountID && strings.HasPrefix(key, prefix) {
			return true, nil
		}
	}
	return false, nil
}

// BindEmail rejects reassignment and independently owned mailboxes.
func (r memoryAccounts) BindEmail(ctx context.Context, accountID, email string) error {
	account, err := r.GetByID(ctx, accountID)
	if err != nil {
		return err
	}
	if account.Email != "" {
		return ErrEmailBound
	}
	if _, err := r.GetByEmail(ctx, email); err == nil {
		return ErrEmailAccountConflict
	}
	r.state.bindings[bindingKey(MethodEmail, email)] = accountID
	account.Email = email
	r.state.accounts[accountID] = *account
	return nil
}

// Create enforces unique IDs and mailboxes while permitting accounts without an email.
func (r memoryAccounts) Create(ctx context.Context, account *Account) error {
	if _, exists := r.state.accounts[account.ID]; exists {
		return ErrConflict
	}
	if _, err := r.GetByEmail(ctx, account.Email); err == nil {
		return ErrConflict
	}
	if account.Username != "" {
		for _, existing := range r.state.accounts {
			if existing.Username == account.Username {
				return ErrConflict
			}
		}
	}
	r.state.accounts[account.ID] = *account
	if account.Email != "" {
		r.state.bindings[bindingKey(MethodEmail, account.Email)] = account.ID
	}
	return nil
}

// GetBySessionToken only resolves unexpired sessions.
func (r memoryAccounts) GetBySessionToken(
	ctx context.Context,
	hash string,
	now time.Time,
) (*Account, error) {
	session, exists := r.state.sessions[hash]
	if !exists || !now.Before(session.Expires) {
		return nil, ErrNotFound
	}
	return r.GetByID(ctx, session.AccountID)
}

// accountForBinding resolves the owner of a credential, or reports it missing.
func (r memoryAccounts) accountForBinding(ctx context.Context, key string) (*Account, error) {
	accountID, ok := r.state.bindings[key]
	if !ok || accountID == "" {
		return nil, ErrNotFound
	}
	return r.GetByID(ctx, accountID)
}

// emailOf returns the mailbox bound to an account.
func (r memoryAccounts) emailOf(accountID string) string {
	prefix := MethodEmail + "/"
	for key, id := range r.state.bindings {
		if id == accountID && strings.HasPrefix(key, prefix) {
			return strings.TrimPrefix(key, prefix)
		}
	}
	return ""
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
