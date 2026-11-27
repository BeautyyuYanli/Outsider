package session

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"outsider/internal/proto"
)

// Status represents a session's lifecycle state.
type Status string

const (
	StatusPending   Status = "pending"
	StatusApproved  Status = "approved"
	StatusConsumed  Status = "consumed"
	StatusCancelled Status = "cancelled"
	StatusExpired   Status = "expired"
)

var (
	ErrReplayNonce     = errors.New("request nonce already seen")
	ErrRateLimited     = errors.New("rate limit exceeded")
	ErrTooManyPending  = errors.New("too many pending sessions for client")
	ErrNotFound        = errors.New("session not found")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrAlreadyResolved = errors.New("session is no longer pending")
	ErrExpired         = errors.New("session expired")
)

// Envelope is the opaque end-to-end encrypted payload submitted by the approver.
type Envelope struct {
	V          int    `json:"v"`
	EPK        string `json:"epk"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// CreateParams holds the validated signed request data used to open a session.
type CreateParams struct {
	Version      int
	IDPk         string
	ClientName   string
	PkReq        string
	Context      proto.Context
	RequestTs    int64
	TTLSecs      int
	RequestNonce string
	Sig          string

	GraceTTLSecs        int
	MaxPendingPerClient int
	RateLimitPerMin     int
}

// SessionSnapshot is a read-only copy of public session metadata (never includes wait_token or ciphertext).
type SessionSnapshot struct {
	V            int            `json:"v"`
	SessionID    string         `json:"session_id"`
	IDPk         string         `json:"id_pk"`
	ClientName   string         `json:"client_name"`
	PkReq        string         `json:"pk_req"`
	Context      proto.Context `json:"context"`
	RequestTs    int64          `json:"request_ts"`
	TTLSecs      int            `json:"ttl_secs"`
	RequestNonce string         `json:"request_nonce"`
	Sig          string         `json:"sig"`
	ExpiresAt    time.Time      `json:"expires_at"`
	Status       Status         `json:"status"`
}

// CreatedSession returns the tokens needed by the requester and notification pipeline.
type CreatedSession struct {
	SessionID    string
	WaitToken    string
	ApproveToken string
	NameSlug     string
	ExpiresAt    time.Time
}

// WaitResult is returned by Store.Wait.
type WaitResult struct {
	Status        Status
	RemainingSecs int
	Envelope      *Envelope
}

type sessionEntry struct {
	v            int
	sessionID    string
	waitToken    string
	approveToken string
	idPk         string
	clientName   string
	pkReq        string
	ctx          proto.Context
	requestTs    int64
	ttlSecs      int
	requestNonce string
	sig          string

	createdAt      time.Time
	expiresAt      time.Time
	graceTTL       time.Duration
	graceExpiresAt time.Time
	terminalAt     time.Time

	status   Status
	envelope *Envelope
	done     chan struct{}
	closed   bool
}

func (e *sessionEntry) closeDoneLocked() {
	if !e.closed {
		close(e.done)
		e.closed = true
	}
}

func (e *sessionEntry) wipeEnvelopeLocked() {
	if e.envelope != nil {
		e.envelope.EPK = ""
		e.envelope.Nonce = ""
		e.envelope.Ciphertext = ""
		e.envelope = nil
	}
}

func (e *sessionEntry) refreshExpiryLocked(now time.Time) {
	switch e.status {
	case StatusPending:
		if !now.Before(e.expiresAt) {
			e.status = StatusExpired
			e.terminalAt = now
			e.wipeEnvelopeLocked()
			e.closeDoneLocked()
		}
	case StatusApproved:
		if !now.Before(e.graceExpiresAt) {
			e.status = StatusExpired
			e.terminalAt = now
			e.wipeEnvelopeLocked()
			e.closeDoneLocked()
		}
	}
}

func (e *sessionEntry) snapshotLocked() SessionSnapshot {
	return SessionSnapshot{
		V:            e.v,
		SessionID:    e.sessionID,
		IDPk:         e.idPk,
		ClientName:   e.clientName,
		PkReq:        e.pkReq,
		Context:      e.ctx,
		RequestTs:    e.requestTs,
		TTLSecs:      e.ttlSecs,
		RequestNonce: e.requestNonce,
		Sig:          e.sig,
		ExpiresAt:    e.expiresAt.UTC(),
		Status:       e.status,
	}
}

// Store is an in-memory, zero-persistence session store with nonce replay and rate-limit tracking.
type Store struct {
	mu         sync.Mutex
	byID       map[string]*sessionEntry
	byApprove  map[string]*sessionEntry
	seenNonces map[string]time.Time
	rateHits   map[string][]time.Time
	nowFunc    func() time.Time
}

// NewStore creates an empty in-memory session store.
func NewStore() *Store {
	return &Store{
		byID:       make(map[string]*sessionEntry),
		byApprove:  make(map[string]*sessionEntry),
		seenNonces: make(map[string]time.Time),
		rateHits:   make(map[string][]time.Time),
		nowFunc:    time.Now,
	}
}

// StartReaper starts a background goroutine that periodically clears expired sessions and nonces.
func (s *Store) StartReaper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				s.Reap(t)
			}
		}
	}()
}

// Create registers a new pending session after enforcing replay, rate-limit, and concurrency checks.
func (s *Store) Create(p CreateParams) (CreatedSession, error) {
	now := s.nowFunc()

	sessionRand, err := proto.RandomToken(24)
	if err != nil {
		return CreatedSession{}, err
	}
	waitToken, err := proto.RandomToken(32)
	if err != nil {
		return CreatedSession{}, err
	}
	approveToken, err := proto.RandomToken(32)
	if err != nil {
		return CreatedSession{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Replay check (60s window keyed by id_pk + nonce).
	nonceKey := p.IDPk + ":" + p.RequestNonce
	if exp, exists := s.seenNonces[nonceKey]; exists && now.Before(exp) {
		return CreatedSession{}, ErrReplayNonce
	}

	// Sliding 60s rate limit per client.
	windowStart := now.Add(-60 * time.Second)
	hits := s.rateHits[p.IDPk]
	kept := hits[:0]
	for _, ts := range hits {
		if ts.After(windowStart) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= p.RateLimitPerMin {
		s.rateHits[p.IDPk] = kept
		return CreatedSession{}, ErrRateLimited
	}

	// Max concurrent pending sessions per client.
	pendingCount := 0
	for _, entry := range s.byID {
		if entry.idPk != p.IDPk {
			continue
		}
		entry.refreshExpiryLocked(now)
		if entry.status == StatusPending {
			pendingCount++
		}
	}
	if pendingCount >= p.MaxPendingPerClient {
		return CreatedSession{}, ErrTooManyPending
	}

	// Commit nonce and rate hit only after all checks pass.
	s.seenNonces[nonceKey] = now.Add(60 * time.Second)
	s.rateHits[p.IDPk] = append(kept, now)

	sessionID := "sess_" + sessionRand
	expiresAt := now.Add(time.Duration(p.TTLSecs) * time.Second)
	entry := &sessionEntry{
		v:            p.Version,
		sessionID:    sessionID,
		waitToken:    waitToken,
		approveToken: approveToken,
		idPk:         p.IDPk,
		clientName:   p.ClientName,
		pkReq:        p.PkReq,
		ctx:          p.Context,
		requestTs:    p.RequestTs,
		ttlSecs:      p.TTLSecs,
		requestNonce: p.RequestNonce,
		sig:          p.Sig,
		createdAt:    now,
		expiresAt:    expiresAt,
		graceTTL:     time.Duration(p.GraceTTLSecs) * time.Second,
		status:       StatusPending,
		done:         make(chan struct{}),
	}

	s.byID[sessionID] = entry
	s.byApprove[approveToken] = entry

	return CreatedSession{
		SessionID:    sessionID,
		WaitToken:    waitToken,
		ApproveToken: approveToken,
		NameSlug:     proto.SlugifyName(p.Context.Name),
		ExpiresAt:    expiresAt.UTC(),
	}, nil
}

// GetByApproveToken returns the signed request metadata for the approval page.
func (s *Store) GetByApproveToken(approveToken string) (SessionSnapshot, bool) {
	now := s.nowFunc()
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.byApprove[approveToken]
	if !ok {
		return SessionSnapshot{}, false
	}
	entry.refreshExpiryLocked(now)
	return entry.snapshotLocked(), true
}

// Approve stores the encrypted envelope once and immediately wakes any waiting requester.
func (s *Store) Approve(approveToken string, env Envelope) error {
	now := s.nowFunc()
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.byApprove[approveToken]
	if !ok {
		return ErrNotFound
	}
	entry.refreshExpiryLocked(now)
	if entry.status == StatusExpired {
		return ErrExpired
	}
	if entry.status != StatusPending {
		return ErrAlreadyResolved
	}

	envCopy := env
	entry.envelope = &envCopy
	entry.status = StatusApproved
	entry.graceExpiresAt = now.Add(entry.graceTTL)
	entry.closeDoneLocked()
	return nil
}

// Wait blocks until the session leaves PENDING, chunkTimeout elapses, or ctx is cancelled.
// When APPROVED, Wait atomically pops and wipes the ciphertext from memory.
func (s *Store) Wait(ctx context.Context, sessionID, waitToken string, chunkTimeout time.Duration) (WaitResult, error) {
	if chunkTimeout <= 0 {
		chunkTimeout = 25 * time.Second
	}

	for {
		now := s.nowFunc()
		s.mu.Lock()
		entry, ok := s.byID[sessionID]
		if !ok {
			s.mu.Unlock()
			return WaitResult{}, ErrNotFound
		}
		if subtle.ConstantTimeCompare([]byte(entry.waitToken), []byte(waitToken)) != 1 {
			s.mu.Unlock()
			return WaitResult{}, ErrUnauthorized
		}
		entry.refreshExpiryLocked(now)

		switch entry.status {
		case StatusApproved:
			envCopy := *entry.envelope
			entry.wipeEnvelopeLocked()
			entry.status = StatusConsumed
			entry.terminalAt = now
			s.mu.Unlock()
			return WaitResult{Status: StatusApproved, Envelope: &envCopy}, nil
		case StatusConsumed, StatusCancelled, StatusExpired:
			st := entry.status
			s.mu.Unlock()
			return WaitResult{Status: st}, nil
		}

		// Still PENDING: capture channel & deadline, release lock, then block.
		doneCh := entry.done
		remaining := entry.expiresAt.Sub(now)
		waitDur := chunkTimeout
		if remaining < waitDur {
			waitDur = remaining
		}
		s.mu.Unlock()

		timer := time.NewTimer(waitDur)
		select {
		case <-doneCh:
			timer.Stop()
			// Loop around once to read the resolved state and pop ciphertext atomically.
			continue
		case <-timer.C:
			nowAfter := s.nowFunc()
			s.mu.Lock()
			entry.refreshExpiryLocked(nowAfter)
			if entry.status == StatusPending {
				remSecs := int(entry.expiresAt.Sub(nowAfter).Seconds())
				if remSecs < 0 {
					remSecs = 0
				}
				s.mu.Unlock()
				return WaitResult{Status: StatusPending, RemainingSecs: remSecs}, nil
			}
			s.mu.Unlock()
			continue
		case <-ctx.Done():
			timer.Stop()
			return WaitResult{}, ctx.Err()
		}
	}
}

// Cancel transitions a session to CANCELLED and wipes any stored envelope.
func (s *Store) Cancel(sessionID, waitToken string) error {
	now := s.nowFunc()
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.byID[sessionID]
	if !ok {
		return ErrNotFound
	}
	if subtle.ConstantTimeCompare([]byte(entry.waitToken), []byte(waitToken)) != 1 {
		return ErrUnauthorized
	}
	entry.refreshExpiryLocked(now)
	if entry.status == StatusPending || entry.status == StatusApproved {
		entry.status = StatusCancelled
		entry.terminalAt = now
		entry.wipeEnvelopeLocked()
		entry.closeDoneLocked()
	}
	return nil
}

// Reap expires overdue sessions, wipes envelopes, and prunes old entries, nonces, and rate windows.
func (s *Store) Reap(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	const retentionAfterTerminal = 60 * time.Second
	for id, entry := range s.byID {
		entry.refreshExpiryLocked(now)
		if entry.status != StatusPending && entry.status != StatusApproved {
			entry.wipeEnvelopeLocked()
			if !entry.terminalAt.IsZero() && now.Sub(entry.terminalAt) > retentionAfterTerminal {
				delete(s.byApprove, entry.approveToken)
				delete(s.byID, id)
			}
		}
	}

	for k, exp := range s.seenNonces {
		if !now.Before(exp) {
			delete(s.seenNonces, k)
		}
	}

	windowStart := now.Add(-60 * time.Second)
	for pk, hits := range s.rateHits {
		kept := hits[:0]
		for _, ts := range hits {
			if ts.After(windowStart) {
				kept = append(kept, ts)
			}
		}
		if len(kept) == 0 {
			delete(s.rateHits, pk)
		} else {
			s.rateHits[pk] = kept
		}
	}
}
