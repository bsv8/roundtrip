package core

import (
	"context"
	"sync"
	"time"
)

// ReplayClaim is a request id the receiver wants to claim, and how long the
// claim has to survive.
type ReplayClaim struct {
	// ID is the base64url digest of the signed request bytes.
	ID string
	// RetainUntil is the unix second the record must be kept through.
	RetainUntil int64
}

// ReplayCapabilities states what a store can actually promise.
type ReplayCapabilities struct {
	// Persistent survives a process restart.
	Persistent bool
	// Shared is visible to every instance that can receive the same request.
	Shared bool
	// ResultCache can return a previous business result for a duplicate.
	ResultCache bool
}

// ReplayGuard is the only state interface the core needs.
//
// Claim must be atomic across every instance that can receive the same request:
// a losing caller must see false and must not run the business handler.
// Complete records that the claimed work finished. There is no release, on
// purpose: a cancelled or failed execution must not hand the same request id
// back to a second execution.
type ReplayGuard interface {
	Capabilities() ReplayCapabilities
	Claim(ctx context.Context, claim ReplayClaim) (bool, error)
	Complete(ctx context.Context, id string) error
}

// MemoryReplayGuard is a single process, in memory implementation.
//
// It is enough for demos, tests and business flows without persistent side
// effects. It is not enough for a restart or a second instance: nothing is
// written to disk and nothing is shared, so after either event a replayed
// request is accepted again. A production deployment has to supply a
// persistent, shared store and has to make the side effect idempotent with its
// own transaction.
type MemoryReplayGuard struct {
	mu      sync.Mutex
	entries map[string]*memoryEntry
	now     func() int64
}

type memoryEntry struct {
	retainUntil int64
	completed   bool
}

// NewMemoryReplayGuard builds an in process guard.
//
// now must be the same clock the core uses. Retention is a security decision: if
// the sweep ran on a different clock than the expiry check, a record could be
// dropped while the request is still inside its window, or kept long after it is
// not. A nil now means the wall clock, which is the right choice for a
// deployment that does not inject a clock.
func NewMemoryReplayGuard(now func() int64) *MemoryReplayGuard {
	if now == nil {
		now = func() int64 { return time.Now().Unix() }
	}
	return &MemoryReplayGuard{
		entries: map[string]*memoryEntry{},
		now:     now,
	}
}

// Capabilities reports the limits of this store.
func (g *MemoryReplayGuard) Capabilities() ReplayCapabilities {
	return ReplayCapabilities{Persistent: false, Shared: false, ResultCache: false}
}

// Claim atomically takes ownership of a request id.
func (g *MemoryReplayGuard) Claim(_ context.Context, claim ReplayClaim) (bool, error) {
	if claim.ID == "" {
		return false, failf(ErrReplayed, "replay claim needs a request id")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweep()
	if _, exists := g.entries[claim.ID]; exists {
		return false, nil
	}
	g.entries[claim.ID] = &memoryEntry{retainUntil: claim.RetainUntil}
	return true, nil
}

// Complete marks a claimed request as finished.
func (g *MemoryReplayGuard) Complete(_ context.Context, id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if entry, ok := g.entries[id]; ok {
		entry.completed = true
	}
	return nil
}

// sweep drops records that can no longer pass the expiry check of any receiver.
func (g *MemoryReplayGuard) sweep() {
	now := g.now()
	for id, entry := range g.entries {
		if entry.retainUntil < now {
			delete(g.entries, id)
		}
	}
}

// Size is a test and diagnostic helper.
func (g *MemoryReplayGuard) Size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweep()
	return len(g.entries)
}

// StateOf reports absent, claimed or completed for one request id.
func (g *MemoryReplayGuard) StateOf(id string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweep()
	entry, ok := g.entries[id]
	if !ok {
		return "absent"
	}
	if entry.completed {
		return "completed"
	}
	return "claimed"
}
