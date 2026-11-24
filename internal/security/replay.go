// Package security implements replay protection and security-event logging.
package security

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrStale            = errors.New("timestamp outside freshness window")
	ErrDuplicateSeq     = errors.New("duplicate sequence")
	ErrSequenceTooOld   = errors.New("sequence below replay window")
	ErrDuplicateMessage = errors.New("duplicate message_id")
)

// DefaultSeqWindow is the number of sequence numbers below the highest seen
// that are still tracked (allows limited out-of-order delivery).
const DefaultSeqWindow = 4096

type workerState struct {
	highest uint64
	seenSeq map[uint64]struct{}
	seenMsg map[string]time.Time

	lastPrune time.Time
}

// ReplayGuard rejects replayed envelopes using three independent checks per
// worker: a freshness window on the timestamp, a sliding window over
// sequence numbers (IPsec-style), and a message_id set.
//
// IMPORTANT: CheckAndCommit must be called only AFTER the envelope has been
// authenticated (signature + AES-GCM). Otherwise an attacker could consume
// sequence numbers or message IDs with forged envelopes.
type ReplayGuard struct {
	mu        sync.Mutex
	freshness time.Duration
	window    uint64
	workers   map[string]*workerState
}

func NewReplayGuard(freshness time.Duration, seqWindow uint64) *ReplayGuard {
	if seqWindow == 0 {
		seqWindow = DefaultSeqWindow
	}
	return &ReplayGuard{freshness: freshness, window: seqWindow, workers: map[string]*workerState{}}
}

// CheckAndCommit atomically validates and records (worker, seq, msgID, ts).
// On error nothing is recorded.
func (g *ReplayGuard) CheckAndCommit(worker string, seq uint64, msgID string, ts, now time.Time) error {
	if d := now.Sub(ts); d > g.freshness || d < -g.freshness {
		return ErrStale
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	st := g.workers[worker]
	if st == nil {
		st = &workerState{seenSeq: map[uint64]struct{}{}, seenMsg: map[string]time.Time{}}
		g.workers[worker] = st
	}
	// prune message IDs that can no longer pass the freshness check
	// (at most once per second per worker, to keep the hot path O(1))
	if now.Sub(st.lastPrune) >= time.Second {
		for id, t := range st.seenMsg {
			if now.Sub(t) > g.freshness {
				delete(st.seenMsg, id)
			}
		}
		st.lastPrune = now
	}
	if _, dup := st.seenMsg[msgID]; dup {
		return ErrDuplicateMessage
	}
	switch {
	case seq > st.highest:
		st.highest = seq
		for s := range st.seenSeq {
			if s+g.window < st.highest {
				delete(st.seenSeq, s)
			}
		}
	case seq+g.window <= st.highest:
		return ErrSequenceTooOld
	default:
		if _, dup := st.seenSeq[seq]; dup {
			return ErrDuplicateSeq
		}
	}
	st.seenSeq[seq] = struct{}{}
	st.seenMsg[msgID] = ts
	return nil
}
