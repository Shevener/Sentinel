package security

import (
	"sync"
	"time"
)

// Event types.
const (
	TypeInvalidEnvelope = "invalid_envelope"
	TypeSenderAuth      = "sender_authentication"
	TypeIntegrity       = "integrity_failure"
	TypeReplay          = "replay_rejected"
	TypePayloadInvalid  = "payload_invalid"
)

// Reasons (precise, internal). The HTTP layer returns coarse responses; the
// precise reason is only recorded here.
const (
	ReasonMalformed        = "malformed_envelope"
	ReasonUnknownKeyID     = "unknown_key_id"
	ReasonUnknownWorker    = "unknown_worker"
	ReasonSignatureInvalid = "signature_invalid"
	ReasonKeyUnwrapFailed  = "key_unwrap_failed"
	ReasonGCMAuthFailed    = "gcm_authentication_failed"
	ReasonDuplicateSeq     = "duplicate_sequence"
	ReasonSeqTooOld        = "sequence_too_old"
	ReasonDuplicateMsg     = "duplicate_message_id"
	ReasonStaleTimestamp   = "stale_timestamp"
	ReasonPayloadSchema    = "payload_schema"
)

// Event is one recorded security decision. It never contains key material or
// plaintext.
type Event struct {
	ID             uint64    `json:"id"`
	EventType      string    `json:"event_type"`
	Source         string    `json:"source"` // claimed worker_id or "unknown"
	SourceVerified bool      `json:"source_verified"`
	Result         string    `json:"result"` // always "rejected" for now
	Reason         string    `json:"reason"`
	OccurredAt     time.Time `json:"occurred_at"`
}

const maxEvents = 10000

// EventLog is a bounded, goroutine-safe event buffer with per-reason counters.
type EventLog struct {
	mu     sync.Mutex
	nextID uint64
	events []Event
	counts map[string]uint64
}

func NewEventLog() *EventLog { return &EventLog{counts: map[string]uint64{}} }

func (l *EventLog) Add(e Event) Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextID++
	e.ID = l.nextID
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	if e.Result == "" {
		e.Result = "rejected"
	}
	l.events = append(l.events, e)
	if len(l.events) > maxEvents {
		l.events = l.events[len(l.events)-maxEvents:]
	}
	l.counts[e.Reason]++
	return e
}

// Recent returns up to limit most recent events, newest first.
func (l *EventLog) Recent(limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(l.events)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Event, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, l.events[i])
	}
	return out
}

// Counts returns a copy of the per-reason counters.
func (l *EventLog) Counts() map[string]uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := make(map[string]uint64, len(l.counts))
	for k, v := range l.counts {
		c[k] = v
	}
	return c
}

// Last returns the most recent event, if any.
func (l *EventLog) Last() (Event, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) == 0 {
		return Event{}, false
	}
	return l.events[len(l.events)-1], true
}

// Total returns the number of events ever recorded.
func (l *EventLog) Total() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.nextID
}
