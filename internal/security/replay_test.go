package security

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplayGuard(t *testing.T) {
	now := time.Now()
	g := NewReplayGuard(5*time.Minute, 100)

	if err := g.CheckAndCommit("w1", 10, "a", now, now); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckAndCommit("w1", 10, "b", now, now); !errors.Is(err, ErrDuplicateSeq) {
		t.Fatalf("dup seq: %v", err)
	}
	if err := g.CheckAndCommit("w1", 11, "a", now, now); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("dup msg: %v", err)
	}
	// out-of-order but inside window and unseen: accepted
	if err := g.CheckAndCommit("w1", 5, "c", now, now); err != nil {
		t.Fatalf("out-of-order in window: %v", err)
	}
	// advance far, old one falls out of window
	if err := g.CheckAndCommit("w1", 500, "d", now, now); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckAndCommit("w1", 10, "e", now, now); !errors.Is(err, ErrSequenceTooOld) {
		t.Fatalf("too old: %v", err)
	}
	// stale / future timestamps
	if err := g.CheckAndCommit("w1", 501, "f", now.Add(-10*time.Minute), now); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	if err := g.CheckAndCommit("w1", 502, "g", now.Add(10*time.Minute), now); !errors.Is(err, ErrStale) {
		t.Fatalf("future: %v", err)
	}
	// failed checks must not consume state
	if err := g.CheckAndCommit("w1", 501, "f", now, now); err != nil {
		t.Fatalf("failed check consumed state: %v", err)
	}
	// workers are independent
	if err := g.CheckAndCommit("w2", 10, "a", now, now); err != nil {
		t.Fatalf("worker isolation: %v", err)
	}
}

func TestReplayGuardConcurrentSameEnvelope(t *testing.T) {
	now := time.Now()
	g := NewReplayGuard(5*time.Minute, 100)
	var ok int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.CheckAndCommit("w", 1, "same", now, now) == nil {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("expected exactly 1 acceptance, got %d", ok)
	}
}

func TestEventLogBounded(t *testing.T) {
	l := NewEventLog()
	for i := 0; i < maxEvents+50; i++ {
		l.Add(Event{EventType: TypeReplay, Reason: fmt.Sprintf("r%d", i%3)})
	}
	if len(l.Recent(0)) != maxEvents {
		t.Fatal("log not bounded")
	}
	if l.Total() != uint64(maxEvents+50) {
		t.Fatal("total wrong")
	}
}
