// Package storage holds persistence abstractions. Only an in-memory
// implementation exists for the course prototype; a PostgreSQL
// implementation of ResultStore is the planned next step (see README).
package storage

import (
	"sync"

	"sentinel/internal/monitoring"
)

// ResultStore persists accepted monitoring results.
type ResultStore interface {
	Save(monitoring.Stored) error
	List(limit int) []monitoring.Stored
	Count() int
}

// Memory is a goroutine-safe in-memory ResultStore.
type Memory struct {
	mu   sync.RWMutex
	data []monitoring.Stored
}

func NewMemory() *Memory { return &Memory{} }

func (m *Memory) Save(s monitoring.Stored) error {
	m.mu.Lock()
	m.data = append(m.data, s)
	m.mu.Unlock()
	return nil
}

// List returns up to limit most recent results, newest first.
func (m *Memory) List(limit int) []monitoring.Stored {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.data)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]monitoring.Stored, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, m.data[i])
	}
	return out
}

func (m *Memory) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}
