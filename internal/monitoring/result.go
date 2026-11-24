// Package monitoring defines the health-check result model shared by the
// Worker and the API.
package monitoring

import (
	"errors"
	"time"
)

// Result is the payload a Worker reports after checking one endpoint.
type Result struct {
	Service        string    `json:"service"`
	Status         string    `json:"status"` // "up" | "down"
	StatusCode     int       `json:"status_code"`
	ResponseTimeMS int64     `json:"response_time_ms"`
	CheckedAt      time.Time `json:"checked_at"`
}

// Validate enforces the payload schema after decryption.
func (r *Result) Validate() error {
	switch {
	case len(r.Service) == 0 || len(r.Service) > 128:
		return errors.New("service must be 1..128 characters")
	case r.Status != "up" && r.Status != "down":
		return errors.New("status must be up or down")
	case r.StatusCode < 0 || r.StatusCode > 599:
		return errors.New("status_code out of range")
	case r.ResponseTimeMS < 0 || r.ResponseTimeMS > 600000:
		return errors.New("response_time_ms out of range")
	case r.CheckedAt.IsZero():
		return errors.New("checked_at missing")
	}
	return nil
}

// Stored is a Result as persisted by the API.
type Stored struct {
	Result
	WorkerID   string    `json:"worker_id"`
	Verified   bool      `json:"verified"` // true only when received via the secure path
	ReceivedAt time.Time `json:"received_at"`
}
