// Package api implements the Sentinel REST API.
package api

import (
	"bytes"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"sentinel/internal/crypto"
	"sentinel/internal/monitoring"
	"sentinel/internal/security"
	"sentinel/internal/storage"
)

// Config wires the server's dependencies.
type Config struct {
	Keys         map[string]*rsa.PrivateKey // key_id -> API private key
	Workers      map[string]*rsa.PublicKey  // worker_id -> trusted signing public key
	Guard        *security.ReplayGuard
	Store        storage.ResultStore
	Events       *security.EventLog
	AllowPlain   bool   // enable the baseline (unencrypted) endpoint - lab only
	AdminToken   string // bearer token for read endpoints; empty = open (lab only)
	Now          func() time.Time
	MaxBodyBytes int64
}

// Server is the Sentinel API.
type Server struct {
	cfg Config

	acceptedSecure atomic.Uint64
	acceptedPlain  atomic.Uint64
	openCalls      atomic.Uint64
	openNanos      atomic.Uint64
}

func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 128 * 1024
	}
	if cfg.Events == nil {
		cfg.Events = security.NewEventLog()
	}
	if cfg.Store == nil {
		cfg.Store = storage.NewMemory()
	}
	return &Server{cfg: cfg}
}

func (s *Server) Events() *security.EventLog { return s.cfg.Events }
func (s *Server) Store() storage.ResultStore { return s.cfg.Store }

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/pubkey", s.handlePubKey)
	mux.HandleFunc("POST /v1/results/secure", s.handleSecure)
	mux.HandleFunc("POST /v1/results/plain", s.handlePlain)
	mux.HandleFunc("GET /v1/results", s.admin(s.handleResults))
	mux.HandleFunc("GET /v1/security/events", s.admin(s.handleEvents))
	mux.HandleFunc("GET /v1/stats", s.admin(s.handleStats))
	return mux
}

// ---- helpers ---------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken != "" {
			got := r.Header.Get("Authorization")
			want := "Bearer " + s.cfg.AdminToken
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

// reject records a security event and returns a deliberately coarse response
// so that the endpoint is not an oracle for which internal check failed.
func (s *Server) reject(w http.ResponseWriter, code int, body, typ, reason, source string, verified bool) {
	s.cfg.Events.Add(security.Event{
		EventType: typ, Source: source, SourceVerified: verified, Reason: reason,
	})
	writeJSON(w, code, map[string]string{"error": body})
}

// ---- handlers --------------------------------------------------------

func (s *Server) handlePubKey(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("key_id")
	priv, ok := s.cfg.Keys[id]
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "unknown key_id"})
		return
	}
	pemb, err := crypto.EncodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "internal"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(pemb)
}

func (s *Server) handleSecure(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		s.reject(w, 400, "rejected", security.TypeInvalidEnvelope, security.ReasonMalformed, "unknown", false)
		return
	}
	var env crypto.Envelope
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil || dec.More() {
		s.reject(w, 400, "rejected", security.TypeInvalidEnvelope, security.ReasonMalformed, "unknown", false)
		return
	}
	if _, err := env.Decode(); err != nil {
		s.reject(w, 400, "rejected", security.TypeInvalidEnvelope, security.ReasonMalformed, "unknown", false)
		return
	}
	src := env.WorkerID // claimed, NOT yet verified
	priv, ok := s.cfg.Keys[env.KeyID]
	if !ok {
		s.reject(w, 400, "rejected", security.TypeInvalidEnvelope, security.ReasonUnknownKeyID, src, false)
		return
	}
	wpub, ok := s.cfg.Workers[env.WorkerID]
	if !ok {
		s.reject(w, 401, "unauthorized", security.TypeSenderAuth, security.ReasonUnknownWorker, src, false)
		return
	}

	t0 := time.Now()
	opened, err := crypto.Open(&env, priv, wpub)
	s.openCalls.Add(1)
	s.openNanos.Add(uint64(time.Since(t0)))
	if err != nil {
		switch {
		case errors.Is(err, crypto.ErrSignature):
			s.reject(w, 401, "unauthorized", security.TypeSenderAuth, security.ReasonSignatureInvalid, src, false)
		case errors.Is(err, crypto.ErrDecryptKey):
			s.reject(w, 400, "rejected", security.TypeIntegrity, security.ReasonKeyUnwrapFailed, src, true)
		case errors.Is(err, crypto.ErrAuthFailed):
			s.reject(w, 400, "rejected", security.TypeIntegrity, security.ReasonGCMAuthFailed, src, true)
		default:
			s.reject(w, 400, "rejected", security.TypeInvalidEnvelope, security.ReasonMalformed, src, false)
		}
		return
	}

	// Authenticated from here on: replay state may now be consumed.
	if err := s.cfg.Guard.CheckAndCommit(env.WorkerID, env.Sequence, env.MessageID, opened.Timestamp, s.cfg.Now()); err != nil {
		reason := map[error]string{
			security.ErrStale:            security.ReasonStaleTimestamp,
			security.ErrDuplicateSeq:     security.ReasonDuplicateSeq,
			security.ErrSequenceTooOld:   security.ReasonSeqTooOld,
			security.ErrDuplicateMessage: security.ReasonDuplicateMsg,
		}[err]
		s.reject(w, 409, "replay_rejected", security.TypeReplay, reason, src, true)
		return
	}

	res, ok := decodePayload(opened.Payload)
	if !ok {
		s.reject(w, 400, "rejected", security.TypePayloadInvalid, security.ReasonPayloadSchema, src, true)
		return
	}
	_ = s.cfg.Store.Save(monitoring.Stored{Result: res, WorkerID: env.WorkerID, Verified: true, ReceivedAt: s.cfg.Now().UTC()})
	s.acceptedSecure.Add(1)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

// handlePlain is the BASELINE endpoint: no application-layer protection.
// It exists only for lab comparison and is disabled unless AllowPlain.
func (s *Server) handlePlain(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowPlain {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "rejected"})
		return
	}
	res, ok := decodePayload(body)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "rejected"})
		return
	}
	_ = s.cfg.Store.Save(monitoring.Stored{Result: res, WorkerID: r.Header.Get("X-Worker-ID"), Verified: false, ReceivedAt: s.cfg.Now().UTC()})
	s.acceptedPlain.Add(1)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func decodePayload(b []byte) (monitoring.Result, bool) {
	var res monitoring.Result
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil || dec.More() || res.Validate() != nil {
		return res, false
	}
	return res, true
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	writeJSON(w, 200, s.cfg.Store.List(limit))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	writeJSON(w, 200, s.cfg.Events.Recent(limit))
}

// Stats is the data behind the security dashboard.
type Stats struct {
	AcceptedSecure uint64            `json:"accepted_secure"`
	AcceptedPlain  uint64            `json:"accepted_plain"`
	Rejected       uint64            `json:"rejected"`
	RejectedBy     map[string]uint64 `json:"rejected_by_reason"`
	AvgOpenMicros  float64           `json:"avg_open_micros"` // signature verify + RSA-OAEP + AES-GCM
}

func (s *Server) Stats() Stats {
	st := Stats{
		AcceptedSecure: s.acceptedSecure.Load(),
		AcceptedPlain:  s.acceptedPlain.Load(),
		Rejected:       s.cfg.Events.Total(),
		RejectedBy:     s.cfg.Events.Counts(),
	}
	if n := s.openCalls.Load(); n > 0 {
		st.AvgOpenMicros = float64(s.openNanos.Load()) / float64(n) / 1000
	}
	return st
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.Stats())
}
