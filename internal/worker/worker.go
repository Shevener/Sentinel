// Package worker implements the Sentinel Worker: it checks endpoints and
// reports results to the API, either through the secure envelope or (lab
// baseline only) as plain JSON.
package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"sentinel/internal/crypto"
	"sentinel/internal/monitoring"
)

type Mode string

const (
	ModeSecure Mode = "secure"
	ModePlain  Mode = "plain" // baseline, lab only
)

var ErrPinMismatch = errors.New("API public key does not match pinned fingerprint")

// RejectedError is returned when the API answers with a non-202 status.
type RejectedError struct{ Status int }

func (e *RejectedError) Error() string {
	return fmt.Sprintf("api rejected message (HTTP %d)", e.Status)
}

// Config configures a Client.
type Config struct {
	APIURL   string
	KeyID    string
	WorkerID string
	Mode     Mode
	Signer   *rsa.PrivateKey // worker signing key (secure mode)

	// Recipient is the API public key. If nil it is fetched from the API.
	Recipient *rsa.PublicKey
	// PinnedFingerprint, when set, must equal the SHA-256 fingerprint of the
	// recipient key (public-key pinning). If empty the fetched key is
	// trusted blindly - INSECURE, used only to demonstrate substitution.
	PinnedFingerprint string

	HTTP *http.Client
}

// SendInfo reports per-message measurements.
type SendInfo struct {
	BytesSent int
	EncryptNS int64
}

// Client sends results to the API.
type Client struct {
	cfg  Config
	seq  atomic.Uint64
	http *http.Client
}

// New creates a Client. In secure mode it obtains (and optionally pins) the
// API public key.
func New(ctx context.Context, cfg Config) (*Client, error) {
	c := &Client{cfg: cfg, http: cfg.HTTP}
	if c.http == nil {
		c.http = &http.Client{Timeout: 10 * time.Second}
	}
	// Start sequence from microsecond time so it stays monotonic across
	// worker restarts without persisted state.
	c.seq.Store(uint64(time.Now().UnixMicro()))

	if cfg.Mode == ModeSecure {
		if cfg.Signer == nil {
			return nil, errors.New("secure mode requires a signing key")
		}
		if c.cfg.Recipient == nil {
			pub, err := c.fetchPublicKey(ctx)
			if err != nil {
				return nil, err
			}
			c.cfg.Recipient = pub
		}
		if cfg.PinnedFingerprint != "" {
			fp, err := crypto.Fingerprint(c.cfg.Recipient)
			if err != nil {
				return nil, err
			}
			if fp != cfg.PinnedFingerprint {
				return nil, ErrPinMismatch
			}
		}
	}
	return c, nil
}

func (c *Client) fetchPublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	u := c.cfg.APIURL + "/v1/pubkey?key_id=" + url.QueryEscape(c.cfg.KeyID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch public key: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return nil, err
	}
	return crypto.ParsePublicKeyPEM(b)
}

// Target is an endpoint to monitor.
type Target struct {
	Name string
	URL  string
}

// Check performs one health check.
func (c *Client) Check(ctx context.Context, t Target) monitoring.Result {
	start := time.Now()
	res := monitoring.Result{Service: t.Name, CheckedAt: start.UTC()}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		res.Status = "down"
		return res
	}
	resp, err := (&http.Client{}).Do(req)
	res.ResponseTimeMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Status = "down"
		return res
	}
	defer resp.Body.Close()
	res.StatusCode = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		res.Status = "up"
	} else {
		res.Status = "down"
	}
	return res
}

func newMessageID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// BuildEnvelope seals a result into a secure envelope (exported so the
// attack lab can craft, replay and mutate messages).
func (c *Client) BuildEnvelope(res monitoring.Result) (*crypto.Envelope, error) {
	payload, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	return crypto.Seal(payload, c.cfg.Recipient, c.cfg.Signer, crypto.SealParams{
		KeyID:     c.cfg.KeyID,
		WorkerID:  c.cfg.WorkerID,
		MessageID: newMessageID(),
		Sequence:  c.seq.Add(1),
		Timestamp: time.Now(),
	})
}

// Send reports one result to the API.
func (c *Client) Send(ctx context.Context, res monitoring.Result) (SendInfo, error) {
	var (
		info SendInfo
		body []byte
		path string
		err  error
	)
	switch c.cfg.Mode {
	case ModeSecure:
		t0 := time.Now()
		var env *crypto.Envelope
		if env, err = c.BuildEnvelope(res); err != nil {
			return info, err
		}
		if body, err = json.Marshal(env); err != nil {
			return info, err
		}
		info.EncryptNS = time.Since(t0).Nanoseconds()
		path = "/v1/results/secure"
	case ModePlain:
		if body, err = json.Marshal(res); err != nil {
			return info, err
		}
		path = "/v1/results/plain"
	default:
		return info, fmt.Errorf("unknown mode %q", c.cfg.Mode)
	}
	info.BytesSent = len(body)
	status, err := c.Post(ctx, path, body)
	if err != nil {
		return info, err
	}
	if status != http.StatusAccepted {
		return info, &RejectedError{Status: status}
	}
	return info, nil
}

// Post sends raw bytes to an API path and returns the HTTP status.
func (c *Client) Post(ctx context.Context, path string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.APIURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.Mode == ModePlain {
		req.Header.Set("X-Worker-ID", c.cfg.WorkerID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}
