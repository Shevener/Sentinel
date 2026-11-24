package lab

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

// Captured is one request observed by the Tap.
type Captured struct {
	Method string
	Path   string
	Body   []byte
}

// Tap is a man-in-the-middle HTTP proxy placed in front of the API. It
// records every request, and can optionally rewrite the public-key response
// or observe secure submissions.
type Tap struct {
	Upstream      string
	RewritePubKey func(orig []byte) []byte
	OnSecure      func(body []byte)

	mu   sync.Mutex
	reqs []Captured
}

func (t *Tap) Requests() []Captured {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Captured(nil), t.reqs...)
}

// Body returns the body of the most recent request to path.
func (t *Tap) Body(path string) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.reqs) - 1; i >= 0; i-- {
		if t.reqs[i].Path == path {
			return t.reqs[i].Body
		}
	}
	return nil
}

func (t *Tap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	t.mu.Lock()
	t.reqs = append(t.reqs, Captured{Method: r.Method, Path: r.URL.Path, Body: body})
	t.mu.Unlock()

	if r.URL.Path == "/v1/results/secure" && t.OnSecure != nil {
		t.OnSecure(body)
	}
	req, _ := http.NewRequestWithContext(r.Context(), r.Method, t.Upstream+r.URL.RequestURI(), bytes.NewReader(body))
	req.Header = r.Header.Clone()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if r.URL.Path == "/v1/pubkey" && t.RewritePubKey != nil {
		rb = t.RewritePubKey(rb)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(rb)
}
