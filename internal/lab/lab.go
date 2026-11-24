// Package lab runs the controlled attack simulations (AT-01..AT-07) against
// an in-process Sentinel API. Everything stays on loopback; nothing targets
// third-party systems.
package lab

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"sentinel/internal/api"
	"sentinel/internal/crypto"
	"sentinel/internal/monitoring"
	"sentinel/internal/security"
	"sentinel/internal/storage"
	"sentinel/internal/worker"
)

// Result is one executed test case.
type Result struct {
	Group      string    `json:"group"`
	ID         string    `json:"id"`
	Scenario   string    `json:"scenario"`
	Procedure  string    `json:"procedure"`
	Expected   string    `json:"expected"`
	Actual     string    `json:"actual"`
	HTTPStatus int       `json:"http_status"`
	Reason     string    `json:"reason"`
	Pass       bool      `json:"pass"` // actual outcome matched expected
	Evidence   string    `json:"evidence"`
	RunAt      time.Time `json:"run_at"`
}

// Keys is the key material shared by all scenarios.
type Keys struct {
	API1, API2, W1, W2, Attacker, Rogue *rsa.PrivateKey
}

// GenKeys creates RSA-3072 keys for every role in the lab.
func GenKeys() (*Keys, error) {
	k := &Keys{}
	for _, p := range []**rsa.PrivateKey{&k.API1, &k.API2, &k.W1, &k.W2, &k.Attacker, &k.Rogue} {
		key, err := crypto.GenerateRSAKey(crypto.DefaultRSABits)
		if err != nil {
			return nil, err
		}
		*p = key
	}
	return k, nil
}

// ---- environment -----------------------------------------------------

type env struct {
	k      *Keys
	srv    *httptest.Server
	api    *api.Server
	store  *storage.Memory
	events *security.EventLog
}

func (k *Keys) newEnv(allowPlain bool) *env {
	store := storage.NewMemory()
	events := security.NewEventLog()
	s := api.New(api.Config{
		Keys:       map[string]*rsa.PrivateKey{"api-key-01": k.API1, "api-key-02": k.API2},
		Workers:    map[string]*rsa.PublicKey{"worker-01": &k.W1.PublicKey, "worker-02": &k.W2.PublicKey},
		Guard:      security.NewReplayGuard(5*time.Minute, security.DefaultSeqWindow),
		Store:      store,
		Events:     events,
		AllowPlain: allowPlain,
	})
	return &env{k: k, srv: httptest.NewServer(s.Handler()), api: s, store: store, events: events}
}

func (e *env) close() { e.srv.Close() }

// outcome is what the attacker (and the operator) can observe for one request.
type outcome struct {
	Status    int
	Body      string
	Reason    string
	EventType string
	Stored    int // total stored results after the request
	NewEvent  bool
}

func (e *env) post(path string, body []byte) outcome {
	before := e.events.Total()
	resp, err := http.Post(e.srv.URL+path, "application/json", bytes.NewReader(body))
	o := outcome{}
	if err != nil {
		o.Body = "transport error: " + err.Error()
		return o
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	o.Status, o.Body = resp.StatusCode, strings.TrimSpace(string(b))
	if e.events.Total() > before {
		o.NewEvent = true
		if ev, ok := e.events.Last(); ok {
			o.Reason, o.EventType = ev.Reason, ev.EventType
		}
	}
	o.Stored = e.store.Count()
	return o
}

func (e *env) secure(body []byte) outcome { return e.post("/v1/results/secure", body) }

func (e *env) client(id string, signer *rsa.PrivateKey) *worker.Client {
	c, err := worker.New(context.Background(), worker.Config{
		APIURL: e.srv.URL, KeyID: "api-key-01", WorkerID: id, Mode: worker.ModeSecure,
		Signer: signer, Recipient: &e.k.API1.PublicKey,
	})
	if err != nil {
		panic(err)
	}
	return c
}

func samplePayload() monitoring.Result {
	return monitoring.Result{Service: "payment-api", Status: "down", StatusCode: 503, ResponseTimeMS: 842, CheckedAt: time.Now().UTC()}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func flip(s string, idx int) string {
	raw, _ := base64.StdEncoding.DecodeString(s)
	if idx < 0 {
		idx = len(raw) + idx
	}
	raw[idx] ^= 0x01
	return base64.StdEncoding.EncodeToString(raw)
}

func ptr(e crypto.Envelope) *crypto.Envelope { return &e }

// ---- runner ----------------------------------------------------------

type runner struct {
	out []Result
}

func (r *runner) add(group, id, scenario, procedure, expected, actual string, o outcome, pass bool, evidence string) {
	r.out = append(r.out, Result{
		Group: group, ID: id, Scenario: scenario, Procedure: procedure,
		Expected: expected, Actual: actual, HTTPStatus: o.Status, Reason: o.Reason,
		Pass: pass, Evidence: evidence, RunAt: time.Now().UTC(),
	})
}

func fmtOutcome(o outcome) string {
	if o.Reason != "" {
		return fmt.Sprintf("HTTP %d, event=%s/%s", o.Status, o.EventType, o.Reason)
	}
	return fmt.Sprintf("HTTP %d", o.Status)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RunAll executes every scenario and returns the recorded results.
func RunAll(k *Keys) []Result {
	r := &runner{}
	r.at01(k)
	r.at02(k)
	r.at03(k)
	r.at04(k)
	r.at05(k)
	r.at06(k)
	r.at07(k)
	return r.out
}

// ---- AT-01: plaintext exposure ---------------------------------------

func (r *runner) at01(k *Keys) {
	e := k.newEnv(true)
	defer e.close()
	tap := &Tap{Upstream: e.srv.URL}
	tapSrv := httptest.NewServer(tap)
	defer tapSrv.Close()

	res := samplePayload()
	ctx := context.Background()

	plain, _ := worker.New(ctx, worker.Config{APIURL: tapSrv.URL, KeyID: "api-key-01", WorkerID: "worker-01", Mode: worker.ModePlain})
	_, err1 := plain.Send(ctx, res)
	sec, _ := worker.New(ctx, worker.Config{APIURL: tapSrv.URL, KeyID: "api-key-01", WorkerID: "worker-01", Mode: worker.ModeSecure, Signer: k.W1, Recipient: &k.API1.PublicKey})
	_, err2 := sec.Send(ctx, res)

	plainBody := tap.Body("/v1/results/plain")
	secBody := tap.Body("/v1/results/secure")

	markers := []string{"payment-api", "503", "842", `"down"`}
	readable := true
	for _, m := range markers {
		if !bytes.Contains(plainBody, []byte(m)) {
			readable = false
		}
	}
	r.add("AT-01", "AT-01a", "Eksposur plaintext (baseline)",
		"Worker mengirim hasil monitoring tanpa enkripsi aplikasi; penyerang pasif menyadap body request di antara Worker dan API (misal pada reverse proxy/load balancer tempat TLS diterminasi).",
		"Isi payload (nama service, status, status code, response time) terbaca penuh oleh penyadap.",
		fmt.Sprintf("Semua penanda %v ditemukan di body tersadap: %v (send err=%v)", markers, readable, err1),
		outcome{Status: 202}, readable, "body tersadap: "+trunc(string(plainBody), 160))

	// Decode every base64 field and search for plaintext markers as well.
	var env crypto.Envelope
	_ = json.Unmarshal(secBody, &env)
	blob := append([]byte{}, secBody...)
	for _, f := range []string{env.EncryptedKey, env.Nonce, env.Ciphertext, env.Signature} {
		if raw, err := base64.StdEncoding.DecodeString(f); err == nil {
			blob = append(blob, raw...)
		}
	}
	leaked := false
	for _, m := range []string{"payment-api", "503", "842", `"status"`, `"service"`} {
		if bytes.Contains(blob, []byte(m)) {
			leaked = true
		}
	}
	r.add("AT-01", "AT-01b", "Eksposur plaintext (secure mode)",
		"Worker mengirim hasil yang sama melalui secure envelope; penyadap yang sama menangkap body request dan memeriksa seluruh field (termasuk hasil decode base64) untuk mencari isi payload.",
		"Isi payload tidak dapat ditemukan pada envelope yang tersadap.",
		fmt.Sprintf("Penanda plaintext ditemukan: %v (send err=%v); ukuran envelope %d byte vs plaintext %d byte", leaked, err2, len(secBody), len(plainBody)),
		outcome{Status: 202}, !leaked && err2 == nil, "body tersadap: "+trunc(string(secBody), 160))
}

// ---- AT-02: ciphertext tampering -------------------------------------

func (r *runner) at02(k *Keys) {
	// Layer 1: network attacker without any key material.
	e := k.newEnv(false)
	defer e.close()
	c := e.client("worker-01", k.W1)

	control, _ := c.BuildEnvelope(samplePayload())
	oc := e.secure(mustJSON(control))
	r.add("AT-02", "AT-02-00", "Kontrol: envelope asli",
		"Worker mengirim envelope valid tanpa modifikasi.",
		"Diterima (HTTP 202) dan disimpan.", fmtOutcome(oc), oc, oc.Status == 202 && oc.Stored == 1, "stored=1")

	type mut struct {
		id, name string
		fn       func(*crypto.Envelope)
	}
	netMuts := []mut{
		{"01", "ciphertext (byte pertama)", func(x *crypto.Envelope) { x.Ciphertext = flip(x.Ciphertext, 0) }},
		{"02", "authentication tag (byte terakhir)", func(x *crypto.Envelope) { x.Ciphertext = flip(x.Ciphertext, -1) }},
		{"03", "nonce", func(x *crypto.Envelope) { x.Nonce = flip(x.Nonce, 0) }},
		{"04", "encrypted_key", func(x *crypto.Envelope) { x.EncryptedKey = flip(x.EncryptedKey, 7) }},
		{"05", "signature", func(x *crypto.Envelope) { x.Signature = flip(x.Signature, 7) }},
		{"06", "sequence (metadata AAD)", func(x *crypto.Envelope) { x.Sequence += 1000 }},
		{"07", "timestamp (metadata AAD)", func(x *crypto.Envelope) { x.Timestamp = time.Now().UTC().Add(time.Second).Format(time.RFC3339) }},
		{"08", "message_id (metadata AAD)", func(x *crypto.Envelope) { x.MessageID = "forged-id" }},
		{"09", "worker_id (metadata AAD)", func(x *crypto.Envelope) { x.WorkerID = "worker-02" }},
		{"10", "key_id (metadata AAD)", func(x *crypto.Envelope) { x.KeyID = "api-key-02" }},
	}
	for _, m := range netMuts {
		env, _ := c.BuildEnvelope(samplePayload())
		before := e.store.Count()
		mutated := ptr(*env)
		m.fn(mutated)
		o := e.secure(mustJSON(mutated))
		ok := (o.Status == 400 || o.Status == 401) && o.Stored == before && o.NewEvent
		r.add("AT-02", "AT-02-"+m.id, "Tampering oleh penyerang tanpa kunci: "+m.name,
			"Penyerang jaringan mengubah field '"+m.name+"' pada envelope valid lalu mengirimkannya ke API.",
			"Ditolak; tidak ada data yang diproses atau disimpan.",
			fmtOutcome(o)+fmt.Sprintf("; stored sebelum/sesudah=%d/%d", before, o.Stored), o, ok, "")
	}

	// Layer 2: adversary holding a signing key (compromised worker / insider)
	// re-signs the tampered envelope, so only AES-GCM + OAEP can stop it.
	gcmMuts := []struct {
		id, name, want string
		fn             func(*crypto.Envelope)
	}{
		{"11", "ciphertext", security.ReasonGCMAuthFailed, func(x *crypto.Envelope) { x.Ciphertext = flip(x.Ciphertext, 0) }},
		{"12", "authentication tag", security.ReasonGCMAuthFailed, func(x *crypto.Envelope) { x.Ciphertext = flip(x.Ciphertext, -1) }},
		{"13", "nonce", security.ReasonGCMAuthFailed, func(x *crypto.Envelope) { x.Nonce = flip(x.Nonce, 0) }},
		{"14", "sequence (AAD)", security.ReasonGCMAuthFailed, func(x *crypto.Envelope) { x.Sequence += 1 }},
		{"15", "timestamp (AAD)", security.ReasonGCMAuthFailed, func(x *crypto.Envelope) { x.Timestamp = time.Now().UTC().Add(time.Second).Format(time.RFC3339) }},
		{"16", "message_id (AAD)", security.ReasonGCMAuthFailed, func(x *crypto.Envelope) { x.MessageID = "forged-id" }},
		{"17", "encrypted_key", security.ReasonKeyUnwrapFailed, func(x *crypto.Envelope) { x.EncryptedKey = flip(x.EncryptedKey, 7) }},
		{"18", "key_id -> api-key-02 (label/AAD)", security.ReasonKeyUnwrapFailed, func(x *crypto.Envelope) { x.KeyID = "api-key-02" }},
	}
	for _, m := range gcmMuts {
		env, _ := c.BuildEnvelope(samplePayload())
		before := e.store.Count()
		mutated := ptr(*env)
		m.fn(mutated)
		if err := crypto.Resign(mutated, k.W1); err != nil {
			panic(err)
		}
		o := e.secure(mustJSON(mutated))
		ok := o.Status == 400 && o.Reason == m.want && o.Stored == before
		r.add("AT-02", "AT-02-"+m.id, "Tampering oleh pemegang kunci tanda tangan: "+m.name,
			"Penyerang yang memegang kunci tanda tangan Worker (skenario worker terkompromi) mengubah '"+m.name+"' lalu menandatangani ulang agar lolos verifikasi signature, sehingga hanya AES-GCM/RSA-OAEP yang dapat menolak.",
			"Ditolak oleh lapisan AES-GCM/RSA-OAEP dengan alasan "+m.want+"; tidak ada data tersimpan.",
			fmtOutcome(o)+fmt.Sprintf("; stored sebelum/sesudah=%d/%d", before, o.Stored), o, ok, "")
	}
}

// ---- AT-03: replay ---------------------------------------------------

func (r *runner) at03(k *Keys) {
	e := k.newEnv(false)
	defer e.close()
	c := e.client("worker-01", k.W1)
	api1 := &k.API1.PublicKey
	seal := func(seq uint64, msgID string, ts time.Time) []byte {
		env, err := crypto.Seal(mustJSON(samplePayload()), api1, k.W1, crypto.SealParams{
			KeyID: "api-key-01", WorkerID: "worker-01", MessageID: msgID, Sequence: seq, Timestamp: ts})
		if err != nil {
			panic(err)
		}
		return mustJSON(env)
	}
	envBody := func() []byte { env, _ := c.BuildEnvelope(samplePayload()); return mustJSON(env) }
	base := uint64(time.Now().UnixMicro())

	// 00 control
	first := envBody()
	o := e.secure(first)
	r.add("AT-03", "AT-03-00", "Kontrol: pesan pertama", "Worker mengirim envelope valid.", "Diterima (HTTP 202).", fmtOutcome(o), o, o.Status == 202, "")

	// 01 immediate replay
	o = e.secure(first)
	r.add("AT-03", "AT-03-01", "Replay segera",
		"Penyerang menyalin envelope valid (byte identik) dan mengirimkannya ulang.",
		"Ditolak (HTTP 409); jumlah data tersimpan tidak bertambah.", fmtOutcome(o)+fmt.Sprintf("; stored=%d", o.Stored), o, o.Status == 409 && o.Stored == 1, "")

	// 02 replay after later traffic
	for i := 0; i < 5; i++ {
		e.secure(envBody())
	}
	stored := e.store.Count()
	o = e.secure(first)
	r.add("AT-03", "AT-03-02", "Replay setelah pesan lain diproses",
		"Setelah 5 pesan valid lain diproses, penyerang mengirim ulang envelope pertama.",
		"Tetap ditolak (HTTP 409).", fmtOutcome(o)+fmt.Sprintf("; stored sebelum/sesudah=%d/%d", stored, o.Stored), o, o.Status == 409 && o.Stored == stored, "")

	// 03 duplicate sequence, different message_id
	seq := base + 1_000_000
	e.secure(seal(seq, "msg-a", time.Now()))
	o = e.secure(seal(seq, "msg-b", time.Now()))
	r.add("AT-03", "AT-03-03", "Sequence number ganda dengan message_id berbeda",
		"Pihak yang memegang kunci tanda tangan membuat envelope baru yang valid tetapi memakai sequence yang sudah dipakai.",
		"Ditolak (HTTP 409, duplicate_sequence).", fmtOutcome(o), o, o.Status == 409 && o.Reason == security.ReasonDuplicateSeq, "")

	// 04 duplicate message id, new sequence
	o = e.secure(seal(seq+1, "msg-a", time.Now()))
	r.add("AT-03", "AT-03-04", "message_id ganda dengan sequence baru",
		"Envelope valid memakai ulang message_id 'msg-a' dengan sequence yang belum dipakai.",
		"Ditolak (HTTP 409, duplicate_message_id).", fmtOutcome(o), o, o.Status == 409 && o.Reason == security.ReasonDuplicateMsg, "")

	// 05 sequence below window
	e.secure(seal(seq+20000, "msg-hi", time.Now()))
	o = e.secure(seal(seq+10, "msg-old", time.Now()))
	r.add("AT-03", "AT-03-05", "Sequence di bawah replay window",
		"Setelah sequence tinggi (+20000) diterima, dikirim envelope valid dengan sequence jauh lebih rendah (+10; window=4096).",
		"Ditolak (HTTP 409, sequence_too_old).", fmtOutcome(o), o, o.Status == 409 && o.Reason == security.ReasonSeqTooOld, "")

	// 06 stale timestamp
	o = e.secure(seal(seq+20001, "msg-stale", time.Now().Add(-10*time.Minute)))
	r.add("AT-03", "AT-03-06", "Timestamp kedaluwarsa",
		"Envelope valid dengan timestamp 10 menit lalu (freshness window 5 menit).",
		"Ditolak (HTTP 409, stale_timestamp).", fmtOutcome(o), o, o.Status == 409 && o.Reason == security.ReasonStaleTimestamp, "")

	// 07 future timestamp
	o = e.secure(seal(seq+20002, "msg-future", time.Now().Add(10*time.Minute)))
	r.add("AT-03", "AT-03-07", "Timestamp di masa depan",
		"Envelope valid dengan timestamp 10 menit ke depan.",
		"Ditolak (HTTP 409, stale_timestamp).", fmtOutcome(o), o, o.Status == 409 && o.Reason == security.ReasonStaleTimestamp, "")

	// 08 legitimate out-of-order inside window
	o = e.secure(seal(seq+20000-5, "msg-ooo", time.Now()))
	r.add("AT-03", "AT-03-08", "Kontrol: pesan sah datang tidak berurutan",
		"Envelope sah dengan sequence 5 di bawah yang tertinggi tetapi belum pernah dipakai (di dalam window).",
		"Diterima (tidak ada false positive).", fmtOutcome(o), o, o.Status == 202, "")

	// 09 forged envelopes must not burn sequence numbers
	rogue, _ := crypto.Seal(mustJSON(samplePayload()), api1, k.Attacker, crypto.SealParams{
		KeyID: "api-key-01", WorkerID: "worker-01", MessageID: "burn", Sequence: seq + 900000000, Timestamp: time.Now()})
	ob := e.secure(mustJSON(rogue))
	o = e.secure(seal(seq+20003, "msg-after-burn", time.Now()))
	r.add("AT-03", "AT-03-09", "Envelope palsu tidak boleh menghabiskan sequence",
		"Penyerang mengirim envelope palsu (signature tidak valid) dengan sequence sangat tinggi, lalu Worker sah mengirim pesan berikutnya.",
		"Envelope palsu ditolak dan pesan sah berikutnya tetap diterima (state replay hanya diubah setelah autentikasi).",
		fmt.Sprintf("palsu: %s; sah berikutnya: %s", fmtOutcome(ob), fmtOutcome(o)), o, ob.Status == 401 && o.Status == 202, "")

	// 10 concurrent replay
	body := seal(seq+20004, "msg-race", time.Now())
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[int]int{}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(e.srv.URL+"/v1/results/secure", "application/json", bytes.NewReader(body))
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			mu.Lock()
			counts[resp.StatusCode]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	r.add("AT-03", "AT-03-10", "Replay konkuren (race)",
		"Envelope yang sama dikirim 50 kali secara paralel.",
		"Tepat 1 diterima (202); 49 lainnya ditolak (409).",
		fmt.Sprintf("distribusi status: %v", counts), outcome{Status: 409}, counts[202] == 1 && counts[409] == 49, "")

	// 11 worker restart
	e2 := k.newEnv(false)
	defer e2.close()
	cA := e2.client("worker-01", k.W1)
	for i := 0; i < 3; i++ {
		env, _ := cA.BuildEnvelope(samplePayload())
		e2.secure(mustJSON(env))
	}
	time.Sleep(50 * time.Millisecond)
	cB := e2.client("worker-01", k.W1) // "restarted" worker, no persisted state
	env, _ := cB.BuildEnvelope(samplePayload())
	o = e2.secure(mustJSON(env))
	r.add("AT-03", "AT-03-11", "Kontrol: Worker restart",
		"Setelah 3 pesan, instance Worker baru dibuat (tanpa state tersimpan) lalu mengirim pesan.",
		"Diterima, karena sequence awal berbasis waktu (mikrodetik) tetap monoton.", fmtOutcome(o), o, o.Status == 202, "")
}

// ---- AT-04: public-key substitution / MITM ---------------------------

func (r *runner) at04(k *Keys) {
	e := k.newEnv(false)
	defer e.close()
	attackerPEM, _ := crypto.EncodePublicKeyPEM(&k.Attacker.PublicKey)
	realFP, _ := crypto.Fingerprint(&k.API1.PublicKey)
	ctx := context.Background()

	// 01: unauthenticated key exchange -> substitution succeeds
	var stolen []byte
	tap := &Tap{
		Upstream:      e.srv.URL,
		RewritePubKey: func([]byte) []byte { return attackerPEM },
		OnSecure: func(body []byte) {
			var env crypto.Envelope
			if json.Unmarshal(body, &env) == nil {
				if op, err := crypto.DecryptWithoutSignature(&env, k.Attacker); err == nil {
					stolen = op.Payload
				}
			}
		},
	}
	tsrv := httptest.NewServer(tap)
	defer tsrv.Close()

	c, err := worker.New(ctx, worker.Config{APIURL: tsrv.URL, KeyID: "api-key-01", WorkerID: "worker-01", Mode: worker.ModeSecure, Signer: k.W1})
	var sendErr error
	if err == nil {
		_, sendErr = c.Send(ctx, samplePayload())
	}
	read := bytes.Contains(stolen, []byte("payment-api"))
	r.add("AT-04", "AT-04-01", "Substitusi public key tanpa verifikasi",
		"Penyerang di jalur Worker→API (mis. gateway terkompromi) mengganti respons /v1/pubkey dengan public key miliknya. Worker mempercayai key yang diambil tanpa pinning, lalu mengirim envelope.",
		"Penyerang dapat mendekripsi payload (kerahasiaan hilang): ini membuktikan RSA-OAEP saja tidak mencegah MITM.",
		fmt.Sprintf("plaintext terbaca penyerang: %v; hasil kiriman ke API asli: %v", read, sendErr), outcome{Status: 400}, read,
		"payload hasil dekripsi penyerang: "+trunc(string(stolen), 140))
	o := e.store.Count()
	rejectedReason := ""
	if ev, ok := e.events.Last(); ok {
		rejectedReason = ev.Reason
	}
	r.add("AT-04", "AT-04-02", "Dampak substitusi terhadap API asli",
		"Envelope yang dibungkus untuk key penyerang diteruskan tanpa perubahan ke API asli.",
		"API menolak (key_unwrap_failed); tidak ada data tersimpan. Penyerang membaca pesan tetapi tidak dapat meneruskannya sebagai pesan sah karena signature Worker mencakup encrypted_key.",
		fmt.Sprintf("stored=%d; alasan penolakan API=%s", o, rejectedReason),
		outcome{Status: 400, Reason: rejectedReason}, o == 0 && rejectedReason == security.ReasonKeyUnwrapFailed, "")

	// 03: pinning blocks substitution
	nTapReq := len(tap.Requests())
	_, err = worker.New(ctx, worker.Config{APIURL: tsrv.URL, KeyID: "api-key-01", WorkerID: "worker-01", Mode: worker.ModeSecure,
		Signer: k.W1, PinnedFingerprint: realFP})
	secureSent := 0
	for _, rq := range tap.Requests()[nTapReq:] {
		if rq.Path == "/v1/results/secure" {
			secureSent++
		}
	}
	r.add("AT-04", "AT-04-03", "Substitusi public key dengan pinning fingerprint",
		"Skenario sama, tetapi Worker mem-pin SHA-256 fingerprint public key API yang didistribusikan lewat kanal terpisah.",
		"Worker menolak key (fingerprint tidak cocok) dan tidak mengirim pesan apa pun.",
		fmt.Sprintf("error Worker: %v; pesan secure yang terkirim ke penyerang: %d", err, secureSent),
		outcome{}, err == worker.ErrPinMismatch && secureSent == 0, "")

	// 04: control - pinned, no attack
	clean := httptest.NewServer(&Tap{Upstream: e.srv.URL})
	defer clean.Close()
	c2, err := worker.New(ctx, worker.Config{APIURL: clean.URL, KeyID: "api-key-01", WorkerID: "worker-01", Mode: worker.ModeSecure,
		Signer: k.W1, PinnedFingerprint: realFP})
	var err2 error
	if err == nil {
		_, err2 = c2.Send(ctx, samplePayload())
	}
	r.add("AT-04", "AT-04-04", "Kontrol: pinning tanpa serangan",
		"Worker dengan pin yang benar mengambil key melalui proxy yang tidak memodifikasi apa pun.",
		"Key diterima dan pesan diterima API (202).",
		fmt.Sprintf("error pembuatan client: %v; error kirim: %v; stored=%d", err, err2, e.store.Count()), outcome{Status: 202}, err == nil && err2 == nil && e.store.Count() == 1, "")

	// 05: attacker who knows the API public key forges messages (sender authentication)
	// -> covered in AT-06
}

// ---- AT-05: invalid envelope -----------------------------------------

func (r *runner) at05(k *Keys) { r.at05impl(k) }

func (r *runner) at05impl(k *Keys) {
	e := k.newEnv(false)
	defer e.close()
	c := e.client("worker-01", k.W1)
	good, _ := c.BuildEnvelope(samplePayload())
	goodMap := map[string]any{}
	_ = json.Unmarshal(mustJSON(good), &goodMap)
	with := func(f func(map[string]any)) []byte {
		m := map[string]any{}
		for kk, v := range goodMap {
			m[kk] = v
		}
		f(m)
		return mustJSON(m)
	}

	type tc struct {
		name string
		body []byte
		want int
	}
	var cases []tc
	cases = append(cases,
		tc{"body kosong", []byte{}, 400},
		tc{"bukan JSON", []byte("not json at all"), 400},
		tc{"JSON null", []byte("null"), 400},
		tc{"JSON array", []byte("[1,2,3]"), 400},
		tc{"objek kosong {}", []byte("{}"), 400},
		tc{"data sisa setelah JSON", append(mustJSON(good), []byte(` {"x":1}`)...), 400},
		tc{"field tidak dikenal", with(func(m map[string]any) { m["extra"] = "x" }), 400},
		tc{"versi 2", with(func(m map[string]any) { m["version"] = 2 }), 400},
		tc{"versi 0", with(func(m map[string]any) { m["version"] = 0 }), 400},
		tc{"tipe sequence salah (string)", with(func(m map[string]any) { m["sequence"] = "abc" }), 400},
		tc{"timestamp bukan RFC3339", with(func(m map[string]any) { m["timestamp"] = "kemarin" }), 400},
		tc{"nonce panjang 8 byte", with(func(m map[string]any) { m["nonce"] = base64.StdEncoding.EncodeToString(make([]byte, 8)) }), 400},
		tc{"ciphertext 4 byte (< tag)", with(func(m map[string]any) { m["ciphertext"] = base64.StdEncoding.EncodeToString(make([]byte, 4)) }), 400},
		tc{"key_id tidak dikenal", with(func(m map[string]any) { m["key_id"] = "api-key-99" }), 400},
		tc{"key_id berisi karakter ilegal", with(func(m map[string]any) { m["key_id"] = "../etc/passwd" }), 400},
		tc{"body 200 KB (melebihi batas)", bytes.Repeat([]byte("A"), 200*1024), 400},
		tc{"worker tidak terdaftar", with(func(m map[string]any) { m["worker_id"] = "rogue-99" }), 401},
	)
	for _, f := range []string{"version", "key_id", "worker_id", "encrypted_key", "nonce", "ciphertext", "sequence", "timestamp", "message_id", "signature"} {
		f := f
		cases = append(cases, tc{"field '" + f + "' hilang", with(func(m map[string]any) { delete(m, f) }), 400})
	}
	for _, f := range []string{"encrypted_key", "nonce", "ciphertext", "signature"} {
		f := f
		cases = append(cases, tc{"base64 rusak pada '" + f + "'", with(func(m map[string]any) { m[f] = "***not*base64***" }), 400})
	}

	for i, cs := range cases {
		before := e.store.Count()
		o := e.secure(cs.body)
		ok := o.Status == cs.want && o.Stored == before && o.NewEvent
		r.add("AT-05", fmt.Sprintf("AT-05-%02d", i+1), "Envelope tidak valid: "+cs.name,
			"Mengirim request secure dengan input: "+cs.name+".",
			fmt.Sprintf("Ditolak dengan HTTP %d tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event.", cs.want),
			fmtOutcome(o)+fmt.Sprintf("; stored sebelum/sesudah=%d/%d", before, o.Stored), o, ok, "")
	}
	// server must still be healthy after the barrage
	resp, err := http.Get(e.srv.URL + "/healthz")
	healthy := err == nil && resp.StatusCode == 200
	if resp != nil {
		resp.Body.Close()
	}
	o := e.secure(mustJSON(good))
	r.add("AT-05", "AT-05-99", "Kontrol: API tetap sehat setelah input tidak valid",
		"Setelah seluruh kasus di atas, API menerima kembali envelope valid.",
		"Healthz OK dan envelope valid diterima.", fmt.Sprintf("healthz=%v; %s", healthy, fmtOutcome(o)), o, healthy && o.Status == 202, "")
}

// ---- AT-06: sender forgery -------------------------------------------

func (r *runner) at06(k *Keys) {
	e := k.newEnv(false)
	defer e.close()
	api1 := &k.API1.PublicKey // public: anyone can obtain it
	seal := func(signer *rsa.PrivateKey, worker string) []byte {
		env, err := crypto.Seal(mustJSON(samplePayload()), api1, signer, crypto.SealParams{
			KeyID: "api-key-01", WorkerID: worker, MessageID: fmt.Sprintf("f-%d", time.Now().UnixNano()),
			Sequence: uint64(time.Now().UnixMicro()), Timestamp: time.Now()})
		if err != nil {
			panic(err)
		}
		return mustJSON(env)
	}
	o := e.secure(seal(k.Attacker, "worker-01"))
	r.add("AT-06", "AT-06-01", "Pemalsuan pengirim: menyamar sebagai worker-01",
		"Penyerang hanya memiliki public key API (yang memang publik) dan membuat envelope berformat sempurna dengan kunci tanda tangan miliknya sendiri, mengaku sebagai worker-01.",
		"Ditolak (HTTP 401, signature_invalid). Tanpa tanda tangan, enkripsi dengan public key saja tidak membuktikan identitas pengirim.",
		fmtOutcome(o), o, o.Status == 401 && o.Reason == security.ReasonSignatureInvalid && o.Stored == 0, "")
	o = e.secure(seal(k.Rogue, "rogue-01"))
	r.add("AT-06", "AT-06-02", "Pemalsuan pengirim: identitas worker tidak terdaftar",
		"Penyerang membuat envelope valid secara format dan menandatanganinya sebagai worker 'rogue-01' yang tidak terdaftar.",
		"Ditolak (HTTP 401, unknown_worker).", fmtOutcome(o), o, o.Status == 401 && o.Reason == security.ReasonUnknownWorker && o.Stored == 0, "")
	resp, err := http.Post(e.srv.URL+"/v1/results/plain", "application/json", bytes.NewReader(mustJSON(samplePayload())))
	st := 0
	if err == nil {
		st = resp.StatusCode
		resp.Body.Close()
	}
	r.add("AT-06", "AT-06-03", "Endpoint baseline tidak terbuka pada deployment secure",
		"Penyerang mengirim payload plaintext ke /v1/results/plain pada API yang berjalan tanpa flag -allow-plain.",
		"Ditolak (HTTP 404); tidak ada data tersimpan.", fmt.Sprintf("HTTP %d; stored=%d", st, e.store.Count()), outcome{Status: st}, st == 404 && e.store.Count() == 0, "")
}

// ---- AT-07: no oracle ------------------------------------------------

func (r *runner) at07(k *Keys) {
	e := k.newEnv(false)
	defer e.close()
	c := e.client("worker-01", k.W1)
	mk := func(fn func(*crypto.Envelope)) outcome {
		env, _ := c.BuildEnvelope(samplePayload())
		m := ptr(*env)
		fn(m)
		_ = crypto.Resign(m, k.W1)
		return e.secure(mustJSON(m))
	}
	a := mk(func(x *crypto.Envelope) { x.Ciphertext = flip(x.Ciphertext, 0) })     // gcm failure
	b := mk(func(x *crypto.Envelope) { x.EncryptedKey = flip(x.EncryptedKey, 3) }) // oaep failure
	env, _ := c.BuildEnvelope(samplePayload())
	bad := ptr(*env)
	bad.Version = 9
	cc := e.secure(mustJSON(bad)) // malformed
	same := a.Status == b.Status && a.Body == b.Body && b.Status == cc.Status && b.Body == cc.Body
	distinct := a.Reason != b.Reason && b.Reason != cc.Reason
	r.add("AT-07", "AT-07-01", "Respons tidak membocorkan tahap kegagalan (anti-oracle)",
		"Tiga jenis kegagalan berbeda (AES-GCM gagal, RSA-OAEP unwrap gagal, format tidak valid) dikirim dan respons HTTP luar dibandingkan dengan log keamanan internal.",
		"Respons HTTP (status + body) identik untuk ketiganya, sedangkan security event internal mencatat alasan yang berbeda.",
		fmt.Sprintf("respons: [%d %s] [%d %s] [%d %s]; alasan internal: %s | %s | %s", a.Status, a.Body, b.Status, b.Body, cc.Status, cc.Body, a.Reason, b.Reason, cc.Reason),
		a, same && distinct, "")
}
