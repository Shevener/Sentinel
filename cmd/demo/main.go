// demo prints a step-by-step walkthrough of one secure message: payload,
// envelope, successful open, tampering, and replay. All values are real.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"sentinel/internal/crypto"
	"sentinel/internal/monitoring"
	"sentinel/internal/security"
)

func short(s string) string {
	if len(s) <= 36 {
		return s
	}
	return s[:24] + "…" + s[len(s)-8:] + fmt.Sprintf("  (%d char)", len(s))
}

func main() {
	apiKey, err := crypto.GenerateRSAKey(crypto.DefaultRSABits)
	check(err)
	workerKey, err := crypto.GenerateRSAKey(crypto.DefaultRSABits)
	check(err)
	apiFP, _ := crypto.Fingerprint(&apiKey.PublicKey)
	fmt.Println("== 1. Kunci ==")
	fmt.Printf("API   : RSA-%d  key_id=api-key-01  fingerprint=%s\n", apiKey.N.BitLen(), apiFP)
	wfp, _ := crypto.Fingerprint(&workerKey.PublicKey)
	fmt.Printf("Worker: RSA-%d  worker_id=worker-01 fingerprint=%s\n\n", workerKey.N.BitLen(), wfp)

	res := monitoring.Result{Service: "payment-api", Status: "down", StatusCode: 503, ResponseTimeMS: 842, CheckedAt: time.Now().UTC()}
	payload, _ := json.Marshal(res)
	fmt.Println("== 2. Payload (plaintext, di sisi Worker) ==")
	fmt.Printf("%s\n(%d byte)\n\n", payload, len(payload))

	now := time.Now()
	seq := uint64(now.UnixMicro())
	env, err := crypto.Seal(payload, &apiKey.PublicKey, workerKey, crypto.SealParams{
		KeyID: "api-key-01", WorkerID: "worker-01", MessageID: "3f9c1a7e5b2d4c80a1e6f0d9b7c24a15", Sequence: seq, Timestamp: now})
	check(err)
	wire, _ := json.Marshal(env)
	fmt.Println("== 3. Secure envelope (yang lewat di jaringan) ==")
	fmt.Printf("version       : %d\nkey_id        : %s\nworker_id     : %s\nsequence      : %d\ntimestamp     : %s\nmessage_id    : %s\n", env.Version, env.KeyID, env.WorkerID, env.Sequence, env.Timestamp, env.MessageID)
	fmt.Printf("encrypted_key : %s\nnonce         : %s\nciphertext    : %s\nsignature     : %s\n", short(env.EncryptedKey), env.Nonce, short(env.Ciphertext), short(env.Signature))
	fmt.Printf("ukuran envelope JSON: %d byte (payload asli %d byte)\n\n", len(wire), len(payload))

	guard := security.NewReplayGuard(5*time.Minute, security.DefaultSeqWindow)
	fmt.Println("== 4. API membuka envelope ==")
	op, err := crypto.Open(env, apiKey, &workerKey.PublicKey)
	check(err)
	fmt.Printf("verifikasi tanda tangan RSA-PSS : OK\nunwrap session key RSA-OAEP     : OK\nAES-256-GCM (tag + AAD)         : OK\nplaintext: %s\n", op.Payload)
	fmt.Printf("replay guard                    : %v (nil = diterima)\n\n", guard.CheckAndCommit("worker-01", env.Sequence, env.MessageID, op.Timestamp, now))

	fmt.Println("== 5. Tampering: 1 bit ciphertext diubah ==")
	t := *env
	raw := []byte(t.Ciphertext)
	if raw[10] == 'A' {
		raw[10] = 'B'
	} else {
		raw[10] = 'A'
	}
	t.Ciphertext = string(raw)
	_, err = crypto.Open(&t, apiKey, &workerKey.PublicKey)
	fmt.Printf("hasil: ditolak -> %v\n\n", err)

	fmt.Println("== 6. Tampering oleh pemegang kunci tanda tangan (tanda tangan dibuat ulang) ==")
	t2 := *env
	t2.Sequence++
	check(crypto.Resign(&t2, workerKey))
	_, err = crypto.Open(&t2, apiKey, &workerKey.PublicKey)
	fmt.Printf("sequence diubah + signature valid -> AES-GCM tetap menolak: %v\n\n", err)

	fmt.Println("== 7. Replay: envelope yang sama dikirim lagi ==")
	fmt.Printf("hasil: ditolak -> %v\n", guard.CheckAndCommit("worker-01", env.Sequence, env.MessageID, op.Timestamp, time.Now()))
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
