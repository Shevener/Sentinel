package crypto

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// Key generation is slow; share keys across tests.
var (
	apiKey, workerKey, otherKey *rsa.PrivateKey
)

func TestMain(m *testing.M) {
	var err error
	if apiKey, err = GenerateRSAKey(DefaultRSABits); err != nil {
		panic(err)
	}
	if workerKey, err = GenerateRSAKey(DefaultRSABits); err != nil {
		panic(err)
	}
	if otherKey, err = GenerateRSAKey(DefaultRSABits); err != nil {
		panic(err)
	}
	m.Run()
}

func params(seq uint64) SealParams {
	return SealParams{KeyID: "api-key-01", WorkerID: "worker-01", MessageID: "m-1", Sequence: seq, Timestamp: time.Now()}
}

func TestRoundTrip(t *testing.T) {
	payload := []byte(`{"service":"payment-api","status":"down"}`)
	env, err := Seal(payload, &apiKey.PublicKey, workerKey, params(1))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Open(env, apiKey, &workerKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Payload, payload) {
		t.Fatalf("payload mismatch: %q", out.Payload)
	}
}

func TestWrongRecipientKeyCannotDecrypt(t *testing.T) {
	env, _ := Seal([]byte("secret"), &apiKey.PublicKey, workerKey, params(1))
	if _, err := DecryptWithoutSignature(env, otherKey); !errors.Is(err, ErrDecryptKey) {
		t.Fatalf("want ErrDecryptKey, got %v", err)
	}
}

func TestWrongSenderKeyRejected(t *testing.T) {
	env, _ := Seal([]byte("x"), &apiKey.PublicKey, otherKey, params(1))
	if _, err := Open(env, apiKey, &workerKey.PublicKey); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestFreshKeyAndNoncePerMessage(t *testing.T) {
	a, _ := Seal([]byte("same"), &apiKey.PublicKey, workerKey, params(1))
	b, _ := Seal([]byte("same"), &apiKey.PublicKey, workerKey, params(2))
	if a.EncryptedKey == b.EncryptedKey || a.Nonce == b.Nonce || a.Ciphertext == b.Ciphertext {
		t.Fatal("two messages share key/nonce/ciphertext material")
	}
}

func flipB64(s string, idx int) string {
	raw, _ := base64.StdEncoding.DecodeString(s)
	raw[idx%len(raw)] ^= 0x01
	return base64.StdEncoding.EncodeToString(raw)
}

func TestAnyFieldTamperingRejected(t *testing.T) {
	base, _ := Seal([]byte(`{"a":1}`), &apiKey.PublicKey, workerKey, params(7))
	muts := map[string]func(e *Envelope){
		"ciphertext": func(e *Envelope) { e.Ciphertext = flipB64(e.Ciphertext, 0) },
		"tag": func(e *Envelope) {
			raw, _ := base64.StdEncoding.DecodeString(e.Ciphertext)
			e.Ciphertext = flipB64(e.Ciphertext, len(raw)-1) // last byte = inside the GCM tag
		},
		"nonce":      func(e *Envelope) { e.Nonce = flipB64(e.Nonce, 0) },
		"enc_key":    func(e *Envelope) { e.EncryptedKey = flipB64(e.EncryptedKey, 5) },
		"signature":  func(e *Envelope) { e.Signature = flipB64(e.Signature, 5) },
		"sequence":   func(e *Envelope) { e.Sequence++ },
		"message_id": func(e *Envelope) { e.MessageID = "m-2" },
		"worker_id":  func(e *Envelope) { e.WorkerID = "worker-02" },
		"timestamp":  func(e *Envelope) { e.Timestamp = time.Now().Add(time.Hour).UTC().Format(time.RFC3339) },
	}
	for name, mut := range muts {
		e := *base
		mut(&e)
		out, err := Open(&e, apiKey, &workerKey.PublicKey)
		if err == nil || out != nil {
			t.Errorf("%s: tampered envelope was accepted", name)
		}
	}
}

// Even if an attacker defeated/bypassed the signature, AES-GCM alone must
// reject any change to the metadata bound as AAD, and to ciphertext/nonce.
func TestGCMBindsAADIndependentlyOfSignature(t *testing.T) {
	base, _ := Seal([]byte(`{"a":1}`), &apiKey.PublicKey, workerKey, params(7))
	muts := map[string]func(e *Envelope){
		"version":    func(e *Envelope) { e.Version = 1; e.Sequence++ }, // sequence in AAD
		"sequence":   func(e *Envelope) { e.Sequence++ },
		"message_id": func(e *Envelope) { e.MessageID = "m-9" },
		"worker_id":  func(e *Envelope) { e.WorkerID = "worker-99" },
		"timestamp":  func(e *Envelope) { e.Timestamp = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) },
		"ciphertext": func(e *Envelope) { e.Ciphertext = flipB64(e.Ciphertext, 0) },
		"nonce":      func(e *Envelope) { e.Nonce = flipB64(e.Nonce, 0) },
	}
	for name, mut := range muts {
		e := *base
		mut(&e)
		_, err := DecryptWithoutSignature(&e, apiKey)
		if !errors.Is(err, ErrAuthFailed) {
			t.Errorf("%s: want ErrAuthFailed (GCM), got %v", name, err)
		}
	}
	// key_id is bound through the OAEP label and the AAD.
	e := *base
	e.KeyID = "api-key-02"
	if _, err := DecryptWithoutSignature(&e, apiKey); err == nil {
		t.Error("key_id swap accepted")
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	good, _ := Seal([]byte("x"), &apiKey.PublicKey, workerKey, params(1))
	cases := map[string]func(e *Envelope){
		"version":     func(e *Envelope) { e.Version = 2 },
		"key_id":      func(e *Envelope) { e.KeyID = "" },
		"key_id_char": func(e *Envelope) { e.KeyID = "a b" },
		"worker_id":   func(e *Envelope) { e.WorkerID = "x/../y" },
		"timestamp":   func(e *Envelope) { e.Timestamp = "yesterday" },
		"enc_key_b64": func(e *Envelope) { e.EncryptedKey = "!!!" },
		"nonce_len":   func(e *Envelope) { e.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 8)) },
		"ct_short":    func(e *Envelope) { e.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, 4)) },
		"sig_empty":   func(e *Envelope) { e.Signature = "" },
	}
	for name, mut := range cases {
		e := *good
		mut(&e)
		if _, err := e.Decode(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("%s: want ErrInvalidEnvelope, got %v", name, err)
		}
	}
}

func TestSmallRSAKeysRefused(t *testing.T) {
	if _, err := GenerateRSAKey(1024); err == nil {
		t.Fatal("1024-bit key generation should be refused")
	}
}

func TestPEMAndFingerprint(t *testing.T) {
	pemb, _ := EncodePublicKeyPEM(&apiKey.PublicKey)
	pub, err := ParsePublicKeyPEM(pemb)
	if err != nil {
		t.Fatal(err)
	}
	f1, _ := Fingerprint(pub)
	f2, _ := Fingerprint(&apiKey.PublicKey)
	f3, _ := Fingerprint(&otherKey.PublicKey)
	if f1 != f2 || f1 == f3 || len(f1) != 64 {
		t.Fatal("fingerprint mismatch")
	}
	privb, _ := EncodePrivateKeyPEM(apiKey)
	if _, err := ParsePrivateKeyPEM(privb); err != nil {
		t.Fatal(err)
	}
}
