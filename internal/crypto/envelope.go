package crypto

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	EnvelopeVersion = 1
	// MaxCiphertext bounds the decoded ciphertext size accepted by Decode.
	MaxCiphertext = 64 * 1024
	maxIDLen      = 64
)

// Envelope is the secure message sent from Worker to API.
//
//	version        protocol version (must be 1)
//	key_id         which API key pair the session key is wrapped for
//	worker_id      claimed sender identity (verified via signature)
//	encrypted_key  RSA-OAEP(API public key, session key)
//	nonce          AES-GCM nonce (12 bytes)
//	ciphertext     AES-256-GCM(payload) || tag
//	sequence       per-worker message counter (replay protection)
//	timestamp      RFC 3339 creation time (freshness window)
//	message_id     unique message identifier (replay protection)
//	signature      RSA-PSS(worker key) over all fields above
//
// version, key_id, worker_id, sequence, timestamp and message_id are bound
// into the AES-GCM AAD. The signature additionally covers encrypted_key,
// nonce and ciphertext.
type Envelope struct {
	Version      int    `json:"version"`
	KeyID        string `json:"key_id"`
	WorkerID     string `json:"worker_id"`
	EncryptedKey string `json:"encrypted_key"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
	Sequence     uint64 `json:"sequence"`
	Timestamp    string `json:"timestamp"`
	MessageID    string `json:"message_id"`
	Signature    string `json:"signature"`
}

// SealParams carries the metadata for a new envelope.
type SealParams struct {
	KeyID     string
	WorkerID  string
	MessageID string
	Sequence  uint64
	Timestamp time.Time
}

// Opened is the result of a successful Open.
type Opened struct {
	Payload   []byte
	Timestamp time.Time
}

// Decoded holds the binary form of an envelope's encoded fields.
type Decoded struct {
	EncKey, Nonce, Ciphertext, Signature []byte
	Timestamp                            time.Time
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidEnvelope, fmt.Sprintf(format, a...))
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > maxIDLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

// Decode performs strict structural validation and base64 decoding. It does
// not touch any key material.
func (e *Envelope) Decode() (*Decoded, error) {
	if e.Version != EnvelopeVersion {
		return nil, invalid("unsupported version %d", e.Version)
	}
	if e.Sequence == 0 {
		return nil, invalid("missing or zero sequence")
	}
	if !validID(e.KeyID) {
		return nil, invalid("bad key_id")
	}
	if !validID(e.WorkerID) {
		return nil, invalid("bad worker_id")
	}
	if !validID(e.MessageID) {
		return nil, invalid("bad message_id")
	}
	if len(e.Timestamp) == 0 || len(e.Timestamp) > 40 {
		return nil, invalid("bad timestamp length")
	}
	ts, err := time.Parse(time.RFC3339, e.Timestamp)
	if err != nil {
		return nil, invalid("bad timestamp")
	}
	dec := base64.StdEncoding.Strict()
	d := &Decoded{Timestamp: ts.UTC()}
	if d.EncKey, err = dec.DecodeString(e.EncryptedKey); err != nil || len(d.EncKey) < 128 || len(d.EncKey) > 1024 {
		return nil, invalid("bad encrypted_key")
	}
	if d.Nonce, err = dec.DecodeString(e.Nonce); err != nil || len(d.Nonce) != NonceSize {
		return nil, invalid("bad nonce")
	}
	if d.Ciphertext, err = dec.DecodeString(e.Ciphertext); err != nil || len(d.Ciphertext) < TagSize || len(d.Ciphertext) > MaxCiphertext {
		return nil, invalid("bad ciphertext")
	}
	if d.Signature, err = dec.DecodeString(e.Signature); err != nil || len(d.Signature) < 128 || len(d.Signature) > 1024 {
		return nil, invalid("bad signature")
	}
	return d, nil
}

func appendLP(b, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
	return append(b, v...)
}

// aad is the canonical, length-prefixed encoding of the authenticated
// metadata. Both sides build it from the envelope fields, so encoding is
// identical by construction.
func (e *Envelope) aad() []byte {
	b := []byte("sentinel/v1/aad")
	b = binary.BigEndian.AppendUint32(b, uint32(e.Version))
	b = appendLP(b, []byte(e.KeyID))
	b = appendLP(b, []byte(e.WorkerID))
	b = binary.BigEndian.AppendUint64(b, e.Sequence)
	b = appendLP(b, []byte(e.Timestamp))
	b = appendLP(b, []byte(e.MessageID))
	return b
}

func (e *Envelope) signedBytes(encKey, nonce, ct []byte) []byte {
	b := []byte("sentinel/v1/sig")
	b = appendLP(b, e.aad())
	b = appendLP(b, encKey)
	b = appendLP(b, nonce)
	b = appendLP(b, ct)
	return b
}

// Seal builds a secure envelope: fresh session key -> AES-256-GCM(payload,
// AAD) -> RSA-OAEP(session key) -> RSA-PSS signature by the worker.
func Seal(payload []byte, recipient *rsa.PublicKey, signer *rsa.PrivateKey, p SealParams) (*Envelope, error) {
	e := &Envelope{
		Version:   EnvelopeVersion,
		KeyID:     p.KeyID,
		WorkerID:  p.WorkerID,
		Sequence:  p.Sequence,
		Timestamp: p.Timestamp.UTC().Format(time.RFC3339),
		MessageID: p.MessageID,
	}
	if !validID(e.KeyID) || !validID(e.WorkerID) || !validID(e.MessageID) {
		return nil, invalid("bad identifier in seal params")
	}
	sk, err := NewSessionKey()
	if err != nil {
		return nil, err
	}
	defer zero(sk)

	nonce, ct, err := EncryptGCM(sk, payload, e.aad())
	if err != nil {
		return nil, err
	}
	wrapped, err := WrapSessionKey(recipient, p.KeyID, sk)
	if err != nil {
		return nil, err
	}
	sig, err := Sign(signer, e.signedBytes(wrapped, nonce, ct))
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding
	e.EncryptedKey = b64.EncodeToString(wrapped)
	e.Nonce = b64.EncodeToString(nonce)
	e.Ciphertext = b64.EncodeToString(ct)
	e.Signature = b64.EncodeToString(sig)
	return e, nil
}

// Open verifies and decrypts an envelope. Order of operations:
//
//  1. strict structural validation (no key use)
//  2. RSA-PSS signature check with the claimed worker's trusted public key
//     (cheap public-key op; unauthenticated senders never reach the RSA
//     private-key operation)
//  3. RSA-OAEP unwrap of the session key
//  4. AES-GCM open, which verifies the tag over ciphertext + AAD
//
// No plaintext is returned unless every step succeeds.
func Open(e *Envelope, recipient *rsa.PrivateKey, senderPub *rsa.PublicKey) (*Opened, error) {
	d, err := e.Decode()
	if err != nil {
		return nil, err
	}
	if err := Verify(senderPub, e.signedBytes(d.EncKey, d.Nonce, d.Ciphertext), d.Signature); err != nil {
		return nil, ErrSignature
	}
	return openAfterSignature(e, d, recipient)
}

func openAfterSignature(e *Envelope, d *Decoded, recipient *rsa.PrivateKey) (*Opened, error) {
	sk, err := UnwrapSessionKey(recipient, e.KeyID, d.EncKey)
	if err != nil {
		return nil, err
	}
	defer zero(sk)
	pt, err := DecryptGCM(sk, d.Nonce, d.Ciphertext, e.aad())
	if err != nil {
		return nil, err
	}
	return &Opened{Payload: pt, Timestamp: d.Timestamp}, nil
}

// Resign recomputes the envelope signature with signer. It models an
// adversary that holds a worker's signing key (compromised worker/insider)
// and is used only by the attack lab to show that AES-GCM + AAD still rejects
// tampering even when the signature layer is satisfied.
func Resign(e *Envelope, signer *rsa.PrivateKey) error {
	d, err := e.Decode()
	if err != nil {
		return err
	}
	sig, err := Sign(signer, e.signedBytes(d.EncKey, d.Nonce, d.Ciphertext))
	if err != nil {
		return err
	}
	e.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// DecryptWithoutSignature opens an envelope using only the recipient private
// key. It exists for the attack lab (to model an attacker who holds the
// recipient private key, e.g. after public-key substitution) and must not be
// used by the API.
func DecryptWithoutSignature(e *Envelope, recipient *rsa.PrivateKey) (*Opened, error) {
	d, err := e.Decode()
	if err != nil {
		return nil, err
	}
	return openAfterSignature(e, d, recipient)
}
