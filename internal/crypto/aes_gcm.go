package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

const (
	// SessionKeySize is the AES-256 key length in bytes.
	SessionKeySize = 32
	// NonceSize is the standard 96-bit GCM nonce length.
	NonceSize = 12
	// TagSize is the GCM authentication tag length appended to ciphertext.
	TagSize = 16
)

// NewSessionKey returns a fresh random 256-bit key from crypto/rand.
// A new key is generated for EVERY message, so a (key, nonce) pair can never
// repeat across messages even though the nonce itself is random.
func NewSessionKey() ([]byte, error) {
	k := make([]byte, SessionKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// EncryptGCM encrypts plaintext with AES-256-GCM and a fresh random nonce.
// The returned ciphertext includes the 16-byte authentication tag.
func EncryptGCM(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// DecryptGCM verifies the tag (over ciphertext, nonce and aad) and returns
// the plaintext. On failure no plaintext is returned.
func DecryptGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrAuthFailed
	}
	pt, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return pt, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
