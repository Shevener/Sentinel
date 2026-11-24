// Package crypto contains the hybrid-encryption primitives used by Sentinel.
//
// No algorithm is implemented here: everything is a thin, strict wrapper
// around Go's standard library (crypto/rsa, crypto/aes, crypto/cipher,
// crypto/sha256, crypto/rand).
package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	// DefaultRSABits is the modulus size used for the experiment (3072-bit,
	// ~128-bit security strength per NIST SP 800-57 Part 1 Rev. 5).
	DefaultRSABits = 3072
	// MinRSABits is the smallest modulus this package will generate.
	MinRSABits = 2048
)

// GenerateRSAKey creates a new RSA key pair using crypto/rand.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < MinRSABits {
		return nil, fmt.Errorf("rsa key size %d is below minimum %d", bits, MinRSABits)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// oaepLabel binds a wrapped session key to the recipient key_id.
func oaepLabel(keyID string) []byte {
	return []byte("sentinel/v1/session-key/" + keyID)
}

// WrapSessionKey encrypts a session key with RSA-OAEP (SHA-256 for both the
// OAEP hash and MGF1). The key_id is used as the OAEP label.
func WrapSessionKey(pub *rsa.PublicKey, keyID string, sessionKey []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, sessionKey, oaepLabel(keyID))
}

// UnwrapSessionKey reverses WrapSessionKey. All failures collapse into
// ErrDecryptKey.
func UnwrapSessionKey(priv *rsa.PrivateKey, keyID string, wrapped []byte) ([]byte, error) {
	k, err := rsa.DecryptOAEP(sha256.New(), nil, priv, wrapped, oaepLabel(keyID))
	if err != nil || len(k) != SessionKeySize {
		return nil, ErrDecryptKey
	}
	return k, nil
}

var pssOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}

// Sign produces an RSA-PSS (SHA-256) signature over msg.
func Sign(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, h[:], pssOpts)
}

// Verify checks an RSA-PSS (SHA-256) signature over msg.
func Verify(pub *rsa.PublicKey, msg, sig []byte) error {
	h := sha256.Sum256(msg)
	return rsa.VerifyPSS(pub, crypto.SHA256, h[:], sig, pssOpts)
}

// Fingerprint returns the hex SHA-256 digest of the DER (PKIX) encoding of
// the public key. It is used for public-key pinning.
func Fingerprint(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// ---- PEM helpers -----------------------------------------------------

func EncodePrivateKeyPEM(priv *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func EncodePublicKeyPEM(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func ParsePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("no PEM block found")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return priv, nil
}

func ParsePublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("no PEM block found")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	if pub.N.BitLen() < MinRSABits {
		return nil, fmt.Errorf("rsa public key too small (%d bits)", pub.N.BitLen())
	}
	return pub, nil
}
