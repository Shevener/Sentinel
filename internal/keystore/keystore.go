// Package keystore loads and writes key files for the Sentinel binaries.
//
// Layout produced by cmd/keygen:
//
//	keys/api/<key_id>.key.pem             API private key (RSA-OAEP unwrap)
//	keys/api/<key_id>.pub.pem             API public key
//	keys/workers/<worker_id>.key.pem      worker private key (RSA-PSS signing)
//	keys/trusted-workers/<worker_id>.pub.pem   worker public keys trusted by the API
//	keys/tls/cert.pem, keys/tls/key.pem   self-signed TLS pair (lab)
package keystore

import (
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sentinel/internal/crypto"
)

// LoadAPIKeys reads every <key_id>.key.pem in dir/api.
func LoadAPIKeys(root string) (map[string]*rsa.PrivateKey, error) {
	files, err := filepath.Glob(filepath.Join(root, "api", "*.key.pem"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no API keys found in %s/api (run cmd/keygen)", root)
	}
	out := map[string]*rsa.PrivateKey{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		k, err := crypto.ParsePrivateKeyPEM(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out[strings.TrimSuffix(filepath.Base(f), ".key.pem")] = k
	}
	return out, nil
}

// LoadTrustedWorkers reads every <worker_id>.pub.pem in root/trusted-workers.
func LoadTrustedWorkers(root string) (map[string]*rsa.PublicKey, error) {
	files, err := filepath.Glob(filepath.Join(root, "trusted-workers", "*.pub.pem"))
	if err != nil {
		return nil, err
	}
	out := map[string]*rsa.PublicKey{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		k, err := crypto.ParsePublicKeyPEM(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out[strings.TrimSuffix(filepath.Base(f), ".pub.pem")] = k
	}
	return out, nil
}

// LoadWorkerKey reads root/workers/<id>.key.pem.
func LoadWorkerKey(root, id string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(root, "workers", id+".key.pem"))
	if err != nil {
		return nil, err
	}
	return crypto.ParsePrivateKeyPEM(b)
}

// LoadAPIPublicKey reads root/api/<key_id>.pub.pem (used for pinning).
func LoadAPIPublicKey(root, keyID string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(filepath.Join(root, "api", keyID+".pub.pem"))
	if err != nil {
		return nil, err
	}
	return crypto.ParsePublicKeyPEM(b)
}

// WriteFile writes data with 0600 permissions, creating parent dirs (0700).
func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
