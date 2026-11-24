package crypto

import "errors"

// Sentinel errors. Callers map these to security-event reasons; they are
// deliberately coarse so that the HTTP layer never leaks which internal
// step failed (see docs/crypto-design.md, "oracle avoidance").
var (
	ErrInvalidEnvelope = errors.New("invalid envelope")
	ErrSignature       = errors.New("sender signature verification failed")
	ErrDecryptKey      = errors.New("session key unwrap failed")
	ErrAuthFailed      = errors.New("aes-gcm authentication failed")
)
