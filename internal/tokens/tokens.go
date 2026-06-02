// Package tokens issues and verifies short, opaque HMAC-signed strings tied
// to a specific purpose so a confirm-subscriber token can never be replayed
// as an unsubscribe token (and vice versa).
package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Purpose narrows a token to a single workflow.
type Purpose string

const (
	PurposeConfirmSubscriber     Purpose = "confirm_subscriber"
	PurposeUnsubscribeSubscriber Purpose = "unsubscribe_subscriber"
)

const (
	headerLen = 1 + 1 + 8 + 8 // version(1) + purpose-tag(1) + issued(8) + expires(8)
	macLen    = 32            // SHA-256
)

// Signer is goroutine-safe.
type Signer struct {
	key []byte
}

// NewSigner panics on empty key — caller has already validated len >= 32 at config load.
func NewSigner(key []byte) *Signer {
	if len(key) < 32 {
		panic("tokens: signing key must be at least 32 bytes")
	}
	cp := make([]byte, len(key))
	copy(cp, key)
	return &Signer{key: cp}
}

// Issue creates a token. `expiresAt` zero means no expiry (the format still
// carries the zero value; verifier treats zero as "no expiry").
func (s *Signer) Issue(purpose Purpose, subjectID []byte, expiresAt time.Time) (string, error) {
	pt := purposeByte(purpose)
	if pt == 0 {
		return "", fmt.Errorf("tokens: unknown purpose %q", purpose)
	}
	now := time.Now().UTC().Unix()
	var exp int64
	if !expiresAt.IsZero() {
		exp = expiresAt.UTC().Unix()
	}
	payload := make([]byte, headerLen+len(subjectID))
	payload[0] = 1
	payload[1] = pt
	binary.BigEndian.PutUint64(payload[2:10], uint64(now))
	binary.BigEndian.PutUint64(payload[10:18], uint64(exp))
	copy(payload[18:], subjectID)

	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	sig := mac.Sum(nil)

	out := append(payload, sig...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Verify decodes a token, checks signature constant-time, enforces the purpose
// matches the expected one, and enforces expiry if present.
func (s *Signer) Verify(token string, expected Purpose) (subjectID []byte, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, errors.New("tokens: malformed")
	}
	if len(raw) < headerLen+macLen {
		return nil, errors.New("tokens: too short")
	}
	payload := raw[:len(raw)-macLen]
	sig := raw[len(raw)-macLen:]

	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(sig, expectedSig) {
		return nil, errors.New("tokens: bad signature")
	}

	if payload[0] != 1 {
		return nil, errors.New("tokens: bad version")
	}
	if payload[1] != purposeByte(expected) {
		return nil, errors.New("tokens: purpose mismatch")
	}
	exp := int64(binary.BigEndian.Uint64(payload[10:18]))
	if exp != 0 && time.Now().UTC().Unix() > exp {
		return nil, errors.New("tokens: expired")
	}
	return payload[headerLen:], nil
}

// Hash returns a deterministic SHA-256 of a token, suitable for storing
// alongside a subscriber row so a stolen DB read does not reveal the raw token.
func Hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func purposeByte(p Purpose) byte {
	switch p {
	case PurposeConfirmSubscriber:
		return 1
	case PurposeUnsubscribeSubscriber:
		return 2
	default:
		return 0
	}
}
