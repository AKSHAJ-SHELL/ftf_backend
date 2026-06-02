package email

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// Fake records every Send into memory. Useful for tests and as a local-dev
// fallback when RESEND_API_KEY is empty.
type Fake struct {
	mu       sync.Mutex
	Sent     []Message
	FailNext error
}

func NewFake() *Fake { return &Fake{} }

func (f *Fake) Send(_ context.Context, m Message) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNext != nil {
		err := f.FailNext
		f.FailNext = nil
		return "", err
	}
	f.Sent = append(f.Sent, m)
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "fake_" + hex.EncodeToString(b[:]), nil
}

// Drain returns and clears recorded messages.
func (f *Fake) Drain() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.Sent
	f.Sent = nil
	return out
}
