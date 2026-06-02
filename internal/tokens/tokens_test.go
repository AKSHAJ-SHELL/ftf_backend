package tokens

import (
	"bytes"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestRoundTrip(t *testing.T) {
	s := NewSigner(testKey)
	subj := []byte{0xab, 0xcd, 0xef}
	tok, err := s.Issue(PurposeConfirmSubscriber, subj, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Verify(tok, PurposeConfirmSubscriber)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, subj) {
		t.Fatalf("subject mismatch: %x vs %x", got, subj)
	}
}

func TestPurposeMismatch(t *testing.T) {
	s := NewSigner(testKey)
	tok, _ := s.Issue(PurposeConfirmSubscriber, []byte{1}, time.Now().Add(time.Hour))
	if _, err := s.Verify(tok, PurposeUnsubscribeSubscriber); err == nil {
		t.Fatal("expected purpose mismatch")
	}
}

func TestTamperDetection(t *testing.T) {
	s := NewSigner(testKey)
	tok, _ := s.Issue(PurposeConfirmSubscriber, []byte{1, 2, 3}, time.Now().Add(time.Hour))
	tampered := []byte(tok)
	tampered[0] ^= 0x01
	if _, err := s.Verify(string(tampered), PurposeConfirmSubscriber); err == nil {
		t.Fatal("expected tamper rejection")
	}
}

func TestExpiry(t *testing.T) {
	s := NewSigner(testKey)
	tok, _ := s.Issue(PurposeConfirmSubscriber, []byte{1}, time.Now().Add(-time.Second))
	if _, err := s.Verify(tok, PurposeConfirmSubscriber); err == nil {
		t.Fatal("expected expiry rejection")
	}
}

func TestUnlimitedExpiry(t *testing.T) {
	s := NewSigner(testKey)
	tok, _ := s.Issue(PurposeUnsubscribeSubscriber, []byte{1}, time.Time{})
	if _, err := s.Verify(tok, PurposeUnsubscribeSubscriber); err != nil {
		t.Fatalf("expected no-expiry token to verify, got %v", err)
	}
}

func TestDifferentKeyRejects(t *testing.T) {
	s1 := NewSigner(testKey)
	s2 := NewSigner(bytes.Repeat([]byte{0x42}, 32))
	tok, _ := s1.Issue(PurposeConfirmSubscriber, []byte{1}, time.Now().Add(time.Hour))
	if _, err := s2.Verify(tok, PurposeConfirmSubscriber); err == nil {
		t.Fatal("expected bad signature on different key")
	}
}

func TestShortKeyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on short key")
		}
	}()
	_ = NewSigner([]byte("short"))
}

func TestHashStable(t *testing.T) {
	if !bytes.Equal(Hash("abc"), Hash("abc")) {
		t.Fatal("hash unstable")
	}
	if bytes.Equal(Hash("abc"), Hash("abd")) {
		t.Fatal("collision on trivial input")
	}
}
