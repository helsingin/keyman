package pkcs11

import (
	"crypto"
	"crypto/sha256"
	"testing"
)

func TestDigestInfoSHA256(t *testing.T) {
	digest := sha256.Sum256([]byte("payload"))
	info, err := digestInfo(digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("digestInfo: %v", err)
	}
	if len(info) <= len(digest) {
		t.Fatalf("digestInfo length = %d, want > %d", len(info), len(digest))
	}
	if got := info[len(info)-len(digest):]; string(got) != string(digest[:]) {
		t.Fatal("digestInfo does not end with digest")
	}
}

func TestDigestInfoRejectsWrongLength(t *testing.T) {
	if _, err := digestInfo([]byte("short"), crypto.SHA256); err == nil {
		t.Fatal("digestInfo accepted wrong digest length")
	}
}
