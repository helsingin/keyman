package pkcs11

import (
	"testing"
	"time"

	"github.com/helsingin/keyman"
)

func TestMetadataRoundTrip(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	rotated := created.Add(time.Hour)
	input := keyMetadata{
		Type:      keyring.KeyTypeAES256GCM,
		Version:   2,
		CreatedAt: created,
		RotatedAt: rotated,
	}

	encoded, err := encodeMetadata(input)
	if err != nil {
		t.Fatalf("encodeMetadata: %v", err)
	}
	got, err := decodeMetadata(encoded)
	if err != nil {
		t.Fatalf("decodeMetadata: %v", err)
	}
	if got != input {
		t.Fatalf("metadata mismatch\ngot:  %#v\nwant: %#v", got, input)
	}
}

func TestDecodeMetadataRejectsInvalid(t *testing.T) {
	if _, err := decodeMetadata([]byte(`{"type":"aes-256-gcm","version":0}`)); err == nil {
		t.Fatal("decodeMetadata accepted invalid metadata")
	}
}
