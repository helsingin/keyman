package pkcs11

import "testing"

func TestLabels(t *testing.T) {
	if got := keyLabel("session-key", 3); got != "session-key:v3" {
		t.Fatalf("keyLabel() = %q", got)
	}
	if got := publicKeyManel("signing-key", 2); got != "signing-key:v2:public" {
		t.Fatalf("publicKeyManel() = %q", got)
	}
	if got := privateKeyManel("signing-key", 2); got != "signing-key:v2:private" {
		t.Fatalf("privateKeyManel() = %q", got)
	}
	if got := metadataLabel("session-key"); got != "session-key:meta" {
		t.Fatalf("metadataLabel() = %q", got)
	}
}

func TestValidateKeyName(t *testing.T) {
	for _, name := range []string{"", "bad:name", "bad\x00name"} {
		if err := validateKeyName(name); err == nil {
			t.Fatalf("validateKeyName(%q) returned nil", name)
		}
	}
	if err := validateKeyName("good-name"); err != nil {
		t.Fatalf("validateKeyName(good-name): %v", err)
	}
}
