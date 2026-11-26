package pkcs11

import (
	"errors"
	"testing"

	keyring "github.com/helsingin/keyman"
)

func TestSLHDSARejectsUnsupportedParameters(t *testing.T) {
	for _, typ := range []keyring.KeyType{"", "slh-dsa", "slh-dsa-sha2-128s", "slh-dsa-sha2-192f", "slh-dsa-shake-256s", keyring.KeyTypeMLDSA65} {
		if _, _, err := slhDSAParameters(typ); !errors.Is(err, keyring.ErrUnsupportedKeyType) {
			t.Fatalf("%q: %v", typ, err)
		}
		// Parameter selection must fail before attempting a token operation.
		m := &Manager{}
		if err := m.createSLHDSAKeyLocked("unused", 1, typ); !errors.Is(err, keyring.ErrUnsupportedKeyType) {
			t.Fatalf("%q: %v", typ, err)
		}
	}
}
