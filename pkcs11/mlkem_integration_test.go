//go:build integration

package pkcs11

import (
	"context"
	"crypto/mlkem"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/helsingin/keyman"
)

func TestTokenMLKEM768(t *testing.T) {
	path := os.Getenv("PKCS11_MODULE_PATH")
	if path == "" {
		t.Skip("PKCS11_MODULE_PATH is not set")
	}
	m, err := New(Config{ModulePath: path, TokenLabel: envDefault("PKCS11_TOKEN_LABEL", "KEYMAN"), PIN: envDefault("PKCS11_PIN", "1234")})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx := context.Background()
	name := fmt.Sprintf("kem-%d", time.Now().UnixNano())
	if _, err := m.CreateKey(ctx, keyring.KeyType("ml-kem-768"), name); err != nil {
		t.Fatal(err)
	}
	pub, err := m.PublicKey(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*mlkem.EncapsulationKey768); !ok {
		t.Fatal("invalid ML-KEM-768 public key")
	}
	if err := m.DeleteKey(ctx, name); err != nil {
		t.Fatal(err)
	}
}
