//go:build integration

package pkcs11

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/helsingin/keyman"
)

func TestTokenP256Agreement(t *testing.T) {
	module := os.Getenv("PKCS11_MODULE_PATH")
	if module == "" {
		t.Skip("PKCS11_MODULE_PATH is not set")
	}
	m, err := New(Config{ModulePath: module, TokenLabel: envDefault("PKCS11_TOKEN_LABEL", "KEYMAN"), PIN: envDefault("PKCS11_PIN", "1234")})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx := context.Background()
	name := fmt.Sprintf("agreement-%d", time.Now().UnixNano())
	if _, err := m.CreateP256SigningAndAgreementKey(ctx, name); err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 2; version++ {
		pub, err := m.PublicKey(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		dhPub, err := pub.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			t.Fatal(err)
		}
		want, err := peer.ECDH(dhPub)
		if err != nil {
			t.Fatal(err)
		}
		got, err := m.ECDH(ctx, name, peer.PublicKey())
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("agreement version %d: %v", version, err)
		}
		if _, err := m.ManagedSigner(ctx, name); err != nil {
			t.Fatal(err)
		}
		if version == 1 {
			if _, err := m.RotateKey(ctx, name); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := m.CreateKey(ctx, keyring.KeyTypeECDSAP256, name+"-sign"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ECDH(ctx, name+"-sign", peer.PublicKey()); err == nil {
		t.Fatal("signing-only key allowed ECDH")
	}
}
