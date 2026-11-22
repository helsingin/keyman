//go:build integration

package pkcs11

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

func TestTokenMLDSA65(t *testing.T) {
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
	id := fmt.Sprintf("mldsa-%d", time.Now().UnixNano())
	if _, err = m.CreateKey(ctx, keyring.KeyTypeMLDSA65, id); err != nil {
		t.Fatal(err)
	}
	msg := []byte("sign this message")
	opts := crypto.Hash(0)
	var previous []byte
	for v := 1; v <= 2; v++ {
		signer, err := m.ManagedSigner(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		pub := signer.Public().(MLDSA65PublicKey)
		if len(pub) != 1952 || bytes.Equal(pub, previous) {
			t.Fatal("invalid or repeated public key")
		}
		previous = pub
		sig, err := signer.Sign(nil, msg, opts)
		if err != nil || len(sig) != 3309 {
			t.Fatalf("sign: length %d, error %v", len(sig), err)
		}
		if err = m.Verify(ctx, id, msg, sig, opts); err != nil {
			t.Fatal(err)
		}
		if err = m.Verify(ctx, id, []byte("altered"), sig, opts); err == nil {
			t.Fatal("accepted altered message")
		}
		if _, err = m.Sign(ctx, id, msg, crypto.SHA256); err == nil {
			t.Fatal("accepted prehash options")
		}
		h, err := m.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(id, v), false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = m.getValueLocked(h); !errors.Is(err, p11.Error(p11.CKR_ATTRIBUTE_SENSITIVE)) {
			t.Fatalf("private value read: %v", err)
		}
		attrs, err := m.ctx.GetAttributeValue(m.session, h, []*p11.Attribute{p11.NewAttribute(p11.CKA_NEVER_EXTRACTABLE, nil)})
		if err != nil || !bytes.Equal(attrs[0].Value, []byte{1}) {
			t.Fatalf("never extractable: %v, %v", attrs, err)
		}
		if v == 1 {
			if _, err = m.RotateKey(ctx, id); err != nil {
				t.Fatal(err)
			}
			if err = m.Verify(ctx, id, msg, sig, opts); err == nil {
				t.Fatal("new version accepted old signature")
			}
		}
	}
	if err = m.DeleteKey(ctx, id); err != nil {
		t.Fatal(err)
	}
	for v := 1; v <= 2; v++ {
		if _, err = m.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(id, v), false); !errors.Is(err, keyring.ErrKeyNotFound) {
			t.Fatalf("deleted version %d: %v", v, err)
		}
	}
}
