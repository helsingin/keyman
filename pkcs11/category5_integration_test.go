//go:build integration

package pkcs11

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	keyring "github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

func TestCategory5PrivateObjects(t *testing.T) {
	if os.Getenv("PKCS11_MODULE_PATH") == "" {
		t.Skip("requires disposable PKCS11 token")
	}
	cfg := Config{ModulePath: os.Getenv("PKCS11_MODULE_PATH"), TokenLabel: os.Getenv("PKCS11_TOKEN_LABEL"), PIN: os.Getenv("PKCS11_PIN")}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	ctx := context.Background()
	for _, typ := range []keyring.KeyType{"ml-dsa-87", "ml-kem-1024"} {
		id := "test-" + string(typ)
		if _, err := m.CreateKey(ctx, typ, id); err != nil {
			t.Fatal(err)
		}
		h, err := m.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(id, 1), false)
		if err != nil {
			t.Fatal(err)
		}
		for _, attr := range []uint{p11.CKA_VALUE, 0x637} {
			_, err := m.ctx.GetAttributeValue(m.session, h, []*p11.Attribute{p11.NewAttribute(attr, nil)})
			if !errors.Is(err, p11.Error(p11.CKR_ATTRIBUTE_SENSITIVE)) {
				t.Fatalf("%s private attribute %#x: %v", typ, attr, err)
			}
		}
		for _, attr := range []uint{p11.CKA_ALWAYS_SENSITIVE, p11.CKA_NEVER_EXTRACTABLE} {
			flags, err := m.ctx.GetAttributeValue(m.session, h, []*p11.Attribute{p11.NewAttribute(attr, nil)})
			if err != nil || len(flags) != 1 || !bytes.Equal(flags[0].Value, []byte{1}) {
				t.Fatalf("%s protection flag %#x: %v", typ, attr, err)
			}
		}
		if typ == "ml-dsa-87" {
			msg := []byte("category 5 token proof")
			sig, err := m.Sign(ctx, id, msg, crypto.Hash(0))
			if err != nil || len(sig) != 4627 {
				t.Fatalf("signature size %d: %v", len(sig), err)
			}
			if err := m.Verify(ctx, id, msg, sig, crypto.Hash(0)); err != nil {
				t.Fatal(err)
			}
		}
		if typ == "ml-kem-1024" {
			k, err := m.PublicKey(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			var binding [64]byte
			batch, sender, err := m.WrapKeyBatch1024(ctx, k.(*mlkem.EncapsulationKey1024), binding, []string{"sender-slot"})
			if err != nil {
				t.Fatal(err)
			}
			shared, challenge := k.(*mlkem.EncapsulationKey1024).Encapsulate()
			expected := hmac.New(sha256.New, shared)
			expected.Write([]byte("Keyman ML-KEM-1024 confirmation v1\x00"))
			expected.Write(challenge)
			tag, err := m.DecapsulateMLKEM1024Proof(ctx, id, challenge)
			if err != nil || !hmac.Equal(tag, expected.Sum(nil)) {
				t.Fatalf("key confirmation: %v", err)
			}
			record, err := m.Encrypt(ctx, "sender-slot", []byte("signed contact directory"), binding[:])
			if err != nil {
				t.Fatal(err)
			}
			body, err := m.OpenWrappedMLKEM1024(ctx, id, batch.Ciphertext, batch.Wrapped[0], record.Nonce, record.Ciphertext, record.AAD)
			if err != nil || !bytes.Equal(body, []byte("signed contact directory")) {
				t.Fatalf("open directory: %v", err)
			}
			if _, err := m.OpenWrappedMLKEM768(ctx, id, batch.Ciphertext, batch.Wrapped[0], record.Nonce, record.Ciphertext, record.AAD); err == nil {
				t.Fatal("incorrect envelope suite accepted")
			}
			receiver, err := m.UnwrapKeyBatch1024(ctx, id, binding, batch, []string{"receiver-slot"})
			if err != nil || sender != receiver {
				t.Fatalf("batch confirmation: %v", err)
			}
			if err := m.DeleteKey(ctx, id); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			m, err = New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.UnwrapKeyBatch1024(ctx, id, binding, batch, []string{"retired-slot"}); !errors.Is(err, keyring.ErrKeyNotFound) {
				t.Fatalf("retired decapsulation key: %v", err)
			}
			for _, name := range []string{"sender-slot", "receiver-slot"} {
				if err := m.DeleteKey(ctx, name); err != nil {
					t.Fatal(err)
				}
			}
			continue
		}
		if err := m.DeleteKey(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
}
