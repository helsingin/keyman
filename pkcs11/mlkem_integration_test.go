//go:build integration

package pkcs11

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

func TestTokenMLKEM768(t *testing.T) {
	path := os.Getenv("PKCS11_MODULE_PATH")
	if path == "" {
		t.Skip("PKCS11_MODULE_PATH is not set")
	}
	config := Config{ModulePath: path, TokenLabel: envDefault("PKCS11_TOKEN_LABEL", "KEYMAN"), PIN: envDefault("PKCS11_PIN", "1234")}
	m, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	ctx := context.Background()
	name := fmt.Sprintf("kem-%d", time.Now().UnixNano())
	if _, err := m.CreateKey(ctx, keyring.KeyTypeMLKEM768, name); err != nil {
		t.Fatal(err)
	}
	pub, err := m.PublicKey(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	tokenPublic, ok := pub.(*mlkem.EncapsulationKey768)
	if !ok {
		t.Fatal("invalid ML-KEM-768 public key")
	}
	private, err := m.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(name, 1), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, attr := range []uint{p11.CKA_VALUE, 0x637 /* CKA_SEED */} {
		_, err := m.ctx.GetAttributeValue(m.session, private, []*p11.Attribute{p11.NewAttribute(attr, nil)})
		if !errors.Is(err, p11.Error(p11.CKR_ATTRIBUTE_SENSITIVE)) {
			t.Fatalf("read of private attribute %#x returned %v", attr, err)
		}
	}
	for _, attr := range []uint{p11.CKA_ALWAYS_SENSITIVE, p11.CKA_NEVER_EXTRACTABLE} {
		got, err := m.ctx.GetAttributeValue(m.session, private, []*p11.Attribute{p11.NewAttribute(attr, nil)})
		if err != nil || len(got) != 1 || !bytes.Equal(got[0].Value, []byte{1}) {
			t.Fatalf("private key flag %#x missing: %v", attr, err)
		}
	}
	confirm := func(secret, ciphertext []byte) []byte {
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte("Keyman ML-KEM-768 confirmation v1\x00"))
		mac.Write(ciphertext)
		return mac.Sum(nil)
	}
	shared, ct := tokenPublic.Encapsulate()
	secret, err := m.nativeKEMLocked(false, private, ct)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := m.ctx.GetAttributeValue(m.session, secret, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_TOKEN, nil), p11.NewAttribute(p11.CKA_EXTRACTABLE, nil), p11.NewAttribute(p11.CKA_SENSITIVE, nil),
	})
	if err != nil || len(flags) != 3 || !bytes.Equal(flags[0].Value, []byte{0}) || !bytes.Equal(flags[1].Value, []byte{0}) || !bytes.Equal(flags[2].Value, []byte{1}) {
		t.Fatalf("unexpected shared secret protection: %v", err)
	}
	if _, err := m.getValueLocked(secret); !errors.Is(err, p11.Error(p11.CKR_ATTRIBUTE_SENSITIVE)) {
		t.Fatalf("read of shared secret returned %v", err)
	}
	if err := m.ctx.DestroyObject(m.session, secret); err != nil {
		t.Fatal(err)
	}
	got, err := m.DecapsulateMLKEM768Proof(ctx, name, ct)
	if err != nil || !hmac.Equal(got, confirm(shared, ct)) {
		t.Fatalf("Go to token confirmation failed: %v", err)
	}
	bad := bytes.Clone(ct)
	bad[0] ^= 1
	got, err = m.DecapsulateMLKEM768Proof(ctx, name, bad)
	if err != nil || hmac.Equal(got, confirm(shared, bad)) {
		t.Fatalf("altered ciphertext failed implicit rejection: %v", err)
	}
	if _, err := m.DecapsulateMLKEM768Proof(ctx, name, ct[:len(ct)-1]); err == nil {
		t.Fatal("accepted truncated ciphertext")
	}
	peer, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	out, got, err := m.EncapsulateMLKEM768Proof(ctx, peer.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	shared, err = peer.Decapsulate(out)
	if err != nil || !hmac.Equal(got, confirm(shared, out)) {
		t.Fatalf("token to Go confirmation failed: %v", err)
	}
	if err := m.DeleteKey(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	m = reopened
	if _, err := m.DecapsulateMLKEM768Proof(ctx, name, ct); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("retired key returned %v", err)
	}
	if _, err := m.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(name, 1), false); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("retired private object returned %v", err)
	}
}
