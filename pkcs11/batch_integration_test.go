//go:build integration

package pkcs11

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	keyring "github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

func TestTokenWrappedBatch(t *testing.T) {
	path := os.Getenv("PKCS11_MODULE_PATH")
	if path == "" {
		t.Skip("requires token")
	}
	m, err := New(Config{ModulePath: path, TokenLabel: envDefault("PKCS11_TOKEN_LABEL", "KEYMAN"), PIN: envDefault("PKCS11_PIN", "1234")})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	checkKeyWrapVector(t, m)
	ctx := context.Background()
	id := fmt.Sprintf("test-batch-%d", time.Now().UnixNano())
	if _, err = m.CreateKey(ctx, keyring.KeyTypeMLKEM768, id); err != nil {
		t.Fatal(err)
	}
	pub, err := m.PublicKey(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	binding := sha512.Sum384([]byte("signed offer"))
	batch, sendTags, err := m.WrapKeyBatch(ctx, pub.(*mlkem.EncapsulationKey768), binding, []string{id + "-a"})
	if err != nil {
		t.Fatal(err)
	}
	recvTags, err := m.UnwrapKeyBatch(ctx, id, binding, batch, []string{id + "-b"})
	if err != nil || sendTags != recvTags || sendTags[0] == sendTags[1] {
		t.Fatalf("confirmation failed: %v", err)
	}
	sealed, err := m.Encrypt(ctx, id+"-a", []byte("batch interop"), []byte("header"))
	if err != nil {
		t.Fatal(err)
	}
	sealed.KeyID = id + "-b"
	opened, err := m.OpenWrappedMLKEM768(ctx, id, batch.Ciphertext, batch.Wrapped[0], sealed.Nonce, sealed.Ciphertext, sealed.AAD)
	if err != nil || !bytes.Equal(opened, []byte("batch interop")) {
		t.Fatalf("one-shot open: %v", err)
	}
	if _, err = m.OpenWrappedMLKEM768(ctx, id, batch.Ciphertext, batch.Wrapped[0], sealed.Nonce, sealed.Ciphertext, []byte("other")); err == nil {
		t.Fatal("accepted different AAD")
	}
	got, err := m.Decrypt(ctx, sealed)
	if err != nil || !bytes.Equal(got, []byte("batch interop")) {
		t.Fatalf("open: %v", err)
	}
	for _, name := range []string{id + "-a", id + "-b"} {
		key, err := m.findOneLocked(p11.CKO_SECRET_KEY, keyLabel(name, 1), false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = m.getValueLocked(key); !errors.Is(err, p11.Error(p11.CKR_ATTRIBUTE_SENSITIVE)) {
			t.Fatalf("traffic key export: %v", err)
		}
		flags, err := m.ctx.GetAttributeValue(m.session, key, []*p11.Attribute{p11.NewAttribute(p11.CKA_EXTRACTABLE, nil)})
		if err != nil || len(flags) != 1 || !bytes.Equal(flags[0].Value, []byte{0}) {
			t.Fatalf("traffic key flags: %v", err)
		}
	}
	batch.Wrapped[0][0] ^= 1
	if _, err := m.UnwrapKeyBatch(ctx, id, binding, batch, []string{id + "-bad"}); err == nil {
		t.Fatal("accepted modified wrapped key")
	}
	for _, key := range []string{id, id + "-a", id + "-b", id + "-bad"} {
		if err := m.DeleteKey(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
}

// RFC 3394 section 4.6, using the same native wrap mechanism as the batch.
func checkKeyWrapVector(t *testing.T, m *Manager) {
	t.Helper()
	object := func(raw string, usage uint) p11.ObjectHandle {
		value, err := hex.DecodeString(raw)
		if err != nil {
			t.Fatal(err)
		}
		h, err := m.ctx.CreateObject(m.session, []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY), p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
			p11.NewAttribute(p11.CKA_VALUE, value), p11.NewAttribute(p11.CKA_TOKEN, false), p11.NewAttribute(usage, true),
		})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	kek := object("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", p11.CKA_WRAP)
	key := object("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f", p11.CKA_EXTRACTABLE)
	got, err := m.ctx.WrapKey(m.session, mechanism(p11.CKM_AES_KEY_WRAP), kek, key)
	if err != nil || hex.EncodeToString(got) != "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21" {
		t.Fatalf("RFC 3394 section 4.6: %v", err)
	}
}
