//go:build integration

package pkcs11

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"crypto/sha512"
	"fmt"
	"os"
	"testing"
	"time"

	keyring "github.com/helsingin/keyman"
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
	got, err := m.Decrypt(ctx, sealed)
	if err != nil || !bytes.Equal(got, []byte("batch interop")) {
		t.Fatalf("open: %v", err)
	}
	for _, key := range []string{id, id + "-a", id + "-b"} {
		if err := m.DeleteKey(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
}
