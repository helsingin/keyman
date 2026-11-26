//go:build integration

package pkcs11

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	keyring "github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

func TestTokenSLHDSALifecycle(t *testing.T) {
	if os.Getenv("PKCS11_MODULE_PATH") == "" {
		t.Skip("requires disposable PKCS11 token")
	}
	for _, profile := range []struct {
		typ                       keyring.KeyType
		publicSize, signatureSize int
	}{
		{keyring.KeyTypeSLHDSASHA2192s, 48, 16224},
		{keyring.KeyTypeSLHDSASHA2256s, 64, 29792},
	} {
		t.Run(string(profile.typ), func(t *testing.T) {
			cfg := Config{ModulePath: os.Getenv("PKCS11_MODULE_PATH"), TokenLabel: os.Getenv("PKCS11_TOKEN_LABEL"), PIN: os.Getenv("PKCS11_PIN")}
			m, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			id := fmt.Sprintf("slhdsa-%d", time.Now().UnixNano())
			ctx := t.Context()
			defer func() {
				if err := m.DeleteKey(ctx, id); err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
					t.Error(err)
				}
				if err := m.Close(); err != nil {
					t.Error(err)
				}
			}()
			key, err := m.CreateKey(ctx, profile.typ, id)
			if err != nil {
				t.Fatal(err)
			}
			if key.Type != profile.typ || key.Version != 1 {
				t.Fatalf("unexpected key metadata: %+v", key)
			}
			if _, err := m.CreateKey(ctx, profile.typ, id); err == nil {
				t.Fatal("duplicate key accepted")
			}
			message := []byte("token-backed SLH-DSA evidence")
			var previous []byte
			var lastSigner *Signer
			for version := 1; version <= 2; version++ {
				signer, err := m.ManagedSigner(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				lastSigner = signer
				var public []byte
				switch p := signer.Public().(type) {
				case SLHDSASHA2192sPublicKey:
					public = p
				case SLHDSASHA2256sPublicKey:
					public = p
				default:
					t.Fatalf("unexpected public key %T", p)
				}
				if len(public) != profile.publicSize || bytes.Equal(public, previous) {
					t.Fatal("invalid or repeated public key")
				}
				previous = public
				sig, err := signer.Sign(nil, message, crypto.Hash(0))
				if err != nil || len(sig) != profile.signatureSize {
					t.Fatalf("signature length %d: %v", len(sig), err)
				}
				if err := m.Verify(ctx, id, message, sig, crypto.Hash(0)); err != nil {
					t.Fatal(err)
				}
				if err := m.Verify(ctx, id, []byte("altered"), sig, crypto.Hash(0)); err == nil {
					t.Fatal("accepted altered message")
				}
				for _, bad := range [][]byte{nil, sig[:len(sig)-1], append(bytes.Clone(sig), 0)} {
					if err := m.Verify(ctx, id, message, bad, crypto.Hash(0)); err == nil {
						t.Fatal("accepted malformed signature")
					}
				}
				for _, opts := range []crypto.SignerOpts{nil, crypto.SHA256} {
					if _, err := m.Sign(ctx, id, message, opts); err == nil {
						t.Fatal("accepted invalid signing options")
					}
					if _, err := signer.Sign(nil, message, opts); err == nil {
						t.Fatal("signer accepted invalid options")
					}
					if err := m.Verify(ctx, id, message, sig, opts); err == nil {
						t.Fatal("verify accepted invalid options")
					}
				}
				private, err := m.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(id, version), false)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := m.getValueLocked(private); !errors.Is(err, p11.Error(p11.CKR_ATTRIBUTE_SENSITIVE)) {
					t.Fatalf("private key export: %v", err)
				}
				for attr, want := range map[uint]byte{p11.CKA_SENSITIVE: 1, p11.CKA_ALWAYS_SENSITIVE: 1, p11.CKA_EXTRACTABLE: 0, p11.CKA_NEVER_EXTRACTABLE: 1} {
					values, err := m.ctx.GetAttributeValue(m.session, private, []*p11.Attribute{p11.NewAttribute(attr, nil)})
					if err != nil || len(values) != 1 || !bytes.Equal(values[0].Value, []byte{want}) {
						t.Fatalf("protection attribute %#x: %v %v", attr, values, err)
					}
				}
				if err := m.ctx.SetAttributeValue(m.session, private, []*p11.Attribute{p11.NewAttribute(p11.CKA_EXTRACTABLE, true)}); err == nil {
					t.Fatal("made private key extractable")
				}
				wrappingKey, err := m.ctx.GenerateKey(m.session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_GEN, nil)}, []*p11.Attribute{
					p11.NewAttribute(p11.CKA_VALUE_LEN, 32), p11.NewAttribute(p11.CKA_WRAP, true), p11.NewAttribute(p11.CKA_TOKEN, false),
				})
				if err != nil {
					t.Fatal(err)
				}
				_, wrapErr := m.ctx.WrapKey(m.session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_WRAP_PAD, nil)}, wrappingKey, private)
				if err := m.ctx.DestroyObject(m.session, wrappingKey); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(wrapErr, p11.Error(p11.CKR_KEY_UNEXTRACTABLE)) {
					t.Fatalf("private key wrapping: %v", wrapErr)
				}
				if version == 1 {
					rotated, err := m.RotateKey(ctx, id)
					if err != nil {
						t.Fatal(err)
					}
					if rotated.Type != profile.typ || rotated.Version != 2 {
						t.Fatalf("unexpected rotated key: %+v", rotated)
					}
					if err := m.Verify(ctx, id, message, sig, crypto.Hash(0)); err == nil {
						t.Fatal("new key accepted old signature")
					}
				}
			}
			// Re-open the token session: metadata and both versions must persist.
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			m = reopened
			// Handles belong to their original session. Acquire a new signer before
			// checking that deletion retires the active signing capability.
			lastSigner, err = m.ManagedSigner(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			current, err := m.GetKey(ctx, id)
			if err != nil || current.Type != profile.typ || current.Version != 2 {
				t.Fatalf("reopened metadata: %v %v", current, err)
			}
			keys, err := m.ListKeys(ctx)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, k := range keys {
				if k.ID == id && k.Type == profile.typ && k.LatestVersion == 2 {
					found = true
				}
			}
			if !found {
				t.Fatal("missing key in inventory")
			}
			empty, err := m.Sign(ctx, id, nil, crypto.Hash(0))
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Verify(ctx, id, nil, empty, crypto.Hash(0)); err != nil {
				t.Fatal(err)
			}
			if err := m.DeleteKey(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err := lastSigner.Sign(nil, message, crypto.Hash(0)); err == nil {
				t.Fatal("deleted key still signs")
			}
			for version := 1; version <= 2; version++ {
				for _, object := range []struct {
					class uint
					label string
				}{
					{p11.CKO_PRIVATE_KEY, privateKeyManel(id, version)},
					{p11.CKO_PUBLIC_KEY, publicKeyManel(id, version)},
				} {
					if _, err := m.findOneLocked(object.class, object.label, false); !errors.Is(err, keyring.ErrKeyNotFound) {
						t.Fatalf("deleted object %s: %v", object.label, err)
					}
				}
			}
			if _, err := m.GetKey(ctx, id); !errors.Is(err, keyring.ErrKeyNotFound) {
				t.Fatalf("deleted metadata: %v", err)
			}
		})
	}
}
