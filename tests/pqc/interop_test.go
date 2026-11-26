package interop

import (
	"crypto"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/helsingin/keyman"
	"github.com/helsingin/keyman/pkcs11"
	"github.com/helsingin/pqc"
)

// Only the exported verification key and signature cross into pqc.
func TestVerifyTokenSignature(t *testing.T) {
	mgr, err := pkcs11.New(pkcs11.Config{ModulePath: os.Getenv("PKCS11_MODULE_PATH"), TokenLabel: os.Getenv("PKCS11_TOKEN_LABEL"), PIN: os.Getenv("PKCS11_PIN")})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	for _, profile := range []struct {
		keyType   keyring.KeyType
		algorithm pqc.Algorithm
	}{
		{keyring.KeyTypeMLDSA65, pqc.AlgorithmMLDSA65},
		{keyring.KeyTypeMLDSA87, pqc.AlgorithmMLDSA87},
	} {
		t.Run(string(profile.algorithm), func(t *testing.T) {
			testTokenSignature(t, mgr, profile.keyType, profile.algorithm)
		})
	}
}

func testTokenSignature(t *testing.T, mgr *pkcs11.Manager, keyType keyring.KeyType, algorithm pqc.Algorithm) {
	ctx := t.Context()
	key, err := mgr.CreateKey(ctx, keyType, fmt.Sprintf("interop-%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := mgr.DeleteKey(ctx, key.ID); err != nil {
			t.Error(err)
		}
	}()
	pub, err := mgr.PublicKey(ctx, key.ID)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	switch p := pub.(type) {
	case pkcs11.MLDSA65PublicKey:
		raw = p
	case pkcs11.MLDSA87PublicKey:
		raw = p
	default:
		t.Fatalf("unexpected public key type %T", pub)
	}
	public := pqc.PublicKey{ID: key.ID, Version: key.Version, Algorithm: algorithm, Use: pqc.KeyUseSignature, PublicKey: raw}
	for _, msg := range [][]byte{[]byte("Keyman token signature"), {}} {
		sig, err := mgr.Sign(ctx, key.ID, msg, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		envelope := pqc.SignatureEnvelope{Schema: pqc.SignatureSchema, KeyID: key.ID, KeyVersion: key.Version, Algorithm: public.Algorithm, Signature: sig}
		if err := pqc.VerifyWithPublicKey(public, msg, &envelope); err != nil {
			t.Fatal(err)
		}
		if err := pqc.VerifyWithPublicKey(public, []byte("changed"), &envelope); err == nil {
			t.Fatal("accepted altered message")
		}
		envelope.Context = []byte("unexpected context")
		if err := pqc.VerifyWithPublicKey(public, msg, &envelope); err == nil {
			t.Fatal("accepted wrong context")
		}
		envelope.Context = nil
		envelope.Signature = sig[:len(sig)-1]
		if err := pqc.VerifyWithPublicKey(public, msg, &envelope); err == nil {
			t.Fatal("accepted truncated signature")
		}
	}
}
