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
		{keyring.KeyTypeSLHDSASHA2192s, pqc.AlgorithmSLHDSASHA2192s},
		{keyring.KeyTypeSLHDSASHA2256s, pqc.AlgorithmSLHDSASHA2256s},
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
	raw := rawSigningPublicKey(t, pub)
	public := pqc.PublicKey{ID: key.ID, Version: key.Version, Algorithm: algorithm, Use: pqc.KeyUseSignature, PublicKey: raw}
	oldSigner, err := mgr.ManagedSigner(ctx, key.ID)
	if err != nil {
		t.Fatal(err)
	}
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
	// Preserve the v1 public key and signer across rotation. A previously opened
	// signer remains tied to v1; manager operations use the new version.
	message := []byte("versioned evidence")
	saved, err := mgr.Sign(ctx, key.ID, message, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := mgr.RotateKey(ctx, key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Type != keyType || rotated.Version != 2 {
		t.Fatalf("unexpected rotated key: %+v", rotated)
	}
	envelope := pqc.SignatureEnvelope{Schema: pqc.SignatureSchema, KeyID: key.ID, KeyVersion: 1, Algorithm: algorithm, Signature: saved}
	if err := pqc.VerifyWithPublicKey(public, message, &envelope); err != nil {
		t.Fatal(err)
	}
	oldSignature, err := oldSigner.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = oldSignature
	if err := pqc.VerifyWithPublicKey(public, message, &envelope); err != nil {
		t.Fatalf("version-bound signer: %v", err)
	}
	newPub, err := mgr.PublicKey(ctx, key.ID)
	if err != nil {
		t.Fatal(err)
	}
	newPublic := public
	newPublic.PublicKey = rawSigningPublicKey(t, newPub)
	// Keep v1 metadata to test wrong key material, not only a version mismatch.
	if err := pqc.VerifyWithPublicKey(newPublic, message, &envelope); err == nil {
		t.Fatal("accepted wrong key material")
	}
	newPublic.Version = rotated.Version
	signature, err := mgr.Sign(ctx, key.ID, message, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	envelope.KeyVersion = rotated.Version
	envelope.Signature = signature
	if err := pqc.VerifyWithPublicKey(newPublic, message, &envelope); err != nil {
		t.Fatalf("rotated signature: %v", err)
	}

}

func rawSigningPublicKey(t *testing.T, pub any) []byte {
	t.Helper()
	var raw []byte
	switch p := pub.(type) {
	case pkcs11.MLDSA65PublicKey:
		raw = p
	case pkcs11.MLDSA87PublicKey:
		raw = p
	case pkcs11.SLHDSASHA2192sPublicKey:
		raw = p
	case pkcs11.SLHDSASHA2256sPublicKey:
		raw = p
	default:
		t.Fatalf("unexpected public key type %T", pub)
	}
	return raw
}
