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
	ctx := t.Context()
	key, err := mgr.CreateKey(ctx, keyring.KeyTypeMLDSA65, fmt.Sprintf("interop-%d", time.Now().UnixNano()))
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
	public := pqc.PublicKey{ID: key.ID, Version: key.Version, Algorithm: pqc.AlgorithmMLDSA65, Use: pqc.KeyUseSignature, PublicKey: pub.(pkcs11.MLDSA65PublicKey)}
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
	}
}
