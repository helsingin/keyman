package interop

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/helsingin/keyman"
	"github.com/helsingin/keyman/pkcs11"
)

// Only public keys and signatures cross into the OpenSSL verifier. This checks
// format/API interoperability, not independent cryptographic implementations:
// the test token's SoftHSM backend also uses OpenSSL.
func TestVerifyTokenSignature(t *testing.T) {
	mgr, err := pkcs11.New(pkcs11.Config{ModulePath: os.Getenv("PKCS11_MODULE_PATH"), TokenLabel: os.Getenv("PKCS11_TOKEN_LABEL"), PIN: os.Getenv("PKCS11_PIN")})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	for _, profile := range []struct {
		keyType keyring.KeyType
		oid     int
	}{
		{keyring.KeyTypeMLDSA65, 18},
		{keyring.KeyTypeMLDSA87, 19},
		{keyring.KeyTypeSLHDSASHA2192s, 22},
		{keyring.KeyTypeSLHDSASHA2256s, 24},
	} {
		t.Run(string(profile.keyType), func(t *testing.T) {
			testTokenSignature(t, mgr, profile.keyType, profile.oid)
		})
	}
}

func testTokenSignature(t *testing.T, mgr *pkcs11.Manager, keyType keyring.KeyType, oid int) {
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
	public := publicKeyDER(t, pub, oid)
	oldSigner, err := mgr.ManagedSigner(ctx, key.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range [][]byte{[]byte("Keyman token signature"), {}} {
		sig, err := mgr.Sign(ctx, key.ID, msg, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		verify(t, public, msg, sig, "", true)
		verify(t, public, []byte("changed"), sig, "", false)
		verify(t, public, msg, sig, "unexpected context", false)
		verify(t, public, msg, sig[:len(sig)-1], "", false)
	}
	// A previously opened signer remains tied to v1 after rotation; manager
	// operations use the new version. Historical signatures must remain valid.
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
	verify(t, public, message, saved, "", true)
	oldSignature, err := oldSigner.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	verify(t, public, message, oldSignature, "", true)
	newPub, err := mgr.PublicKey(ctx, key.ID)
	if err != nil {
		t.Fatal(err)
	}
	newPublic := publicKeyDER(t, newPub, oid)
	verify(t, newPublic, message, oldSignature, "", false)
	signature, err := mgr.Sign(ctx, key.ID, message, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	verify(t, newPublic, message, signature, "", true)
}

func verify(t *testing.T, public, message, signature []byte, context string, valid bool) {
	t.Helper()
	accepted, err := verifyOpenSSL(public, message, signature, []byte(context))
	if err != nil {
		t.Fatalf("OpenSSL verifier error: %v", err)
	}
	if accepted != valid {
		t.Fatalf("OpenSSL verification = %t, want %t (message=%d bytes, signature=%d bytes, context=%q)", accepted, valid, len(message), len(signature), context)
	}
}

func publicKeyDER(t *testing.T, pub any, oid int) []byte {
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
	// NIST signature OIDs, with absent parameters, in SubjectPublicKeyInfo.
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, oid}}, asn1.BitString{Bytes: raw, BitLength: len(raw) * 8}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}
