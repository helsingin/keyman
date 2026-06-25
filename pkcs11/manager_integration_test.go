//go:build integration

package pkcs11

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/helsingin/keyman"
)

func TestManagerLifecycleIntegration(t *testing.T) {
	modulePath := os.Getenv("PKCS11_MODULE_PATH")
	if modulePath == "" {
		t.Skip("PKCS11_MODULE_PATH is not set")
	}

	mgr, err := New(Config{
		ModulePath: modulePath,
		TokenLabel: envDefault("PKCS11_TOKEN_LABEL", "KEYMAN"),
		PIN:        envDefault("PKCS11_PIN", "1234"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		if err := mgr.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}()

	ctx := context.Background()
	suffix := time.Now().UnixNano()

	aesID := fmt.Sprintf("aes-%d", suffix)
	if _, err := mgr.CreateKey(ctx, keyring.KeyTypeAES256GCM, aesID); err != nil {
		t.Fatalf("CreateKey AES: %v", err)
	}
	ctV1, err := mgr.Encrypt(ctx, aesID, []byte("old payload"), []byte("tenant=demo"))
	if err != nil {
		t.Fatalf("Encrypt v1: %v", err)
	}
	if ctV1.KeyVersion != 1 {
		t.Fatalf("ciphertext version = %d, want 1", ctV1.KeyVersion)
	}
	if _, err := mgr.RotateKey(ctx, aesID); err != nil {
		t.Fatalf("RotateKey AES: %v", err)
	}
	pt, err := mgr.Decrypt(ctx, ctV1)
	if err != nil {
		t.Fatalf("Decrypt old ciphertext: %v", err)
	}
	if string(pt) != "old payload" {
		t.Fatalf("plaintext = %q", pt)
	}
	ctV2, err := mgr.Encrypt(ctx, aesID, []byte("new payload"), nil)
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}
	if ctV2.KeyVersion != 2 {
		t.Fatalf("ciphertext version = %d, want 2", ctV2.KeyVersion)
	}

	rsaID := fmt.Sprintf("rsa-%d", suffix)
	if _, err := mgr.CreateKey(ctx, keyring.KeyTypeRSA4096, rsaID); err != nil {
		t.Fatalf("CreateKey RSA: %v", err)
	}
	digest := sha256.Sum256([]byte("signed payload"))
	sig, err := mgr.Sign(ctx, rsaID, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign RSA: %v", err)
	}
	if err := mgr.Verify(ctx, rsaID, digest[:], sig, crypto.SHA256); err != nil {
		t.Fatalf("Verify RSA: %v", err)
	}
	if pub, err := mgr.PublicKey(ctx, rsaID); err != nil {
		t.Fatalf("PublicKey RSA: %v", err)
	} else if rsaPub, ok := pub.(*rsa.PublicKey); !ok || rsaPub.N.BitLen() < 4096 {
		t.Fatalf("unexpected RSA public key: %T", pub)
	}

	certLabel := fmt.Sprintf("cert-%d", suffix)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(suffix),
		Subject: pkix.Name{
			CommonName:   "keyman integration",
			Organization: []string{"Example"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	cert, err := mgr.SelfSignCertificate(ctx, rsaID, certLabel, template)
	if err != nil {
		t.Fatalf("SelfSignCertificate: %v", err)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("self-signed certificate verification: %v", err)
	}
	tlsCert, err := mgr.ManagedTLSCertificate(ctx, certLabel, rsaID)
	if err != nil {
		t.Fatalf("ManagedTLSCertificate: %v", err)
	}
	signer, ok := tlsCert.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("TLS private key does not implement crypto.Signer: %T", tlsCert.PrivateKey)
	}
	tlsSig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("TLS signer Sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(tlsCert.Leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], tlsSig); err != nil {
		t.Fatalf("TLS signer verification: %v", err)
	}

	ecdsaID := fmt.Sprintf("ecdsa-%d", suffix)
	if _, err := mgr.CreateKey(ctx, keyring.KeyTypeECDSAP256, ecdsaID); err != nil {
		t.Fatalf("CreateKey ECDSA: %v", err)
	}
	ecdsaSig, err := mgr.Sign(ctx, ecdsaID, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign ECDSA: %v", err)
	}
	if err := mgr.Verify(ctx, ecdsaID, digest[:], ecdsaSig, crypto.SHA256); err != nil {
		t.Fatalf("Verify ECDSA: %v", err)
	}
}

func envDefault(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
