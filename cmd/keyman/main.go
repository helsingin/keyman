package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/helsingin/keyman"
	"github.com/helsingin/keyman/pkcs11"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	modulePath := flag.String("module", envDefault("PKCS11_MODULE_PATH", ""), "PKCS#11 module path")
	tokenLabel := flag.String("token", envDefault("PKCS11_TOKEN_LABEL", "KEYMAN"), "PKCS#11 token label")
	pin := flag.String("pin", envDefault("PKCS11_PIN", ""), "PKCS#11 user PIN")
	flag.Parse()

	if flag.NArg() > 1 {
		return fmt.Errorf("usage: keyman [flags] [lifecycle]")
	}
	command := "lifecycle"
	if flag.NArg() == 1 {
		command = flag.Arg(0)
	}
	if command != "lifecycle" {
		return fmt.Errorf("unknown command %q", command)
	}

	manager, err := pkcs11.New(pkcs11.Config{
		ModulePath: *modulePath,
		TokenLabel: *tokenLabel,
		PIN:        *pin,
	})
	if err != nil {
		return err
	}
	defer manager.Close()

	return lifecycle(context.Background(), manager)
}

func lifecycle(ctx context.Context, manager keyring.Manager) error {
	suffix := time.Now().UTC().UnixNano()

	aesID := fmt.Sprintf("demo-aes-%d", suffix)
	if _, err := manager.CreateKey(ctx, keyring.KeyTypeAES256GCM, aesID); err != nil {
		return err
	}
	oldCiphertext, err := manager.Encrypt(ctx, aesID, []byte("old payload"), []byte("demo"))
	if err != nil {
		return err
	}
	if _, err := manager.RotateKey(ctx, aesID); err != nil {
		return err
	}
	oldPlaintext, err := manager.Decrypt(ctx, oldCiphertext)
	if err != nil {
		return err
	}
	newCiphertext, err := manager.Encrypt(ctx, aesID, []byte("new payload"), nil)
	if err != nil {
		return err
	}

	rsaID := fmt.Sprintf("demo-rsa-%d", suffix)
	if _, err := manager.CreateKey(ctx, keyring.KeyTypeRSA4096, rsaID); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte("signed payload"))
	signature, err := manager.Sign(ctx, rsaID, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	if err := manager.Verify(ctx, rsaID, digest[:], signature, crypto.SHA256); err != nil {
		return err
	}
	certLabel := fmt.Sprintf("demo-cert-%d", suffix)
	cert, err := manager.(*pkcs11.Manager).SelfSignCertificate(ctx, rsaID, certLabel, &x509.Certificate{
		SerialNumber: big.NewInt(suffix),
		Subject: pkix.Name{
			CommonName:   "keyman demo",
			Organization: []string{"Example"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	if err != nil {
		return err
	}
	tlsCert, err := manager.(*pkcs11.Manager).ManagedTLSCertificate(ctx, certLabel, rsaID)
	if err != nil {
		return err
	}
	tlsSignature, err := tlsCert.PrivateKey.(crypto.Signer).Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(tlsCert.Leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], tlsSignature); err != nil {
		return err
	}

	fmt.Printf("created AES key: %s\n", aesID)
	fmt.Printf("decrypted v%d ciphertext after rotation: %q\n", oldCiphertext.KeyVersion, oldPlaintext)
	fmt.Printf("new ciphertext key version: %d\n", newCiphertext.KeyVersion)
	fmt.Printf("created RSA signing key: %s\n", rsaID)
	fmt.Printf("signature bytes: %d\n", len(signature))
	fmt.Printf("stored self-signed certificate: %s (%s)\n", certLabel, cert.Subject.CommonName)
	fmt.Printf("TLS signer signature bytes: %d\n", len(tlsSignature))
	return nil
}

func envDefault(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
