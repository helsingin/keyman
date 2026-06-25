package pkcs11

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	pkcs11lib "github.com/miekg/pkcs11"
)

// TLSCertificate loads a certificate object and private key from the token.
//
// The private key is exposed only as a crypto.Signer, so signing operations stay
// inside the PKCS#11 token.
func (m *Manager) TLSCertificate(ctx context.Context, certLabel string, keyLabel string) (*tls.Certificate, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if keyLabel == "" {
		keyLabel = certLabel
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}

	certObj, err := m.findOneLocked(pkcs11lib.CKO_CERTIFICATE, certLabel, false)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: find certificate: %w", err)
	}
	certDER, err := m.getValueLocked(certObj)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: parse certificate: %w", err)
	}

	keyObj, err := m.findOneLocked(pkcs11lib.CKO_PRIVATE_KEY, keyLabel, false)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: find certificate private key: %w", err)
	}
	keyType, err := keyTypeFromPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{append([]byte(nil), certDER...)},
		PrivateKey: &Signer{
			manager:   m,
			keyHandle: keyObj,
			keyType:   keyType,
			publicKey: leaf.PublicKey,
		},
		Leaf: leaf,
	}, nil
}

// ManagedTLSCertificate loads a certificate object and binds it to the latest
// private key version for a managed key.
func (m *Manager) ManagedTLSCertificate(ctx context.Context, certLabel string, keyID string) (*tls.Certificate, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}

	certObj, err := m.findOneLocked(pkcs11lib.CKO_CERTIFICATE, certLabel, false)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: find certificate: %w", err)
	}
	certDER, err := m.getValueLocked(certObj)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: parse certificate: %w", err)
	}
	meta, err := m.getMetadataLocked(keyID)
	if err != nil {
		return nil, err
	}
	keyObj, err := m.findOneLocked(pkcs11lib.CKO_PRIVATE_KEY, privateKeyManel(keyID, meta.Version), false)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: find managed private key: %w", err)
	}
	keyType, err := keyTypeFromPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{append([]byte(nil), certDER...)},
		PrivateKey: &Signer{
			manager:   m,
			keyHandle: keyObj,
			keyType:   keyType,
			publicKey: leaf.PublicKey,
		},
		Leaf: leaf,
	}, nil
}

// CACertPool loads a CA certificate object from the token and returns a pool.
func (m *Manager) CACertPool(ctx context.Context, label string) (*x509.CertPool, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}

	obj, err := m.findOneLocked(pkcs11lib.CKO_CERTIFICATE, label, false)
	if err != nil {
		return nil, err
	}
	certDER, err := m.getValueLocked(obj)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: parse CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}
