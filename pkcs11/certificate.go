package pkcs11

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"fmt"

	pkcs11lib "github.com/miekg/pkcs11"
)

// StoreCertificate stores a DER-encoded X.509 certificate in the token.
func (m *Manager) StoreCertificate(ctx context.Context, label string, der []byte) (*x509.Certificate, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := validateKeyName(label); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: parse certificate: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}
	if err := m.replaceCertificateLocked(label, der, cert); err != nil {
		return nil, err
	}
	return cert, nil
}

// SelfSignCertificate creates a self-signed certificate using a managed HSM key
// and stores the certificate object in the token.
func (m *Manager) SelfSignCertificate(ctx context.Context, keyID string, certLabel string, tmpl *x509.Certificate) (*x509.Certificate, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if tmpl == nil {
		return nil, fmt.Errorf("pkcs11: certificate template is nil")
	}
	pub, err := m.PublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	signer, err := m.ManagedSigner(ctx, keyID)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: create self-signed certificate: %w", err)
	}
	return m.StoreCertificate(ctx, certLabel, der)
}

// DeleteCertificate removes a certificate object by label.
func (m *Manager) DeleteCertificate(ctx context.Context, label string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateKeyName(label); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return err
	}
	return m.destroyIfExistsLocked(pkcs11lib.CKO_CERTIFICATE, label, false)
}

func (m *Manager) replaceCertificateLocked(label string, der []byte, cert *x509.Certificate) error {
	if existing, err := m.findOneLocked(pkcs11lib.CKO_CERTIFICATE, label, false); err == nil {
		if err := m.ctx.DestroyObject(m.session, existing); err != nil {
			return fmt.Errorf("pkcs11: replace certificate: %w", err)
		}
	}

	keyID := sha1.Sum(cert.RawSubjectPublicKeyInfo)
	_, err := m.ctx.CreateObject(m.session, []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_CLASS, pkcs11lib.CKO_CERTIFICATE),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_CERTIFICATE_TYPE, pkcs11lib.CKC_X_509),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_TOKEN, true),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, label),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_ID, keyID[:]),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_SUBJECT, cert.RawSubject),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_ISSUER, cert.RawIssuer),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_SERIAL_NUMBER, cert.SerialNumber.Bytes()),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_VALUE, der),
	})
	if err != nil {
		return fmt.Errorf("pkcs11: store certificate: %w", err)
	}
	return nil
}
