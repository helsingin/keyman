package pkcs11

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"sort"
	"time"

	"github.com/helsingin/keyman"
	pkcs11lib "github.com/miekg/pkcs11"
)

// CertificateInfo describes a certificate object stored on the token.
type CertificateInfo struct {
	Label              string    `json:"label"`
	Subject            string    `json:"subject"`
	CommonName         string    `json:"commonName"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serialNumber"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	IsCA               bool      `json:"isCa"`
	DNSNames           []string  `json:"dnsNames"`
	PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
	PublicKeyBits      int       `json:"publicKeyBits"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	KeyUsages          []string  `json:"keyUsages"`
	KeyID              string    `json:"keyId,omitempty"`
}

// CSR describes a certificate signing request created with a managed key.
type CSR struct {
	KeyID string `json:"keyId"`
	PEM   string `json:"pem"`
}

// ListCertificates returns X.509 certificate objects currently stored on the token.
func (m *Manager) ListCertificates(ctx context.Context) ([]CertificateInfo, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}
	return m.listCertificatesWithKeysLocked()
}

// CreateCSR creates a PEM-encoded certificate signing request with a managed key.
func (m *Manager) CreateCSR(ctx context.Context, keyID string, subject pkix.Name, dnsNames []string) (*CSR, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := validateKeyName(keyID); err != nil {
		return nil, err
	}
	if subject.CommonName == "" {
		return nil, fmt.Errorf("pkcs11: common name is required")
	}
	signer, err := m.ManagedSigner(ctx, keyID)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  subject,
		DNSNames: append([]string(nil), dnsNames...),
	}, signer)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: create CSR: %w", err)
	}
	block := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}
	return &CSR{KeyID: keyID, PEM: string(pem.EncodeToMemory(block))}, nil
}

// ImportCertificates stores a PEM or DER certificate bundle after confirming
// that at least one certificate belongs to a managed asymmetric key.
func (m *Manager) ImportCertificates(ctx context.Context, label string, data []byte) ([]CertificateInfo, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := validateKeyName(label); err != nil {
		return nil, err
	}
	certs, err := parseCertificateBundle(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("pkcs11: no certificates found")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}

	matched := false
	infos := make([]CertificateInfo, 0, len(certs))
	for index, cert := range certs {
		info := NewCertificateInfo(importedCertificateLabel(label, index), cert)
		if keyID, err := m.matchCertificateKeyLocked(cert); err == nil {
			info.KeyID = keyID
			matched = true
		}
		infos = append(infos, info)
	}
	if !matched {
		return nil, fmt.Errorf("pkcs11: certificate does not match any managed HSM key")
	}
	for index, cert := range certs {
		if err := m.replaceCertificateLocked(importedCertificateLabel(label, index), cert.Raw, cert); err != nil {
			return nil, err
		}
	}
	return infos, nil
}

// NewCertificateInfo converts a parsed X.509 certificate into API metadata.
func NewCertificateInfo(label string, cert *x509.Certificate) CertificateInfo {
	return CertificateInfo{
		Label:              label,
		Subject:            cert.Subject.String(),
		CommonName:         cert.Subject.CommonName,
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsCA:               cert.IsCA,
		DNSNames:           append([]string(nil), cert.DNSNames...),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:      certificatePublicKeyBits(cert),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		KeyUsages:          certificateKeyUsages(cert),
	}
}

func (m *Manager) certificatesForKeyLocked(keyID string, meta keyMetadata) ([]string, error) {
	if meta.Type != keyring.KeyTypeRSA4096 && meta.Type != keyring.KeyTypeECDSAP256 {
		return nil, nil
	}
	pub, err := m.publicKeyLocked(keyID, meta)
	if err != nil {
		return nil, err
	}
	expected, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: marshal public key: %w", err)
	}

	infos, err := m.listCertificatesLocked()
	if err != nil {
		return nil, err
	}
	labels := []string{}
	for _, info := range infos {
		cert, err := m.certificateByLabelLocked(info.Label)
		if err != nil {
			continue
		}
		if bytes.Equal(cert.RawSubjectPublicKeyInfo, expected) {
			labels = append(labels, info.Label)
		}
	}
	return labels, nil
}

func (m *Manager) matchCertificateKeyLocked(cert *x509.Certificate) (string, error) {
	keys, err := m.listKeysLocked()
	if err != nil {
		return "", err
	}
	for _, key := range keys {
		meta, err := m.getMetadataLocked(key.ID)
		if err != nil {
			continue
		}
		if meta.Type != keyring.KeyTypeRSA4096 && meta.Type != keyring.KeyTypeECDSAP256 {
			continue
		}
		pub, err := m.publicKeyLocked(key.ID, meta)
		if err != nil {
			continue
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			continue
		}
		if bytes.Equal(cert.RawSubjectPublicKeyInfo, der) {
			return key.ID, nil
		}
	}
	return "", fmt.Errorf("pkcs11: no matching managed key")
}

func (m *Manager) publicKeyLocked(keyID string, meta keyMetadata) (any, error) {
	switch meta.Type {
	case keyring.KeyTypeMLKEM768:
		return m.mlKEM768PublicKeyLocked(keyID, meta.Version)
	case keyring.KeyTypeRSA4096:
		return m.rsaPublicKeyLocked(keyID, meta.Version)
	case keyring.KeyTypeECDSAP256:
		return m.ecdsaPublicKeyLocked(keyID, meta.Version)
	case keyring.KeyTypeMLDSA65:
		return m.mlDSA65PublicKeyLocked(keyID, meta.Version)
	default:
		return nil, fmt.Errorf("%w: public key requires asymmetric key, got %s", keyring.ErrUnsupportedKeyType, meta.Type)
	}
}

func (m *Manager) listCertificatesLocked() ([]CertificateInfo, error) {
	template := []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_CLASS, pkcs11lib.CKO_CERTIFICATE),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_CERTIFICATE_TYPE, pkcs11lib.CKC_X_509),
	}
	if err := m.ctx.FindObjectsInit(m.session, template); err != nil {
		return nil, fmt.Errorf("pkcs11: list certificates init: %w", err)
	}
	defer func() { _ = m.ctx.FindObjectsFinal(m.session) }()

	out := []CertificateInfo{}
	for {
		objs, _, err := m.ctx.FindObjects(m.session, 100)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: list certificates: %w", err)
		}
		if len(objs) == 0 {
			break
		}
		for _, obj := range objs {
			attrs, err := m.ctx.GetAttributeValue(m.session, obj, []*pkcs11lib.Attribute{
				pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, nil),
				pkcs11lib.NewAttribute(pkcs11lib.CKA_VALUE, nil),
			})
			if err != nil || len(attrs) != 2 {
				continue
			}
			cert, err := x509.ParseCertificate(attrs[1].Value)
			if err != nil {
				continue
			}
			out = append(out, NewCertificateInfo(string(attrs[0].Value), cert))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Label < out[j].Label
	})
	return out, nil
}

func (m *Manager) listCertificatesWithKeysLocked() ([]CertificateInfo, error) {
	infos, err := m.listCertificatesLocked()
	if err != nil {
		return nil, err
	}
	for idx := range infos {
		cert, err := m.certificateByLabelLocked(infos[idx].Label)
		if err != nil {
			continue
		}
		if keyID, err := m.matchCertificateKeyLocked(cert); err == nil {
			infos[idx].KeyID = keyID
		}
	}
	return infos, nil
}

func (m *Manager) certificateByLabelLocked(label string) (*x509.Certificate, error) {
	obj, err := m.findOneLocked(pkcs11lib.CKO_CERTIFICATE, label, false)
	if err != nil {
		return nil, err
	}
	der, err := m.getValueLocked(obj)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: parse certificate: %w", err)
	}
	return cert, nil
}

func parseCertificateBundle(data []byte) ([]*x509.Certificate, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("pkcs11: certificate data is empty")
	}
	if bytes.Contains(trimmed, []byte("-----BEGIN")) {
		certs := []*x509.Certificate{}
		rest := trimmed
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pkcs11: parse PEM certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		return certs, nil
	}
	certs, err := x509.ParseCertificates(trimmed)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: parse DER certificate: %w", err)
	}
	return certs, nil
}

func importedCertificateLabel(label string, index int) string {
	if index == 0 {
		return label
	}
	return fmt.Sprintf("%s-chain-%d", label, index)
}

func certificatePublicKeyBits(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	default:
		return 0
	}
}

func certificateKeyUsages(cert *x509.Certificate) []string {
	usages := []string{}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "digital signature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "key encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "certificate signing")
	}
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "server auth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "client auth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "code signing")
		}
	}
	return usages
}
