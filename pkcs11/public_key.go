package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	pkcs11lib "github.com/miekg/pkcs11"
)

// PublicKey returns the latest public key for a managed asymmetric key.
func (m *Manager) PublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}

	meta, err := m.getMetadataLocked(keyID)
	if err != nil {
		return nil, err
	}

	return m.publicKeyLocked(keyID, meta)
}

func (m *Manager) rsaPublicKeyLocked(keyID string, version int) (*rsa.PublicKey, error) {
	obj, err := m.findOneLocked(pkcs11lib.CKO_PUBLIC_KEY, publicKeyManel(keyID, version), false)
	if err != nil {
		return nil, err
	}
	attrs, err := m.ctx.GetAttributeValue(m.session, obj, []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_MODULUS, nil),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: read RSA public key: %w", err)
	}
	if len(attrs) != 2 {
		return nil, fmt.Errorf("pkcs11: incomplete RSA public key")
	}
	exponent := new(big.Int).SetBytes(attrs[1].Value).Int64()
	if exponent <= 0 || exponent > int64(^uint(0)>>1) {
		return nil, fmt.Errorf("pkcs11: invalid RSA public exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(attrs[0].Value),
		E: int(exponent),
	}, nil
}

func (m *Manager) ecdsaPublicKeyLocked(keyID string, version int) (*ecdsa.PublicKey, error) {
	obj, err := m.findOneLocked(pkcs11lib.CKO_PUBLIC_KEY, publicKeyManel(keyID, version), false)
	if err != nil {
		return nil, err
	}
	attrs, err := m.ctx.GetAttributeValue(m.session, obj, []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: read ECDSA public key: %w", err)
	}
	if len(attrs) != 1 {
		return nil, fmt.Errorf("pkcs11: incomplete ECDSA public key")
	}

	point, err := decodeECPoint(attrs[0].Value)
	if err != nil {
		return nil, err
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), point)
	if x == nil || y == nil {
		return nil, fmt.Errorf("pkcs11: invalid P-256 public key point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func decodeECPoint(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("pkcs11: empty EC point")
	}
	if len(value) == 65 && value[0] == 0x04 {
		return value, nil
	}
	var point []byte
	rest, err := asn1.Unmarshal(value, &point)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: parse DER EC point: %w", err)
	}
	if len(rest) != 0 || len(point) == 0 {
		return nil, fmt.Errorf("pkcs11: invalid DER EC point")
	}
	return point, nil
}
