package pkcs11

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

// ECDH derives the P-256 shared secret with the current version of a key
// created for agreement. Only the per-exchange secret leaves the token.
func (m *Manager) ECDH(ctx context.Context, keyID string, peer *ecdh.PublicKey) (secret []byte, err error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if peer == nil || peer.Curve() != ecdh.P256() {
		return nil, errors.New("pkcs11: ECDH requires a P-256 peer")
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
	if meta.Type != keyring.KeyTypeECDSAP256 || !meta.Agreement {
		return nil, errors.New("pkcs11: key does not permit P-256 agreement")
	}
	private, err := m.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(keyID, meta.Version), false)
	if err != nil {
		return nil, err
	}
	params := p11.NewECDH1DeriveParams(p11.CKD_NULL, nil, peer.Bytes())
	derived, err := m.ctx.DeriveKey(m.session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_ECDH1_DERIVE, params)}, private, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_GENERIC_SECRET),
		p11.NewAttribute(p11.CKA_TOKEN, false),
		p11.NewAttribute(p11.CKA_PRIVATE, true),
		p11.NewAttribute(p11.CKA_SENSITIVE, false),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, true),
		p11.NewAttribute(p11.CKA_VALUE_LEN, 32),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: derive P-256 shared secret: %w", err)
	}
	defer func() {
		if destroyErr := m.ctx.DestroyObject(m.session, derived); destroyErr != nil {
			clear(secret)
			secret = nil
			err = errors.Join(err, fmt.Errorf("pkcs11: destroy derived object: %w", destroyErr))
		}
	}()
	secret, err = m.getValueLocked(derived)
	if err == nil && len(secret) != 32 {
		clear(secret)
		return nil, errors.New("pkcs11: unexpected P-256 agreement length")
	}
	return secret, err
}
