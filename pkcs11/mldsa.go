package pkcs11

import (
	"fmt"
	keyring "github.com/helsingin/keyman"

	p11 "github.com/miekg/pkcs11"
)

// PKCS#11 v3.2 identifiers absent from the Go binding's older headers.
const (
	ckmMLDSAKeyPairGen = 0x1c
	ckmMLDSA           = 0x1d
	ckaParameterSet    = 0x61d
	ckpMLDSA65         = 2
)

// MLDSA65PublicKey contains a FIPS 204 packed verification key (1952 bytes).
type MLDSA65PublicKey []byte

// MLDSA87PublicKey contains a FIPS 204 packed verification key (2592 bytes).
type MLDSA87PublicKey []byte

func (m *Manager) createMLDSAKeyLocked(id string, version int, typ keyring.KeyType) error {
	if err := m.requirePQGenerationLocked(typ); err != nil {
		return err
	}
	params := ckpMLDSA65
	if typ == keyring.KeyTypeMLDSA87 {
		params = 3
	}
	_, _, err := m.ctx.GenerateKeyPair(m.session, []*p11.Mechanism{p11.NewMechanism(ckmMLDSAKeyPairGen, nil)},
		[]*p11.Attribute{
			p11.NewAttribute(ckaParameterSet, params),
			p11.NewAttribute(p11.CKA_TOKEN, true),
			p11.NewAttribute(p11.CKA_VERIFY, true),
			p11.NewAttribute(p11.CKA_LABEL, publicKeyManel(id, version)),
		},
		[]*p11.Attribute{
			p11.NewAttribute(p11.CKA_TOKEN, true),
			p11.NewAttribute(p11.CKA_PRIVATE, true),
			p11.NewAttribute(p11.CKA_SIGN, true),
			p11.NewAttribute(p11.CKA_SENSITIVE, true),
			p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
			p11.NewAttribute(p11.CKA_LABEL, privateKeyManel(id, version)),
		})
	if err != nil {
		return pqOperationError(fmt.Sprintf("pkcs11: generate %s pair", typ), err)
	}
	return nil
}

func (m *Manager) mlDSAPublicKeyLocked(id string, version int, typ keyring.KeyType) (any, error) {
	h, err := m.findOneLocked(p11.CKO_PUBLIC_KEY, publicKeyManel(id, version), false)
	if err != nil {
		return nil, err
	}
	value, err := m.getValueLocked(h)
	if err != nil {
		return nil, err
	}
	if typ == keyring.KeyTypeMLDSA87 {
		if len(value) != 2592 {
			return nil, fmt.Errorf("pkcs11: invalid ML-DSA-87 public key length %d", len(value))
		}
		return MLDSA87PublicKey(value), nil
	}
	if len(value) != 1952 {
		return nil, fmt.Errorf("pkcs11: invalid ML-DSA-65 public key length %d", len(value))
	}
	return MLDSA65PublicKey(value), nil
}
