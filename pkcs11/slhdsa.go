package pkcs11

import (
	"fmt"

	keyring "github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

// PKCS#11 v3.2 identifiers absent from the Go binding's older headers.
// https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
const (
	ckmSLHDSAKeyPairGen = 0x2d
	ckmSLHDSA           = 0x2e
	ckpSLHDSASHA2192s   = 5
	ckpSLHDSASHA2256s   = 9
)

// SLHDSASHA2192sPublicKey contains a FIPS 205 packed verification key (48 bytes).
type SLHDSASHA2192sPublicKey []byte

// SLHDSASHA2256sPublicKey contains a FIPS 205 packed verification key (64 bytes).
type SLHDSASHA2256sPublicKey []byte

func slhDSAParameters(typ keyring.KeyType) (parameterSet, publicKeySize int, err error) {
	switch typ {
	case keyring.KeyTypeSLHDSASHA2192s:
		return ckpSLHDSASHA2192s, 48, nil
	case keyring.KeyTypeSLHDSASHA2256s:
		return ckpSLHDSASHA2256s, 64, nil
	default:
		return 0, 0, fmt.Errorf("%w: %s", keyring.ErrUnsupportedKeyType, typ)
	}
}

func (m *Manager) createSLHDSAKeyLocked(id string, version int, typ keyring.KeyType) error {
	params, _, err := slhDSAParameters(typ)
	if err != nil {
		return err
	}
	_, _, err = m.ctx.GenerateKeyPair(m.session, []*p11.Mechanism{p11.NewMechanism(ckmSLHDSAKeyPairGen, nil)},
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
		return fmt.Errorf("pkcs11: generate %s pair: %w", typ, err)
	}
	return nil
}

func (m *Manager) slhDSAPublicKeyLocked(id string, version int, typ keyring.KeyType) (any, error) {
	_, size, err := slhDSAParameters(typ)
	if err != nil {
		return nil, err
	}
	h, err := m.findOneLocked(p11.CKO_PUBLIC_KEY, publicKeyManel(id, version), false)
	if err != nil {
		return nil, err
	}
	value, err := m.getValueLocked(h)
	if err != nil {
		return nil, err
	}
	if len(value) != size {
		return nil, fmt.Errorf("pkcs11: invalid %s public key length %d", typ, len(value))
	}
	if typ == keyring.KeyTypeSLHDSASHA2192s {
		return SLHDSASHA2192sPublicKey(value), nil
	}
	return SLHDSASHA2256sPublicKey(value), nil
}
