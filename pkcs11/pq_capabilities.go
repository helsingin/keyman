package pkcs11

import (
	"context"
	"errors"
	"fmt"
	keyring "github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

// PQCapabilities reports advertised mechanisms, not a certification of a token.
// Parameter-set, context and hedging support must be checked by performing the
// requested operation; PKCS#11 mechanism discovery cannot establish them.
type PQCapabilities struct {
	KeyType  keyring.KeyType
	Generate bool
	Sign     bool
	Verify   bool
}

func (m *Manager) PQCapabilities(ctx context.Context, typ keyring.KeyType) (PQCapabilities, error) {
	if err := checkContext(ctx); err != nil {
		return PQCapabilities{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return PQCapabilities{}, err
	}
	return m.pqCapabilitiesLocked(typ)
}

func (m *Manager) pqCapabilitiesLocked(typ keyring.KeyType) (PQCapabilities, error) {
	result := PQCapabilities{KeyType: typ}
	sign, ok := pqSignatureMechanism(typ)
	if !ok {
		return result, fmt.Errorf("%w: %s", keyring.ErrUnsupportedKeyType, typ)
	}
	gen := uint(ckmMLDSAKeyPairGen)
	if sign == ckmSLHDSA {
		gen = ckmSLHDSAKeyPairGen
	}
	session, err := m.ctx.GetSessionInfo(m.session)
	if err != nil {
		return result, fmt.Errorf("pkcs11: capability session: %w", err)
	}
	for _, id := range []uint{gen, sign} {
		info, err := m.ctx.GetMechanismInfo(session.SlotID, []*p11.Mechanism{p11.NewMechanism(id, nil)})
		if errors.Is(err, p11.Error(p11.CKR_MECHANISM_INVALID)) {
			continue
		}
		if err != nil {
			return result, fmt.Errorf("pkcs11: mechanism information: %w", err)
		}
		if id == gen {
			result.Generate = info.Flags&p11.CKF_GENERATE_KEY_PAIR != 0
		} else {
			result.Sign = info.Flags&p11.CKF_SIGN != 0
			result.Verify = info.Flags&p11.CKF_VERIFY != 0
		}
	}
	return result, nil
}

func (m *Manager) requirePQGenerationLocked(typ keyring.KeyType) error {
	caps, err := m.pqCapabilitiesLocked(typ)
	if err != nil {
		return err
	}
	if !caps.Generate || !caps.Sign || !caps.Verify {
		return fmt.Errorf("%w: token does not advertise generation, signing and verification for %s", ErrUnsupportedPQOperation, typ)
	}
	return nil
}
