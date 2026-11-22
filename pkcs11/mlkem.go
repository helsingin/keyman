package pkcs11

import (
	"context"
	"crypto/mlkem"
	"errors"

	keyring "github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

// PKCS #11 v3.2 ML-KEM identifiers.
const (
	ckmMLKEMKeyPairGen = 0x0f
	ckkMLKEM           = 0x49
	ckpMLKEM768        = 2
	ckaEncapsulate     = 0x633
	ckaDecapsulate     = 0x634
)

func (m *Manager) createMLKEM768KeyLocked(name string, version int) error {
	_, _, err := m.ctx.GenerateKeyPair(m.session, []*p11.Mechanism{p11.NewMechanism(ckmMLKEMKeyPairGen, nil)},
		[]*p11.Attribute{
			p11.NewAttribute(ckaParameterSet, ckpMLKEM768),
			p11.NewAttribute(p11.CKA_TOKEN, true), p11.NewAttribute(ckaEncapsulate, true),
			p11.NewAttribute(p11.CKA_LABEL, publicKeyManel(name, version)),
		}, []*p11.Attribute{
			p11.NewAttribute(p11.CKA_TOKEN, true), p11.NewAttribute(p11.CKA_PRIVATE, true),
			p11.NewAttribute(p11.CKA_SENSITIVE, true), p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
			p11.NewAttribute(ckaDecapsulate, true), p11.NewAttribute(p11.CKA_LABEL, privateKeyManel(name, version)),
		})
	return err
}

func (m *Manager) mlKEM768PublicKeyLocked(name string, version int) (*mlkem.EncapsulationKey768, error) {
	if _, err := m.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(name, version), false); err != nil {
		return nil, err
	}
	h, err := m.findOneLocked(p11.CKO_PUBLIC_KEY, publicKeyManel(name, version), false)
	if err != nil {
		return nil, err
	}
	raw, err := m.getValueLocked(h)
	if err != nil {
		return nil, err
	}
	return mlkem.NewEncapsulationKey768(raw)
}

// confirmKEMLocked consumes a temporary shared secret inside the token. Its only
// output is a domain-separated confirmation tag, never a usable traffic key.
func (m *Manager) confirmKEMLocked(secret p11.ObjectHandle, ciphertext []byte) (tag []byte, err error) {
	defer func() {
		if destroyErr := m.ctx.DestroyObject(m.session, secret); destroyErr != nil {
			tag = nil
			err = errors.Join(err, destroyErr)
		}
	}()
	if err := m.ctx.SignInit(m.session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_SHA256_HMAC, nil)}, secret); err != nil {
		return nil, err
	}
	return m.ctx.Sign(m.session, append([]byte("Keyman ML-KEM-768 confirmation v1\x00"), ciphertext...))
}

// EncapsulateMLKEM768Proof uses the token RNG and peer's public key. It returns
// the FIPS 203 ciphertext and a key-confirmation tag for capability tests.
func (m *Manager) EncapsulateMLKEM768Proof(ctx context.Context, peer *mlkem.EncapsulationKey768) (ct, tag []byte, err error) {
	if peer == nil {
		return nil, nil, errors.New("missing ML-KEM-768 public key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := errors.Join(checkContext(ctx), m.ensureOpen()); err != nil {
		return nil, nil, err
	}
	pub, err := m.ctx.CreateObject(m.session, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY), p11.NewAttribute(p11.CKA_KEY_TYPE, ckkMLKEM),
		p11.NewAttribute(ckaParameterSet, ckpMLKEM768), p11.NewAttribute(ckaEncapsulate, true),
		p11.NewAttribute(p11.CKA_TOKEN, false), p11.NewAttribute(p11.CKA_VALUE, peer.Bytes()),
	})
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if destroyErr := m.ctx.DestroyObject(m.session, pub); destroyErr != nil {
			ct, tag, err = nil, nil, errors.Join(err, destroyErr)
		}
	}()
	ct = make([]byte, mlkem.CiphertextSize768)
	secret, err := m.nativeKEMLocked(true, pub, ct)
	if err != nil {
		return nil, nil, err
	}
	tag, err = m.confirmKEMLocked(secret, ct)
	return ct, tag, err
}

// DecapsulateMLKEM768Proof confirms a ciphertext using a managed non-extractable key.
func (m *Manager) DecapsulateMLKEM768Proof(ctx context.Context, name string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != mlkem.CiphertextSize768 {
		return nil, errors.New("invalid ML-KEM-768 ciphertext length")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := errors.Join(checkContext(ctx), m.ensureOpen()); err != nil {
		return nil, err
	}
	meta, err := m.getMetadataLocked(name)
	if err != nil {
		return nil, err
	}
	if meta.Type != keyring.KeyTypeMLKEM768 {
		return nil, keyring.ErrUnsupportedKeyType
	}
	private, err := m.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(name, meta.Version), false)
	if err != nil {
		return nil, err
	}
	secret, err := m.nativeKEMLocked(false, private, ciphertext)
	if err != nil {
		return nil, err
	}
	return m.confirmKEMLocked(secret, ciphertext)
}
