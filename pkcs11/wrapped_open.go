package pkcs11

import (
	"context"
	"crypto/mlkem"
	"errors"

	keyring "github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

// OpenWrappedMLKEM768 decapsulates an ML-KEM-768 ciphertext, unwraps one
// RFC 3394 AES-256 content key and authenticates an AES-GCM record with
// a 96-bit nonce and 128-bit tag. Both derived keys are nonextractable
// session objects. The only application data returned is the plaintext.
func (m *Manager) OpenWrappedMLKEM768(ctx context.Context, name string, kem, wrapped, nonce, ciphertext, aad []byte) (plaintext []byte, err error) {
	return m.openWrapped(ctx, name, keyring.KeyTypeMLKEM768, mlkem.CiphertextSize768, kem, wrapped, nonce, ciphertext, aad)
}

// OpenWrappedMLKEM1024 opens an AES-256-KW and AES-GCM envelope inside the token.
func (m *Manager) OpenWrappedMLKEM1024(ctx context.Context, name string, kem, wrapped, nonce, ciphertext, aad []byte) ([]byte, error) {
	return m.openWrapped(ctx, name, keyring.KeyTypeMLKEM1024, mlkem.CiphertextSize1024, kem, wrapped, nonce, ciphertext, aad)
}

func (m *Manager) openWrapped(ctx context.Context, name string, typ keyring.KeyType, size int, kem, wrapped, nonce, ciphertext, aad []byte) (plaintext []byte, err error) {
	if len(kem) != size || len(wrapped) != 40 || len(nonce) != 12 || len(ciphertext) < 16 {
		return nil, errors.New("invalid wrapped envelope dimensions")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err = errors.Join(checkContext(ctx), m.ensureOpen()); err != nil {
		return nil, err
	}
	s, err := m.temporarySession()
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := s.ctx.CloseSession(s.session); closeErr != nil {
			clear(plaintext)
			plaintext = nil
			err = errors.Join(err, closeErr)
		}
	}()
	meta, err := s.getMetadataLocked(name)
	if err != nil {
		return nil, err
	}
	if meta.Type != typ {
		return nil, keyring.ErrUnsupportedKeyType
	}
	priv, err := s.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(name, meta.Version), false)
	if err != nil {
		return nil, err
	}
	kek, err := s.kemResultLocked(false, true, priv, kem)
	if err != nil {
		return nil, err
	}
	cek, err := s.ctx.UnwrapKey(s.session, mechanism(p11.CKM_AES_KEY_WRAP), kek, wrapped, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY), p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
		p11.NewAttribute(p11.CKA_TOKEN, false), p11.NewAttribute(p11.CKA_PRIVATE, true), p11.NewAttribute(p11.CKA_SENSITIVE, true),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, false), p11.NewAttribute(p11.CKA_DECRYPT, true),
	})
	if err != nil {
		return nil, err
	}
	return s.openGCM(cek, nonce, ciphertext, aad)
}
