package pkcs11

import (
	"context"
	"crypto/mlkem"
	"crypto/sha512"
	"errors"
	"fmt"

	keyring "github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

// WrappedKeyBatch transports ordered 256-bit traffic keys. The final wrapped
// key authenticates the transcript. All elements are RFC 3394 ciphertexts.
type WrappedKeyBatch struct {
	Ciphertext []byte
	Wrapped    [][]byte
}

// BatchTags contains sender and recipient AES-CMACs in that order.
type BatchTags [2][16]byte

func mechanism(id uint) []*p11.Mechanism { return []*p11.Mechanism{p11.NewMechanism(id, nil)} }

// Each operation owns a session so every temporary object, including its
// wrapping key, disappears on success, failure or process exit.
func (m *Manager) batchSession(ctx context.Context, names []string) (*Manager, error) {
	if err := errors.Join(checkContext(ctx), m.ensureOpen()); err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, errors.New("empty key batch")
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if err := validateKeyName(name); err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, errors.New("duplicate batch key name")
		}
		seen[name] = true
		if _, err := m.getMetadataLocked(name); err == nil {
			return nil, fmt.Errorf("key already exists: %s", name)
		} else if !errors.Is(err, keyring.ErrKeyNotFound) {
			return nil, err
		}
	}
	return m.temporarySession()
}

func (m *Manager) temporarySession() (*Manager, error) {
	info, err := m.ctx.GetSessionInfo(m.session)
	if err != nil {
		return nil, err
	}
	session, err := m.ctx.OpenSession(info.SlotID, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	return &Manager{ctx: m.ctx, session: session, modulePath: m.modulePath, appLabel: m.appLabel}, nil
}

// WrapKeyBatch generates independent random traffic keys and installs them in
// this token. Names must be fresh. Journal them before calling so interrupted
// operations can be abandoned with DeleteKey. Binding names the authenticated
// protocol context, including slot order and peer identities.
func (m *Manager) WrapKeyBatch(ctx context.Context, peer *mlkem.EncapsulationKey768, binding [48]byte, names []string) (batch WrappedKeyBatch, tags BatchTags, err error) {
	if peer == nil {
		return batch, tags, errors.New("missing KEM public key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.batchSession(ctx, names)
	if err != nil {
		return batch, tags, err
	}
	defer func() { err = errors.Join(err, s.ctx.CloseSession(s.session)) }()
	pub, err := s.importKEMPeerLocked(peer)
	if err != nil {
		return batch, tags, err
	}
	batch.Ciphertext = make([]byte, mlkem.CiphertextSize768)
	kek, err := s.kemResultLocked(true, true, pub, batch.Ciphertext)
	if err != nil {
		return batch, tags, err
	}
	for i := 0; i <= len(names); i++ {
		key, err := s.ctx.GenerateKey(s.session, mechanism(p11.CKM_AES_KEY_GEN), []*p11.Attribute{
			p11.NewAttribute(p11.CKA_TOKEN, false), p11.NewAttribute(p11.CKA_PRIVATE, true),
			p11.NewAttribute(p11.CKA_VALUE_LEN, 32), p11.NewAttribute(p11.CKA_SENSITIVE, true), p11.NewAttribute(p11.CKA_EXTRACTABLE, true),
		})
		if err != nil {
			return batch, tags, err
		}
		wrapped, err := s.ctx.WrapKey(s.session, mechanism(p11.CKM_AES_KEY_WRAP), kek, key)
		if err != nil {
			return batch, tags, fmt.Errorf("wrap batch key: %w", err)
		}
		if err = s.ctx.DestroyObject(s.session, key); err != nil {
			return batch, tags, err
		}
		batch.Wrapped = append(batch.Wrapped, wrapped)
	}
	tags, err = s.installWrapped(kek, binding, batch, names)
	return batch, tags, err
}

// UnwrapKeyBatch installs a staged batch in fresh token slots. The caller must
// authenticate the transcript, confirm the tags, and erase the decapsulation
// key before activation. On interruption retire all journaled staged names.
func (m *Manager) UnwrapKeyBatch(ctx context.Context, kem string, binding [48]byte, batch WrappedKeyBatch, names []string) (tags BatchTags, err error) {
	if len(batch.Ciphertext) != mlkem.CiphertextSize768 || len(batch.Wrapped) != len(names)+1 {
		return tags, errors.New("invalid batch dimensions")
	}
	for _, key := range batch.Wrapped {
		if len(key) != 40 {
			return tags, errors.New("invalid AES-256 wrapped key length")
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.batchSession(ctx, names)
	if err != nil {
		return tags, err
	}
	defer func() { err = errors.Join(err, s.ctx.CloseSession(s.session)) }()
	meta, err := s.getMetadataLocked(kem)
	if err != nil {
		return tags, err
	}
	if meta.Type != keyring.KeyTypeMLKEM768 {
		return tags, keyring.ErrUnsupportedKeyType
	}
	priv, err := s.findOneLocked(p11.CKO_PRIVATE_KEY, privateKeyManel(kem, meta.Version), false)
	if err != nil {
		return tags, err
	}
	kek, err := s.kemResultLocked(false, true, priv, batch.Ciphertext)
	if err != nil {
		return tags, err
	}
	return s.installWrapped(kek, binding, batch, names)
}

func (s *Manager) installWrapped(kek p11.ObjectHandle, binding [48]byte, batch WrappedKeyBatch, names []string) (tags BatchTags, err error) {
	transcript := sha512.New384()
	transcript.Write([]byte("Keyman wrapped key batch v1\x00"))
	transcript.Write(binding[:])
	transcript.Write(batch.Ciphertext)
	for i, wrapped := range batch.Wrapped {
		if len(wrapped) != 40 {
			return tags, errors.New("invalid wrapped key length")
		}
		transcript.Write(wrapped)
		traffic := i < len(names)
		attrs := []*p11.Attribute{p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY), p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
			p11.NewAttribute(p11.CKA_TOKEN, traffic), p11.NewAttribute(p11.CKA_PRIVATE, true), p11.NewAttribute(p11.CKA_SENSITIVE, true), p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
			p11.NewAttribute(p11.CKA_ENCRYPT, traffic), p11.NewAttribute(p11.CKA_DECRYPT, traffic), p11.NewAttribute(p11.CKA_SIGN, !traffic),
			p11.NewAttribute(p11.CKA_WRAP, false), p11.NewAttribute(p11.CKA_UNWRAP, false), p11.NewAttribute(p11.CKA_DERIVE, false)}
		if traffic {
			meta := keyMetadata{Type: keyring.KeyTypeAES256GCM, Version: 1, CreatedAt: s.now()}
			if err := s.storeMetadataLocked(names[i], meta); err != nil {
				return tags, err
			}
			attrs = append(attrs, p11.NewAttribute(p11.CKA_LABEL, keyLabel(names[i], 1)))
		}
		key, err := s.ctx.UnwrapKey(s.session, mechanism(p11.CKM_AES_KEY_WRAP), kek, wrapped, attrs)
		if err != nil {
			return tags, fmt.Errorf("unwrap batch key: %w", err)
		}
		if !traffic {
			digest := transcript.Sum(nil)
			for role := range tags {
				if err = s.ctx.SignInit(s.session, mechanism(p11.CKM_AES_CMAC), key); err != nil {
					return tags, err
				}
				tag, err := s.ctx.Sign(s.session, append(digest, byte(role)))
				if err != nil {
					return tags, err
				}
				if len(tag) != len(tags[role]) {
					return tags, errors.New("invalid CMAC tag length")
				}
				copy(tags[role][:], tag)
			}
		}
	}
	return tags, nil
}
