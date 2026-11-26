package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/helsingin/keyman"
	pkcs11lib "github.com/miekg/pkcs11"
)

var rsaPublicExponent = []byte{0x01, 0x00, 0x01}

// DER encoding for the secp256r1 / prime256v1 curve OID.
var ecParamsP256 = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}

// CreateKey creates version 1 of a non-extractable key.
func (m *Manager) CreateKey(ctx context.Context, keyType keyring.KeyType, name string) (*keyring.Key, error) {
	return m.createKey(ctx, keyType, name, false)
}

// CreateP256SigningAndAgreementKey permits both signing and ECDH with one non-extractable P-256 key.
func (m *Manager) CreateP256SigningAndAgreementKey(ctx context.Context, name string) (*keyring.Key, error) {
	return m.createKey(ctx, keyring.KeyTypeECDSAP256, name, true)
}

func (m *Manager) createKey(ctx context.Context, keyType keyring.KeyType, name string, agreement bool) (*keyring.Key, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := validateKeyName(name); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}

	if _, err := m.getMetadataLocked(name); err == nil {
		return nil, fmt.Errorf("pkcs11: key already exists: %s", name)
	} else if !errors.Is(err, keyring.ErrKeyNotFound) {
		return nil, err
	}

	if keyType == keyring.KeyTypeMLKEM768 || keyType == keyring.KeyTypeMLKEM1024 {
		// Persist the cleanup record first. Even a process exit immediately
		// after generation leaves DeleteKey enough information to retire it.
		created := m.now()
		if err := m.storeMetadataLocked(name, keyMetadata{Type: keyType, Version: 1, CreatedAt: created}); err != nil {
			return nil, err
		}
		if err := m.createMLKEMKeyLocked(name, 1, keyType); err != nil {
			return nil, errors.Join(err, m.destroyIfExistsLocked(pkcs11lib.CKO_DATA, metadataLabel(name), true))
		}
		return &keyring.Key{ID: name, Name: name, Type: keyType, Version: 1, CreatedAt: created}, nil
	}

	switch keyType {
	case keyring.KeyTypeAES256GCM:
		if err := m.createAESKeyLocked(name, 1); err != nil {
			return nil, err
		}
	case keyring.KeyTypeRSA4096:
		if err := m.createRSAKeyLocked(name, 1); err != nil {
			return nil, err
		}
	case keyring.KeyTypeMLDSA65, keyring.KeyTypeMLDSA87:
		if err := m.createMLDSAKeyLocked(name, 1, keyType); err != nil {
			return nil, err
		}
	case keyring.KeyTypeSLHDSASHA2192s, keyring.KeyTypeSLHDSASHA2256s:
		if err := m.createSLHDSAKeyLocked(name, 1, keyType); err != nil {
			return nil, err
		}
	case keyring.KeyTypeECDSAP256:
		if err := m.createECDSAKeyLocked(name, 1, agreement); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: %s", keyring.ErrUnsupportedKeyType, keyType)
	}

	createdAt := m.now()
	meta := keyMetadata{Type: keyType, Version: 1, CreatedAt: createdAt, Agreement: agreement}
	if err := m.storeMetadataLocked(name, meta); err != nil {
		return nil, errors.Join(err, m.rollbackPQPairLocked(name, 1, keyType))
	}

	return &keyring.Key{ID: name, Name: name, Type: keyType, Version: 1, CreatedAt: createdAt}, nil
}

// RotateKey creates a new key version and keeps older objects available for decrypt/verify.
func (m *Manager) RotateKey(ctx context.Context, keyID string) (*keyring.Key, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := validateKeyName(keyID); err != nil {
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

	nextVersion := meta.Version + 1
	switch meta.Type {
	case keyring.KeyTypeAES256GCM:
		err = m.createAESKeyLocked(keyID, nextVersion)
	case keyring.KeyTypeRSA4096:
		err = m.createRSAKeyLocked(keyID, nextVersion)
	case keyring.KeyTypeECDSAP256:
		err = m.createECDSAKeyLocked(keyID, nextVersion, meta.Agreement)
	case keyring.KeyTypeMLDSA65, keyring.KeyTypeMLDSA87:
		err = m.createMLDSAKeyLocked(keyID, nextVersion, meta.Type)
	case keyring.KeyTypeSLHDSASHA2192s, keyring.KeyTypeSLHDSASHA2256s:
		err = m.createSLHDSAKeyLocked(keyID, nextVersion, meta.Type)
	default:
		err = fmt.Errorf("%w: %s", keyring.ErrUnsupportedKeyType, meta.Type)
	}
	if err != nil {
		return nil, err
	}

	rotatedAt := m.now()
	meta.Version = nextVersion
	meta.RotatedAt = rotatedAt
	if err := m.storeMetadataLocked(keyID, meta); err != nil {
		return nil, errors.Join(err, m.rollbackPQPairLocked(keyID, nextVersion, meta.Type))
	}

	return &keyring.Key{
		ID:        keyID,
		Name:      keyID,
		Type:      meta.Type,
		Version:   nextVersion,
		CreatedAt: meta.CreatedAt,
		RotatedAt: rotatedAt,
	}, nil
}

// GetKey returns the latest key metadata without exposing key material.
func (m *Manager) GetKey(ctx context.Context, keyID string) (*keyring.Key, error) {
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
	return &keyring.Key{
		ID:        keyID,
		Name:      keyID,
		Type:      meta.Type,
		Version:   meta.Version,
		CreatedAt: meta.CreatedAt,
		RotatedAt: meta.RotatedAt,
	}, nil
}

// ListKeys lists keys managed by this application label.
func (m *Manager) ListKeys(ctx context.Context) ([]*keyring.KeyMetadata, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}
	return m.listKeysLocked()
}

func (m *Manager) listKeysLocked() ([]*keyring.KeyMetadata, error) {
	template := []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_CLASS, pkcs11lib.CKO_DATA),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_APPLICATION, m.appLabel),
	}
	if err := m.ctx.FindObjectsInit(m.session, template); err != nil {
		return nil, fmt.Errorf("pkcs11: list init: %w", err)
	}
	defer func() { _ = m.ctx.FindObjectsFinal(m.session) }()

	out := []*keyring.KeyMetadata{}
	for {
		objs, _, err := m.ctx.FindObjects(m.session, 100)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: list objects: %w", err)
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
			label := string(attrs[0].Value)
			if !strings.HasSuffix(label, ":meta") {
				continue
			}
			meta, err := decodeMetadata(attrs[1].Value)
			if err != nil {
				continue
			}
			name := strings.TrimSuffix(label, ":meta")
			out = append(out, &keyring.KeyMetadata{
				ID:            name,
				Name:          name,
				Type:          meta.Type,
				LatestVersion: meta.Version,
				MinDecryptVer: 1,
				CreatedAt:     meta.CreatedAt,
				RotatedAt:     meta.RotatedAt,
			})
		}
	}
	return out, nil
}

// DeleteKey removes a managed key and all of its stored versions.
func (m *Manager) DeleteKey(ctx context.Context, keyID string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateKeyName(keyID); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return err
	}

	meta, err := m.getMetadataLocked(keyID)
	if err != nil {
		return err
	}
	blockingCerts, err := m.certificatesForKeyLocked(keyID, meta)
	if err != nil {
		return err
	}
	if len(blockingCerts) > 0 {
		return fmt.Errorf("key can not be deleted while the following certs are still present: %s", strings.Join(blockingCerts, ", "))
	}
	for version := 1; version <= meta.Version; version++ {
		switch meta.Type {
		case keyring.KeyTypeAES256GCM:
			if err := m.destroyIfExistsLocked(pkcs11lib.CKO_SECRET_KEY, keyLabel(keyID, version), false); err != nil {
				return err
			}
		case keyring.KeyTypeMLKEM768, keyring.KeyTypeMLKEM1024:
			// Retire the decapsulation capability before its public object.
			if err := m.destroyIfExistsLocked(pkcs11lib.CKO_PRIVATE_KEY, privateKeyManel(keyID, version), false); err != nil {
				return err
			}
			if err := m.destroyIfExistsLocked(pkcs11lib.CKO_PUBLIC_KEY, publicKeyManel(keyID, version), false); err != nil {
				return err
			}
		case keyring.KeyTypeRSA4096, keyring.KeyTypeECDSAP256, keyring.KeyTypeMLDSA65, keyring.KeyTypeMLDSA87,
			keyring.KeyTypeSLHDSASHA2192s, keyring.KeyTypeSLHDSASHA2256s:
			if err := m.destroyIfExistsLocked(pkcs11lib.CKO_PUBLIC_KEY, publicKeyManel(keyID, version), false); err != nil {
				return err
			}
			if err := m.destroyIfExistsLocked(pkcs11lib.CKO_PRIVATE_KEY, privateKeyManel(keyID, version), false); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: %s", keyring.ErrUnsupportedKeyType, meta.Type)
		}
	}
	return m.destroyIfExistsLocked(pkcs11lib.CKO_DATA, metadataLabel(keyID), true)
}

func (m *Manager) createAESKeyLocked(name string, version int) error {
	_, err := m.ctx.GenerateKey(m.session,
		[]*pkcs11lib.Mechanism{pkcs11lib.NewMechanism(pkcs11lib.CKM_AES_KEY_GEN, nil)},
		[]*pkcs11lib.Attribute{
			pkcs11lib.NewAttribute(pkcs11lib.CKA_CLASS, pkcs11lib.CKO_SECRET_KEY),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_KEY_TYPE, pkcs11lib.CKK_AES),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_TOKEN, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_PRIVATE, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_SENSITIVE, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_EXTRACTABLE, false),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_ENCRYPT, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_DECRYPT, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, keyLabel(name, version)),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_VALUE_LEN, 32),
		})
	if err != nil {
		return fmt.Errorf("pkcs11: generate AES key: %w", err)
	}
	return nil
}

func (m *Manager) createRSAKeyLocked(name string, version int) error {
	_, _, err := m.ctx.GenerateKeyPair(m.session,
		[]*pkcs11lib.Mechanism{pkcs11lib.NewMechanism(pkcs11lib.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		[]*pkcs11lib.Attribute{
			pkcs11lib.NewAttribute(pkcs11lib.CKA_CLASS, pkcs11lib.CKO_PUBLIC_KEY),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_KEY_TYPE, pkcs11lib.CKK_RSA),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_TOKEN, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_VERIFY, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_ENCRYPT, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_MODULUS_BITS, 4096),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_PUBLIC_EXPONENT, rsaPublicExponent),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, publicKeyManel(name, version)),
		},
		[]*pkcs11lib.Attribute{
			pkcs11lib.NewAttribute(pkcs11lib.CKA_CLASS, pkcs11lib.CKO_PRIVATE_KEY),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_KEY_TYPE, pkcs11lib.CKK_RSA),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_TOKEN, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_PRIVATE, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_SENSITIVE, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_EXTRACTABLE, false),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_SIGN, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_DECRYPT, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, privateKeyManel(name, version)),
		})
	if err != nil {
		return fmt.Errorf("pkcs11: generate RSA key pair: %w", err)
	}
	return nil
}

func (m *Manager) createECDSAKeyLocked(name string, version int, agreement bool) error {
	_, _, err := m.ctx.GenerateKeyPair(m.session,
		[]*pkcs11lib.Mechanism{pkcs11lib.NewMechanism(pkcs11lib.CKM_EC_KEY_PAIR_GEN, nil)},
		[]*pkcs11lib.Attribute{
			pkcs11lib.NewAttribute(pkcs11lib.CKA_CLASS, pkcs11lib.CKO_PUBLIC_KEY),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_KEY_TYPE, pkcs11lib.CKK_EC),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_TOKEN, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_VERIFY, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_EC_PARAMS, ecParamsP256),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, publicKeyManel(name, version)),
		},
		[]*pkcs11lib.Attribute{
			pkcs11lib.NewAttribute(pkcs11lib.CKA_CLASS, pkcs11lib.CKO_PRIVATE_KEY),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_KEY_TYPE, pkcs11lib.CKK_EC),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_TOKEN, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_PRIVATE, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_SENSITIVE, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_EXTRACTABLE, false),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_SIGN, true),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_DERIVE, agreement),
			pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, privateKeyManel(name, version)),
		})
	if err != nil {
		return fmt.Errorf("pkcs11: generate ECDSA key pair: %w", err)
	}
	return nil
}

func parseVersionFromLabel(label string) int {
	idx := strings.LastIndex(label, ":v")
	if idx == -1 {
		return 0
	}
	n, _ := strconv.Atoi(label[idx+2:])
	return n
}

// Roll back a generated PQ pair when committing its metadata fails. Cleanup
// errors are returned to the caller; token failure is never hidden.
func (m *Manager) rollbackPQPairLocked(id string, version int, typ keyring.KeyType) error {
	if _, ok := pqSignatureMechanism(typ); !ok {
		return nil
	}
	return errors.Join(
		m.destroyIfExistsLocked(pkcs11lib.CKO_PRIVATE_KEY, privateKeyManel(id, version), false),
		m.destroyIfExistsLocked(pkcs11lib.CKO_PUBLIC_KEY, publicKeyManel(id, version), false))
}
