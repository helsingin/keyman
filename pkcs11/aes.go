package pkcs11

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/helsingin/keyman"
	pkcs11lib "github.com/miekg/pkcs11"
)

// Encrypt encrypts plaintext with the latest version of an AES-256-GCM key.
func (m *Manager) Encrypt(ctx context.Context, keyID string, plaintext []byte, aad []byte) (*keyring.EncryptedData, error) {
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
	if meta.Type != keyring.KeyTypeAES256GCM {
		return nil, fmt.Errorf("%w: encryption requires %s, got %s", keyring.ErrUnsupportedKeyType, keyring.KeyTypeAES256GCM, meta.Type)
	}

	keyHandle, err := m.findOneLocked(pkcs11lib.CKO_SECRET_KEY, keyLabel(keyID, meta.Version), false)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("pkcs11: generate AES-GCM IV: %w", err)
	}

	gcmParams := pkcs11lib.NewGCMParams(iv, aad, 128)
	defer gcmParams.Free()

	if err := m.ctx.EncryptInit(m.session, []*pkcs11lib.Mechanism{
		pkcs11lib.NewMechanism(pkcs11lib.CKM_AES_GCM, gcmParams),
	}, keyHandle); err != nil {
		return nil, fmt.Errorf("pkcs11: AES-GCM encrypt init: %w", err)
	}

	ciphertext, err := m.ctx.Encrypt(m.session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: AES-GCM encrypt: %w", err)
	}

	return &keyring.EncryptedData{
		Ciphertext: append([]byte(nil), ciphertext...),
		KeyID:      keyID,
		KeyVersion: meta.Version,
		Nonce:      append([]byte(nil), gcmParams.IV()...),
		AAD:        append([]byte(nil), aad...),
	}, nil
}

// Decrypt decrypts ciphertext with the key version recorded in EncryptedData.
func (m *Manager) Decrypt(ctx context.Context, data *keyring.EncryptedData) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("pkcs11: encrypted data is nil")
	}
	if data.KeyID == "" || data.KeyVersion < 1 {
		return nil, fmt.Errorf("pkcs11: encrypted data is missing key identity")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}

	meta, err := m.getMetadataLocked(data.KeyID)
	if err != nil {
		return nil, err
	}
	if meta.Type != keyring.KeyTypeAES256GCM {
		return nil, fmt.Errorf("%w: decryption requires %s, got %s", keyring.ErrUnsupportedKeyType, keyring.KeyTypeAES256GCM, meta.Type)
	}

	keyHandle, err := m.findOneLocked(pkcs11lib.CKO_SECRET_KEY, keyLabel(data.KeyID, data.KeyVersion), false)
	if err != nil {
		return nil, err
	}

	gcmParams := pkcs11lib.NewGCMParams(data.Nonce, data.AAD, 128)
	defer gcmParams.Free()

	if err := m.ctx.DecryptInit(m.session, []*pkcs11lib.Mechanism{
		pkcs11lib.NewMechanism(pkcs11lib.CKM_AES_GCM, gcmParams),
	}, keyHandle); err != nil {
		return nil, fmt.Errorf("pkcs11: AES-GCM decrypt init: %w", err)
	}

	plaintext, err := m.ctx.Decrypt(m.session, data.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: AES-GCM decrypt: %w", err)
	}
	return append([]byte(nil), plaintext...), nil
}
