package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/helsingin/keyman"
	pkcs11lib "github.com/miekg/pkcs11"
)

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

// Sign signs a digest for RSA/ECDSA or the original message for pure ML-DSA-65.
func (m *Manager) Sign(ctx context.Context, keyID string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
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
	return m.signManagedLocked(keyID, meta, digest, opts)
}

// Verify checks the signature against the same input and options as Sign.
func (m *Manager) Verify(ctx context.Context, keyID string, digest []byte, signature []byte, opts crypto.SignerOpts) error {
	if err := checkContext(ctx); err != nil {
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

	var (
		mechanism *pkcs11lib.Mechanism
		payload   []byte
		sig       []byte
		label     string
	)

	switch meta.Type {
	case keyring.KeyTypeMLDSA65, keyring.KeyTypeMLDSA87:
		if err := requireHash(opts, 0); err != nil {
			return err
		}
		mechanism = pkcs11lib.NewMechanism(ckmMLDSA, nil)
		payload, sig = digest, signature
		label = publicKeyManel(keyID, meta.Version)
	case keyring.KeyTypeRSA4096:
		payload, err = digestInfo(digest, opts)
		if err != nil {
			return err
		}
		sig = signature
		mechanism = pkcs11lib.NewMechanism(pkcs11lib.CKM_RSA_PKCS, nil)
		label = publicKeyManel(keyID, meta.Version)
	case keyring.KeyTypeECDSAP256:
		if err := requireHash(opts, crypto.SHA256); err != nil {
			return err
		}
		payload = digest
		sig, err = ecdsaDERToRaw(signature, 32)
		if err != nil {
			return err
		}
		mechanism = pkcs11lib.NewMechanism(pkcs11lib.CKM_ECDSA, nil)
		label = publicKeyManel(keyID, meta.Version)
	default:
		return fmt.Errorf("%w: signing not supported for %s", keyring.ErrUnsupportedKeyType, meta.Type)
	}

	keyHandle, err := m.findOneLocked(pkcs11lib.CKO_PUBLIC_KEY, label, false)
	if err != nil {
		return err
	}
	if err := m.ctx.VerifyInit(m.session, []*pkcs11lib.Mechanism{mechanism}, keyHandle); err != nil {
		return fmt.Errorf("pkcs11: verify init: %w", err)
	}
	if err := m.ctx.Verify(m.session, payload, sig); err != nil {
		return fmt.Errorf("pkcs11: verify: %w", err)
	}
	return nil
}

func (m *Manager) signManagedLocked(keyID string, meta keyMetadata, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch meta.Type {
	case keyring.KeyTypeRSA4096:
		keyHandle, err := m.findOneLocked(pkcs11lib.CKO_PRIVATE_KEY, privateKeyManel(keyID, meta.Version), false)
		if err != nil {
			return nil, err
		}
		payload, err := digestInfo(digest, opts)
		if err != nil {
			return nil, err
		}
		return m.signWithHandleLocked(keyring.KeyTypeRSA4096, keyHandle, payload, opts)
	case keyring.KeyTypeECDSAP256, keyring.KeyTypeMLDSA65, keyring.KeyTypeMLDSA87:
		keyHandle, err := m.findOneLocked(pkcs11lib.CKO_PRIVATE_KEY, privateKeyManel(keyID, meta.Version), false)
		if err != nil {
			return nil, err
		}
		return m.signWithHandleLocked(meta.Type, keyHandle, digest, opts)
	default:
		return nil, fmt.Errorf("%w: signing not supported for %s", keyring.ErrUnsupportedKeyType, meta.Type)
	}
}

func (m *Manager) signWithHandleLocked(keyType keyring.KeyType, keyHandle pkcs11lib.ObjectHandle, payload []byte, opts crypto.SignerOpts) ([]byte, error) {
	var mechanism *pkcs11lib.Mechanism
	switch keyType {
	case keyring.KeyTypeMLDSA65, keyring.KeyTypeMLDSA87:
		if err := requireHash(opts, 0); err != nil {
			return nil, err
		}
		mechanism = pkcs11lib.NewMechanism(ckmMLDSA, nil)
	case keyring.KeyTypeRSA4096:
		mechanism = pkcs11lib.NewMechanism(pkcs11lib.CKM_RSA_PKCS, nil)
	case keyring.KeyTypeECDSAP256:
		if err := requireHash(opts, crypto.SHA256); err != nil {
			return nil, err
		}
		mechanism = pkcs11lib.NewMechanism(pkcs11lib.CKM_ECDSA, nil)
	default:
		return nil, fmt.Errorf("%w: %s", keyring.ErrUnsupportedKeyType, keyType)
	}

	if err := m.ctx.SignInit(m.session, []*pkcs11lib.Mechanism{mechanism}, keyHandle); err != nil {
		return nil, fmt.Errorf("pkcs11: sign init: %w", err)
	}
	sig, err := m.ctx.Sign(m.session, payload)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: sign: %w", err)
	}
	if keyType == keyring.KeyTypeECDSAP256 {
		return ecdsaRawToDER(sig)
	}
	return append([]byte(nil), sig...), nil
}

// Signer returns a crypto.Signer for a managed asymmetric key.
func (m *Manager) Signer(ctx context.Context, keyID string, publicKey crypto.PublicKey) (*Signer, error) {
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
	return m.signerLocked(keyID, meta, publicKey)
}

func (m *Manager) signerLocked(keyID string, meta keyMetadata, publicKey crypto.PublicKey) (*Signer, error) {
	if meta.Type != keyring.KeyTypeRSA4096 && meta.Type != keyring.KeyTypeECDSAP256 && meta.Type != keyring.KeyTypeMLDSA65 && meta.Type != keyring.KeyTypeMLDSA87 {
		return nil, fmt.Errorf("%w: signer requires asymmetric key, got %s", keyring.ErrUnsupportedKeyType, meta.Type)
	}
	keyHandle, err := m.findOneLocked(pkcs11lib.CKO_PRIVATE_KEY, privateKeyManel(keyID, meta.Version), false)
	if err != nil {
		return nil, err
	}
	return &Signer{manager: m, keyHandle: keyHandle, keyType: meta.Type, publicKey: publicKey}, nil
}

// ManagedSigner returns a crypto.Signer for a managed asymmetric key and reads
// the matching public key from the token.
func (m *Manager) ManagedSigner(ctx context.Context, keyID string) (*Signer, error) {
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
	publicKey, err := m.publicKeyLocked(keyID, meta)
	if err != nil {
		return nil, err
	}
	return m.signerLocked(keyID, meta, publicKey)
}

// Signer adapts a PKCS#11 private key handle to crypto.Signer.
type Signer struct {
	manager   *Manager
	keyHandle pkcs11lib.ObjectHandle
	keyType   keyring.KeyType
	publicKey crypto.PublicKey
}

func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s == nil || s.manager == nil {
		return nil, fmt.Errorf("pkcs11: signer is nil")
	}

	payload := digest
	if s.keyType == keyring.KeyTypeRSA4096 {
		var err error
		payload, err = digestInfo(digest, opts)
		if err != nil {
			return nil, err
		}
	}

	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	if err := s.manager.ensureOpen(); err != nil {
		return nil, err
	}
	return s.manager.signWithHandleLocked(s.keyType, s.keyHandle, payload, opts)
}

func keyTypeFromPublicKey(pub crypto.PublicKey) (keyring.KeyType, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return keyring.KeyTypeRSA4096, nil
	case *ecdsa.PublicKey:
		return keyring.KeyTypeECDSAP256, nil
	default:
		return "", fmt.Errorf("%w: unsupported public key type %T", keyring.ErrUnsupportedKeyType, pub)
	}
}

func ecdsaRawToDER(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 || len(raw) == 0 {
		return nil, fmt.Errorf("pkcs11: invalid raw ECDSA signature length")
	}
	n := len(raw) / 2
	return asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(raw[:n]),
		S: new(big.Int).SetBytes(raw[n:]),
	})
}

func ecdsaDERToRaw(der []byte, size int) ([]byte, error) {
	var parsed ecdsaSignature
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: parse ECDSA signature: %w", err)
	}
	if len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return nil, fmt.Errorf("pkcs11: invalid ECDSA signature")
	}
	raw := make([]byte, size*2)
	r := parsed.R.Bytes()
	s := parsed.S.Bytes()
	if len(r) > size || len(s) > size {
		return nil, fmt.Errorf("pkcs11: ECDSA signature component too large")
	}
	copy(raw[size-len(r):size], r)
	copy(raw[2*size-len(s):], s)
	return raw, nil
}
