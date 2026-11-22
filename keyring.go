// Package keyring defines backend-neutral key lifecycle primitives for HSM-backed keys.
package keyring

import (
	"context"
	"crypto"
	"time"
)

// KeyType identifies a managed key class.
type KeyType string

const (
	KeyTypeMLKEM768  KeyType = "ml-kem-768"
	KeyTypeMLDSA65   KeyType = "ml-dsa-65"
	KeyTypeAES256GCM KeyType = "aes-256-gcm"
	KeyTypeRSA4096   KeyType = "rsa-4096"
	KeyTypeECDSAP256 KeyType = "ecdsa-p256"
)

// Key describes a managed key without exposing key material.
type Key struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      KeyType   `json:"type"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	RotatedAt time.Time `json:"rotatedAt"`
}

// KeyMetadata describes the current lifecycle state of a managed key.
type KeyMetadata struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Type          KeyType   `json:"type"`
	LatestVersion int       `json:"latestVersion"`
	MinDecryptVer int       `json:"minDecryptVersion"`
	CreatedAt     time.Time `json:"createdAt"`
	RotatedAt     time.Time `json:"rotatedAt"`
}

// EncryptedData carries ciphertext plus the key version needed for decrypt after rotation.
type EncryptedData struct {
	Ciphertext []byte `json:"ciphertext"`
	KeyID      string `json:"keyId"`
	KeyVersion int    `json:"keyVersion"`
	Nonce      []byte `json:"nonce"`
	AAD        []byte `json:"aad"`
}

// Manager defines the key lifecycle behavior implemented by concrete backends.
type Manager interface {
	CreateKey(ctx context.Context, keyType KeyType, name string) (*Key, error)
	RotateKey(ctx context.Context, keyID string) (*Key, error)
	GetKey(ctx context.Context, keyID string) (*Key, error)
	ListKeys(ctx context.Context) ([]*KeyMetadata, error)
	PublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error)

	Encrypt(ctx context.Context, keyID string, plaintext []byte, aad []byte) (*EncryptedData, error)
	Decrypt(ctx context.Context, data *EncryptedData) ([]byte, error)

	Sign(ctx context.Context, keyID string, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	Verify(ctx context.Context, keyID string, digest []byte, signature []byte, opts crypto.SignerOpts) error
}
