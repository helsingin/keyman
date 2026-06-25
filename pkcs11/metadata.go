package pkcs11

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/helsingin/keyman"
)

type keyMetadata struct {
	Type      keyring.KeyType `json:"type"`
	Version   int             `json:"version"`
	CreatedAt time.Time       `json:"created_at"`
	RotatedAt time.Time       `json:"rotated_at,omitempty"`
}

func encodeMetadata(meta keyMetadata) ([]byte, error) {
	if meta.Version < 1 {
		return nil, fmt.Errorf("pkcs11: metadata version must be positive")
	}
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}
	return json.Marshal(meta)
}

func decodeMetadata(data []byte) (keyMetadata, error) {
	var meta keyMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return keyMetadata{}, fmt.Errorf("pkcs11: decode metadata: %w", err)
	}
	if meta.Type == "" || meta.Version < 1 || meta.CreatedAt.IsZero() {
		return keyMetadata{}, fmt.Errorf("pkcs11: invalid metadata")
	}
	return meta, nil
}
