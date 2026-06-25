package keyring

import "errors"

var (
	ErrKeyNotFound        = errors.New("keyring: key not found")
	ErrUnsupportedKeyType = errors.New("keyring: unsupported key type")
	ErrUnsupportedBackend = errors.New("keyring: unsupported backend")
)
