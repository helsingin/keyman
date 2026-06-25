package pkcs11

import (
	"crypto"
	"fmt"
)

var digestInfoPrefixes = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func digestInfo(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("pkcs11: signer opts are required")
	}
	hash := opts.HashFunc()
	if !hash.Available() {
		return nil, fmt.Errorf("pkcs11: hash is not available: %v", hash)
	}
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("pkcs11: digest length %d does not match %v size %d", len(digest), hash, hash.Size())
	}
	prefix, ok := digestInfoPrefixes[hash]
	if !ok {
		return nil, fmt.Errorf("pkcs11: unsupported RSA hash: %v", hash)
	}
	out := make([]byte, 0, len(prefix)+len(digest))
	out = append(out, prefix...)
	out = append(out, digest...)
	return out, nil
}

func requireHash(opts crypto.SignerOpts, want crypto.Hash) error {
	if opts == nil {
		return fmt.Errorf("pkcs11: signer opts are required")
	}
	if got := opts.HashFunc(); got != want {
		return fmt.Errorf("pkcs11: expected %v, got %v", want, got)
	}
	return nil
}
