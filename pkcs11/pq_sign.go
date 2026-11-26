package pkcs11

import (
	"crypto"
	"errors"
	"fmt"

	keyring "github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

// PQSigningMode controls the PKCS#11 hedging policy. Tokens must honor required
// modes or return an error. Entropy remains owned by the token.
type PQSigningMode uint

const (
	PQTokenDefault  PQSigningMode = iota // CKH_HEDGE_PREFERRED
	PQRandomized                         // CKH_HEDGE_REQUIRED
	PQDeterministic                      // CKH_DETERMINISTIC_REQUIRED
)

// PQSigningOptions selects pure ML-DSA/SLH-DSA with a context of at most 255 bytes.
// It implements crypto.SignerOpts; prehash signing is not supported.
type PQSigningOptions struct {
	Context []byte
	Mode    PQSigningMode
}

func (PQSigningOptions) HashFunc() crypto.Hash { return crypto.Hash(0) }

// ErrUnsupportedPQOperation marks unavailable PQ mechanisms or unsupported
// context/mode requests. Wrapped PKCS#11 errors remain accessible with errors.Is.
var ErrUnsupportedPQOperation = errors.New("pkcs11: unsupported PQ operation")

func pqSignatureMechanism(typ keyring.KeyType) (uint, bool) {
	switch typ {
	case keyring.KeyTypeMLDSA65, keyring.KeyTypeMLDSA87:
		return ckmMLDSA, true
	case keyring.KeyTypeSLHDSASHA2192s, keyring.KeyTypeSLHDSASHA2256s:
		return ckmSLHDSA, true
	default:
		return 0, false
	}
}

func parsePQSigningOptions(opts crypto.SignerOpts) (PQSigningOptions, error) {
	var options PQSigningOptions
	switch value := opts.(type) {
	case crypto.Hash:
		if value != 0 {
			return options, fmt.Errorf("%w: prehash signing is not supported", ErrUnsupportedPQOperation)
		}
	case PQSigningOptions:
		options = value
	case *PQSigningOptions:
		if value == nil {
			return options, fmt.Errorf("%w: nil signing options", ErrUnsupportedPQOperation)
		}
		options = *value
	default:
		return options, fmt.Errorf("%w: use crypto.Hash(0) or PQSigningOptions", ErrUnsupportedPQOperation)
	}
	if len(options.Context) > 255 {
		return options, fmt.Errorf("%w: context exceeds 255 bytes", ErrUnsupportedPQOperation)
	}
	if options.Mode > PQDeterministic {
		return options, fmt.Errorf("%w: unknown signing mode %d", ErrUnsupportedPQOperation, options.Mode)
	}
	return options, nil
}

func pqMechanism(typ keyring.KeyType, opts crypto.SignerOpts) (*p11.Mechanism, func(), error) {
	mechanism, ok := pqSignatureMechanism(typ)
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", keyring.ErrUnsupportedKeyType, typ)
	}
	options, err := parsePQSigningOptions(opts)
	if err != nil {
		return nil, nil, err
	}
	if len(options.Context) == 0 && options.Mode == PQTokenDefault {
		return p11.NewMechanism(mechanism, nil), func() {}, nil
	}
	params, free, err := marshalPQSigningOptions(options)
	if err != nil {
		return nil, nil, err
	}
	return p11.NewMechanism(mechanism, params), free, nil
}

func pqOperationError(operation string, err error) error {
	if errors.Is(err, p11.Error(p11.CKR_MECHANISM_INVALID)) || errors.Is(err, p11.Error(p11.CKR_MECHANISM_PARAM_INVALID)) || errors.Is(err, p11.Error(p11.CKR_FUNCTION_NOT_SUPPORTED)) {
		return fmt.Errorf("%s: %w: %w", operation, ErrUnsupportedPQOperation, err)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
