package pkcs11

import (
	"crypto"
	"errors"
	p11 "github.com/miekg/pkcs11"
	"testing"
)

type unknownPQOptions struct{}

func (unknownPQOptions) HashFunc() crypto.Hash { return 0 }

func TestPQSigningOptions(t *testing.T) {
	for _, opts := range []crypto.SignerOpts{crypto.Hash(0), PQSigningOptions{}, &PQSigningOptions{Context: make([]byte, 255), Mode: PQDeterministic}, PQSigningOptions{Mode: PQRandomized}} {
		if _, err := parsePQSigningOptions(opts); err != nil {
			t.Fatal(err)
		}
	}
	for _, opts := range []crypto.SignerOpts{nil, (*PQSigningOptions)(nil), crypto.SHA256, unknownPQOptions{}, PQSigningOptions{Context: make([]byte, 256)}, PQSigningOptions{Mode: 3}} {
		if _, err := parsePQSigningOptions(opts); !errors.Is(err, ErrUnsupportedPQOperation) {
			t.Fatalf("%T: %v", opts, err)
		}
	}
	original := p11.Error(p11.CKR_MECHANISM_PARAM_INVALID)
	err := pqOperationError("sign", original)
	if !errors.Is(err, ErrUnsupportedPQOperation) || !errors.Is(err, original) {
		t.Fatal(err)
	}
	if errors.Is(pqOperationError("sign", p11.Error(p11.CKR_DEVICE_ERROR)), ErrUnsupportedPQOperation) {
		t.Fatal("device error misreported")
	}
}
