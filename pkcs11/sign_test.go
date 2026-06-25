package pkcs11

import "testing"

func TestECDSASignatureRoundTrip(t *testing.T) {
	raw := make([]byte, 64)
	raw[31] = 1
	raw[63] = 2

	der, err := ecdsaRawToDER(raw)
	if err != nil {
		t.Fatalf("ecdsaRawToDER: %v", err)
	}
	got, err := ecdsaDERToRaw(der, 32)
	if err != nil {
		t.Fatalf("ecdsaDERToRaw: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatal("ECDSA signature round trip mismatch")
	}
}
