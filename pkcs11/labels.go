package pkcs11

import (
	"fmt"
	"strings"
)

func validateKeyName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("pkcs11: key name is required")
	}
	if strings.ContainsAny(name, ":\x00") {
		return fmt.Errorf("pkcs11: key name cannot contain ':' or NUL")
	}
	return nil
}

func keyLabel(name string, version int) string {
	return fmt.Sprintf("%s:v%d", name, version)
}

func publicKeyManel(name string, version int) string {
	return keyLabel(name, version) + ":public"
}

func privateKeyManel(name string, version int) string {
	return keyLabel(name, version) + ":private"
}

func metadataLabel(name string) string {
	return name + ":meta"
}
