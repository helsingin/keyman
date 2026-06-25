// Package pkcs11 provides a PKCS#11 implementation of the keyring Manager interface.
package pkcs11

import (
	"errors"
	"strings"
)

const defaultApplicationLabel = "keyman"

// Config identifies the PKCS#11 module and token used by Manager.
type Config struct {
	ModulePath       string
	TokenLabel       string
	PIN              string
	ApplicationLabel string
}

func (c Config) validate() error {
	if strings.TrimSpace(c.ModulePath) == "" {
		return errors.New("pkcs11: module path is required")
	}
	if strings.TrimSpace(c.PIN) == "" {
		return errors.New("pkcs11: pin is required")
	}
	return nil
}

func (c Config) applicationLabel() string {
	if strings.TrimSpace(c.ApplicationLabel) == "" {
		return defaultApplicationLabel
	}
	return strings.TrimSpace(c.ApplicationLabel)
}
