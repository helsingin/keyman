package pkcs11

import "testing"

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "valid minimal",
			cfg:     Config{ModulePath: "/usr/lib/softhsm/libsofthsm2.so", PIN: "1234"},
			wantErr: false,
		},
		{
			name:    "missing module",
			cfg:     Config{PIN: "1234"},
			wantErr: true,
		},
		{
			name:    "missing pin",
			cfg:     Config{ModulePath: "/usr/lib/softhsm/libsofthsm2.so"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplicationLabelDefault(t *testing.T) {
	if got := (Config{}).applicationLabel(); got != defaultApplicationLabel {
		t.Fatalf("applicationLabel() = %q, want %q", got, defaultApplicationLabel)
	}
}
