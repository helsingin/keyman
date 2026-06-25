// Package tpm2 provides TPM 2.0 operations through the tpm2-tools command set.
package tpm2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Config identifies the TPM TCTI and local working directory used by Client.
type Config struct {
	TCTI    string
	WorkDir string
}

// Client runs TPM2 operations through tpm2-tools.
type Client struct {
	tcti    string
	workDir string
	mu      sync.Mutex
}

// Status describes TPM2 tool and device readiness.
type Status struct {
	Ready        bool   `json:"ready"`
	TCTI         string `json:"tcti"`
	ToolsVersion string `json:"toolsVersion"`
	RandomHex    string `json:"randomHex,omitempty"`
	Error        string `json:"error,omitempty"`
}

// PCR describes one platform configuration register value.
type PCR struct {
	Bank  string `json:"bank"`
	Index int    `json:"index"`
	Value string `json:"value"`
}

// DemoResult describes a complete TPM2 exercise run.
type DemoResult struct {
	TCTI                    string   `json:"tcti"`
	PrimaryContext          string   `json:"primaryContext"`
	SigningKeyPublic        string   `json:"signingKeyPublic"`
	SignatureBytes          int      `json:"signatureBytes"`
	SecretBytes             int      `json:"secretBytes"`
	UnsealedMatches         bool     `json:"unsealedMatches"`
	PCRPolicyDigest         string   `json:"pcrPolicyDigest"`
	PCRBoundSecretBytes     int      `json:"pcrBoundSecretBytes"`
	PCRBoundUnsealedMatches bool     `json:"pcrBoundUnsealedMatches"`
	QuoteBytes              int      `json:"quoteBytes"`
	QuoteSignatureBytes     int      `json:"quoteSignatureBytes"`
	AttestationKeyName      string   `json:"attestationKeyName"`
	PCRs                    []PCR    `json:"pcrs"`
	Operations              []string `json:"operations"`
}

// New creates a TPM2 command client.
func New(cfg Config) *Client {
	tcti := strings.TrimSpace(cfg.TCTI)
	if tcti == "" {
		tcti = "swtpm:host=127.0.0.1,port=2321"
	}
	workDir := strings.TrimSpace(cfg.WorkDir)
	if workDir == "" {
		workDir = filepath.Join(os.TempDir(), "keyman-tpm2")
	}
	return &Client{
		tcti:    tcti,
		workDir: workDir,
	}
}

// Status checks that tpm2-tools can communicate with the configured TPM.
func (c *Client) Status(ctx context.Context) Status {
	version, versionErr := c.run(ctx, "", "tpm2_getrandom", "--version")
	random, randomErr := c.Random(ctx, 8)
	status := Status{
		Ready:        versionErr == nil && randomErr == nil,
		TCTI:         c.tcti,
		ToolsVersion: firstLine(version),
	}
	if randomErr == nil {
		status.RandomHex = random
	}
	if versionErr != nil {
		status.Error = versionErr.Error()
	} else if randomErr != nil {
		status.Error = randomErr.Error()
	}
	return status
}

// Random returns TPM-generated random bytes encoded as lowercase hex.
func (c *Client) Random(ctx context.Context, size int) (string, error) {
	if size <= 0 || size > 64 {
		size = 16
	}
	dir, err := c.tempDir()
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	outPath := filepath.Join(dir, "random.bin")
	if _, err := c.run(ctx, dir, "tpm2_getrandom", "-o", outPath, strconv.Itoa(size)); err != nil {
		return "", err
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		return "", fmt.Errorf("tpm2: read random output: %w", err)
	}
	return hex.EncodeToString(data), nil
}

// PCRs reads PCR values for a bank and set of indexes.
func (c *Client) PCRs(ctx context.Context, bank string, indexes []int) ([]PCR, error) {
	bank = strings.TrimSpace(bank)
	if bank == "" {
		bank = "sha256"
	}
	if len(indexes) == 0 {
		indexes = []int{0, 1, 2, 7}
	}
	indexParts := make([]string, 0, len(indexes))
	for _, index := range indexes {
		if index < 0 || index > 23 {
			return nil, fmt.Errorf("tpm2: PCR index out of range: %d", index)
		}
		indexParts = append(indexParts, strconv.Itoa(index))
	}
	output, err := c.run(ctx, "", "tpm2_pcrread", bank+":"+strings.Join(indexParts, ","))
	if err != nil {
		return nil, err
	}
	return parsePCRs(bank, output), nil
}

// Demo creates a TPM-resident signing key, signs a payload, seals a secret, and
// unseals it again through the configured TPM.
func (c *Client) Demo(ctx context.Context) (*DemoResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir, err := c.tempDir()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	payload := []byte("keyman TPM2 signing payload")
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("tpm2: generate secret: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload.dat"), payload, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.dat"), secret, 0o600); err != nil {
		return nil, err
	}

	parentHandle := "0x81010001"
	c.flushTransient(ctx, dir)
	c.evictPersistent(ctx, dir, parentHandle)
	defer c.flushTransient(context.Background(), dir)
	defer c.evictPersistent(context.Background(), dir, parentHandle)

	if _, err := c.run(ctx, dir, "tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", "primary.ctx"); err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_evictcontrol", "-C", "o", "-c", "primary.ctx", parentHandle); err != nil {
		return nil, err
	}
	c.flushTransient(ctx, dir)

	if _, err := c.run(ctx, dir, "tpm2_create", "-C", parentHandle, "-G", "ecc", "-u", "signing.pub", "-r", "signing.priv", "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"); err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_load", "-C", parentHandle, "-u", "signing.pub", "-r", "signing.priv", "-c", "signing.ctx"); err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_readpublic", "-c", "signing.ctx", "-f", "pem", "-o", "signing.pem"); err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_sign", "-c", "signing.ctx", "-g", "sha256", "-f", "plain", "-o", "signature.bin", "payload.dat"); err != nil {
		return nil, err
	}
	c.flushTransient(ctx, dir)

	if _, err := c.run(ctx, dir, "tpm2_create", "-C", parentHandle, "-i", "secret.dat", "-u", "seal.pub", "-r", "seal.priv"); err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_load", "-C", parentHandle, "-u", "seal.pub", "-r", "seal.priv", "-c", "seal.ctx"); err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_unseal", "-c", "seal.ctx", "-o", "unsealed.dat"); err != nil {
		return nil, err
	}
	c.flushTransient(ctx, dir)

	signature, err := os.ReadFile(filepath.Join(dir, "signature.bin"))
	if err != nil {
		return nil, fmt.Errorf("tpm2: read signature: %w", err)
	}
	publicPEM, err := os.ReadFile(filepath.Join(dir, "signing.pem"))
	if err != nil {
		return nil, fmt.Errorf("tpm2: read signing public key: %w", err)
	}
	unsealed, err := os.ReadFile(filepath.Join(dir, "unsealed.dat"))
	if err != nil {
		return nil, fmt.Errorf("tpm2: read unsealed secret: %w", err)
	}
	pcrs, err := c.PCRs(ctx, "sha256", []int{0, 1, 2, 7})
	if err != nil {
		return nil, err
	}

	policyResult, err := c.policyBoundSecret(ctx, dir, parentHandle)
	if err != nil {
		return nil, err
	}
	quoteResult, err := c.attestationQuote(ctx, dir)
	if err != nil {
		return nil, err
	}

	return &DemoResult{
		TCTI:                    c.tcti,
		PrimaryContext:          "owner hierarchy ECC primary at " + parentHandle,
		SigningKeyPublic:        string(publicPEM),
		SignatureBytes:          len(signature),
		SecretBytes:             len(secret),
		UnsealedMatches:         bytes.Equal(secret, unsealed),
		PCRPolicyDigest:         policyResult.PolicyDigest,
		PCRBoundSecretBytes:     policyResult.SecretBytes,
		PCRBoundUnsealedMatches: policyResult.UnsealedMatches,
		QuoteBytes:              quoteResult.QuoteBytes,
		QuoteSignatureBytes:     quoteResult.SignatureBytes,
		AttestationKeyName:      quoteResult.AttestationKeyName,
		PCRs:                    pcrs,
		Operations: []string{
			"created owner hierarchy ECC primary",
			fmt.Sprintf("persisted primary at %s for child object loading", parentHandle),
			"created TPM-resident ECC signing key",
			fmt.Sprintf("signed payload through TPM key (%d byte signature)", len(signature)),
			"created keyedhash sealed-data object",
			fmt.Sprintf("unsealed %d byte secret through TPM", len(unsealed)),
			fmt.Sprintf("read %d SHA-256 PCR values", len(pcrs)),
			"created PCR policy from SHA-256 PCR 0,1,2,7",
			fmt.Sprintf("unsealed %d byte secret only after matching PCR policy", policyResult.SecretBytes),
			fmt.Sprintf("created attestation key and emitted %d byte quote", quoteResult.QuoteBytes),
		},
	}, nil
}

type policyResult struct {
	PolicyDigest    string
	SecretBytes     int
	UnsealedMatches bool
}

func (c *Client) policyBoundSecret(ctx context.Context, dir string, parentHandle string) (*policyResult, error) {
	defer c.flushTransient(context.Background(), dir)

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("tpm2: generate policy secret: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy-secret.dat"), secret, 0o600); err != nil {
		return nil, err
	}

	if _, err := c.run(ctx, dir, "tpm2_startauthsession", "-S", "policy.ctx"); err != nil {
		return nil, err
	}
	policyDigest, err := c.run(ctx, dir, "tpm2_policypcr", "-S", "policy.ctx", "-l", "sha256:0,1,2,7", "-L", "policy.dat")
	_, _ = c.run(context.Background(), dir, "tpm2_flushcontext", "policy.ctx")
	if err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_create", "-C", parentHandle, "-i", "policy-secret.dat", "-L", "policy.dat", "-u", "policy-seal.pub", "-r", "policy-seal.priv"); err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_load", "-C", parentHandle, "-u", "policy-seal.pub", "-r", "policy-seal.priv", "-c", "policy-seal.ctx"); err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_startauthsession", "--policy-session", "-S", "unseal-policy.ctx"); err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_policypcr", "-S", "unseal-policy.ctx", "-l", "sha256:0,1,2,7"); err != nil {
		_, _ = c.run(context.Background(), dir, "tpm2_flushcontext", "unseal-policy.ctx")
		return nil, err
	}
	err = nil
	if _, err = c.run(ctx, dir, "tpm2_unseal", "-c", "policy-seal.ctx", "-p", "session:unseal-policy.ctx", "-o", "policy-unsealed.dat"); err != nil {
		_, _ = c.run(context.Background(), dir, "tpm2_flushcontext", "unseal-policy.ctx")
		return nil, err
	}
	_, _ = c.run(context.Background(), dir, "tpm2_flushcontext", "unseal-policy.ctx")
	unsealed, err := os.ReadFile(filepath.Join(dir, "policy-unsealed.dat"))
	if err != nil {
		return nil, fmt.Errorf("tpm2: read policy unsealed secret: %w", err)
	}
	return &policyResult{
		PolicyDigest:    firstLine(policyDigest),
		SecretBytes:     len(secret),
		UnsealedMatches: bytes.Equal(secret, unsealed),
	}, nil
}

type quoteResult struct {
	QuoteBytes         int
	SignatureBytes     int
	AttestationKeyName string
}

func (c *Client) attestationQuote(ctx context.Context, dir string) (*quoteResult, error) {
	const akHandle = "0x81010003"
	c.evictPersistent(ctx, dir, akHandle)
	defer c.evictPersistent(context.Background(), dir, akHandle)

	if _, err := c.run(ctx, dir, "tpm2_createek", "-c", "ek.ctx", "-G", "rsa", "-u", "ek.pub"); err != nil {
		return nil, err
	}
	if _, err := c.run(ctx, dir, "tpm2_createak", "-C", "ek.ctx", "-c", "ak.ctx", "-G", "rsa", "-g", "sha256", "-s", "rsassa", "-u", "ak.pub", "-n", "ak.name"); err != nil {
		return nil, err
	}
	handles, err := c.transientHandles(ctx, dir)
	if err != nil {
		return nil, err
	}
	if len(handles) == 0 {
		return nil, fmt.Errorf("tpm2: no transient attestation key handle found")
	}
	if _, err := c.run(ctx, dir, "tpm2_evictcontrol", "-C", "o", "-c", handles[len(handles)-1], akHandle); err != nil {
		return nil, err
	}
	c.flushTransient(ctx, dir)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("tpm2: generate quote nonce: %w", err)
	}
	if _, err := c.run(ctx, dir, "tpm2_quote", "-c", akHandle, "-l", "sha256:0,1,2,7", "-q", hex.EncodeToString(nonce), "-m", "quote.msg", "-s", "quote.sig", "-o", "quote.pcr", "-g", "sha256"); err != nil {
		return nil, err
	}
	quote, err := os.ReadFile(filepath.Join(dir, "quote.msg"))
	if err != nil {
		return nil, fmt.Errorf("tpm2: read quote message: %w", err)
	}
	signature, err := os.ReadFile(filepath.Join(dir, "quote.sig"))
	if err != nil {
		return nil, fmt.Errorf("tpm2: read quote signature: %w", err)
	}
	akName, err := os.ReadFile(filepath.Join(dir, "ak.name"))
	if err != nil {
		return nil, fmt.Errorf("tpm2: read attestation key name: %w", err)
	}
	return &quoteResult{
		QuoteBytes:         len(quote),
		SignatureBytes:     len(signature),
		AttestationKeyName: strings.TrimSpace(hex.EncodeToString(akName)),
	}, nil
}

func (c *Client) tempDir() (string, error) {
	if err := os.MkdirAll(c.workDir, 0o700); err != nil {
		return "", fmt.Errorf("tpm2: create work dir: %w", err)
	}
	dir, err := os.MkdirTemp(c.workDir, "run-")
	if err != nil {
		return "", fmt.Errorf("tpm2: create temp dir: %w", err)
	}
	return dir, nil
}

func (c *Client) run(ctx context.Context, dir string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(), "TPM2TOOLS_TCTI="+c.tcti)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = strings.TrimSpace(stdout.String())
		}
		if message == "" {
			message = err.Error()
		}
		return stdout.String(), fmt.Errorf("tpm2: %s: %s", name, message)
	}
	return stdout.String(), nil
}

var (
	pcrLine             = regexp.MustCompile(`^\s*([0-9]+)\s*:\s*(0x[0-9a-fA-F]+)\s*$`)
	transientHandleLine = regexp.MustCompile(`^\s*-\s*(0x[0-9a-fA-F]+)\s*$`)
)

func parsePCRs(bank string, output string) []PCR {
	out := []PCR{}
	for _, line := range strings.Split(output, "\n") {
		match := pcrLine.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		index, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		out = append(out, PCR{
			Bank:  bank,
			Index: index,
			Value: strings.ToLower(match[2]),
		})
	}
	return out
}

func (c *Client) flushTransient(ctx context.Context, dir string) {
	_, _ = c.run(ctx, dir, "tpm2_flushcontext", "-t")
}

func (c *Client) transientHandles(ctx context.Context, dir string) ([]string, error) {
	output, err := c.run(ctx, dir, "tpm2_getcap", "handles-transient")
	if err != nil {
		return nil, err
	}
	handles := []string{}
	for _, line := range strings.Split(output, "\n") {
		match := transientHandleLine.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		handles = append(handles, strings.ToLower(match[1]))
	}
	return handles, nil
}

func (c *Client) evictPersistent(ctx context.Context, dir string, handle string) {
	_, _ = c.run(ctx, dir, "tpm2_evictcontrol", "-C", "o", "-c", handle)
}

func firstLine(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	line, _, _ := strings.Cut(value, "\n")
	return strings.TrimSpace(line)
}
