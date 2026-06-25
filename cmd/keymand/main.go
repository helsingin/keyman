package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	keyring "github.com/helsingin/keyman"
	"github.com/helsingin/keyman/pkcs11"
	tpm2backend "github.com/helsingin/keyman/tpm2"
)

type config struct {
	Addr             string
	StaticDir        string
	ModulePath       string
	TokenLabel       string
	PIN              string
	ApplicationLabel string
	TPM2TCTI         string
	TPM2WorkDir      string
}

type server struct {
	cfg       config
	startedAt time.Time

	mu         sync.Mutex
	manager    *pkcs11.Manager
	managerErr error
	tpm2       *tpm2backend.Client
}

type healthResponse struct {
	Status           string    `json:"status"`
	ModulePath       string    `json:"modulePath"`
	TokenLabel       string    `json:"tokenLabel"`
	ApplicationLabel string    `json:"applicationLabel"`
	StartedAt        time.Time `json:"startedAt"`
	Error            string    `json:"error,omitempty"`
}

type sessionRequest struct {
	ModulePath       string `json:"modulePath"`
	TokenLabel       string `json:"tokenLabel"`
	ApplicationLabel string `json:"applicationLabel"`
	PIN              string `json:"pin"`
}

type createKeyRequest struct {
	Name string          `json:"name"`
	Type keyring.KeyType `json:"type"`
}

type selfSignRequest struct {
	KeyID        string   `json:"keyId"`
	Label        string   `json:"label"`
	CommonName   string   `json:"commonName"`
	Organization string   `json:"organization"`
	DNSNames     []string `json:"dnsNames"`
	ValidHours   int      `json:"validHours"`
	IsCA         bool     `json:"isCa"`
}

type certificateCSRRequest struct {
	KeyID        string   `json:"keyId"`
	CommonName   string   `json:"commonName"`
	Organization string   `json:"organization"`
	DNSNames     []string `json:"dnsNames"`
}

type certificateImportRequest struct {
	Label     string `json:"label"`
	PEM       string `json:"pem"`
	DERBase64 string `json:"derBase64"`
}

type certificateImportResponse struct {
	Certificates []pkcs11.CertificateInfo `json:"certificates"`
}

type lifecycleResponse struct {
	CreatedAESKey      string   `json:"createdAesKey"`
	CreatedSigningKey  string   `json:"createdSigningKey"`
	CreatedCertificate string   `json:"createdCertificate"`
	OldKeyVersion      int      `json:"oldKeyVersion"`
	NewKeyVersion      int      `json:"newKeyVersion"`
	SignatureBytes     int      `json:"signatureBytes"`
	TLSSignatureBytes  int      `json:"tlsSignatureBytes"`
	DecryptedPlaintext string   `json:"decryptedPlaintext"`
	Operations         []string `json:"operations"`
}

type tpm2PCRRequest struct {
	Bank    string `json:"bank"`
	Indexes []int  `json:"indexes"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := parseConfig()
	if err != nil {
		return err
	}

	s := &server{
		cfg:       cfg,
		startedAt: time.Now().UTC(),
		tpm2: tpm2backend.New(tpm2backend.Config{
			TCTI:    cfg.TPM2TCTI,
			WorkDir: cfg.TPM2WorkDir,
		}),
	}
	if _, err := s.ensureManager(); err != nil {
		s.managerErr = err
	}
	defer s.close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/session", s.handleSession)
	mux.HandleFunc("/api/keys", s.handleKeys)
	mux.HandleFunc("/api/keys/", s.handleKeyAction)
	mux.HandleFunc("/api/certificates", s.handleCertificates)
	mux.HandleFunc("/api/certificates/csr", s.handleCertificateCSR)
	mux.HandleFunc("/api/certificates/import", s.handleCertificateImport)
	mux.HandleFunc("/api/certificates/", s.handleCertificateAction)
	mux.HandleFunc("/api/certificates/self-signed", s.handleSelfSignedCertificate)
	mux.HandleFunc("/api/lifecycle/run", s.handleLifecycleRun)
	mux.HandleFunc("/api/tpm2/health", s.handleTPM2Health)
	mux.HandleFunc("/api/tpm2/pcrs", s.handleTPM2PCRs)
	mux.HandleFunc("/api/tpm2/random", s.handleTPM2Random)
	mux.HandleFunc("/api/tpm2/demo", s.handleTPM2Demo)
	mux.Handle("/", spaHandler(cfg.StaticDir))

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "keymand listening on %s\n", cfg.Addr)
	return httpServer.ListenAndServe()
}

func parseConfig() (config, error) {
	addr := flag.String("addr", envDefault("KEYMAN_ADDR", ":8080"), "HTTP listen address")
	staticDir := flag.String("static", envDefault("KEYMAN_STATIC_DIR", "web/dist"), "compiled management console directory")
	modulePath := flag.String("module", envDefault("PKCS11_MODULE_PATH", ""), "PKCS#11 module path")
	tokenLabel := flag.String("token", envDefault("PKCS11_TOKEN_LABEL", "KEYMAN"), "PKCS#11 token label")
	pin := flag.String("pin", "", "PKCS#11 user PIN")
	applicationLabel := flag.String("app-label", envDefault("KEYMAN_APPLICATION_LABEL", "keyman"), "PKCS#11 application label")
	tpm2TCTI := flag.String("tpm2-tcti", envDefault("TPM2TOOLS_TCTI", "swtpm:host=127.0.0.1,port=2321"), "TPM2 TCTI")
	tpm2WorkDir := flag.String("tpm2-work-dir", envDefault("KEYMAN_TPM2_WORK_DIR", "/tmp/keyman-tpm2"), "TPM2 transient work directory")
	flag.Parse()

	resolvedPIN, err := resolvePIN(*pin)
	if err != nil {
		return config{}, err
	}
	return config{
		Addr:             *addr,
		StaticDir:        *staticDir,
		ModulePath:       strings.TrimSpace(*modulePath),
		TokenLabel:       strings.TrimSpace(*tokenLabel),
		PIN:              resolvedPIN,
		ApplicationLabel: strings.TrimSpace(*applicationLabel),
		TPM2TCTI:         strings.TrimSpace(*tpm2TCTI),
		TPM2WorkDir:      strings.TrimSpace(*tpm2WorkDir),
	}, nil
}

func resolvePIN(flagPIN string) (string, error) {
	if strings.TrimSpace(flagPIN) != "" {
		return flagPIN, nil
	}
	if value := os.Getenv("PKCS11_PIN"); value != "" {
		return value, nil
	}
	if path := os.Getenv("PKCS11_PIN_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read PKCS11_PIN_FILE: %w", err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	return "", nil
}

func (s *server) ensureManager() (*pkcs11.Manager, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.manager != nil {
		return s.manager, nil
	}
	cfg := s.cfg
	if strings.TrimSpace(cfg.ModulePath) == "" {
		s.managerErr = errors.New("PKCS11_MODULE_PATH is not configured")
		return nil, s.managerErr
	}
	if strings.TrimSpace(cfg.PIN) == "" {
		s.managerErr = errors.New("PIN is required to open the PKCS#11 token")
		return nil, s.managerErr
	}
	manager, err := pkcs11.New(pkcs11.Config{
		ModulePath:       cfg.ModulePath,
		TokenLabel:       cfg.TokenLabel,
		PIN:              cfg.PIN,
		ApplicationLabel: cfg.ApplicationLabel,
	})
	if err != nil {
		s.managerErr = err
		return nil, err
	}
	s.manager = manager
	s.managerErr = nil
	return manager, nil
}

func (s *server) configureSession(req sessionRequest) {
	s.mu.Lock()
	manager := s.manager
	s.manager = nil
	s.managerErr = nil
	s.cfg.PIN = req.PIN
	if strings.TrimSpace(req.ModulePath) != "" {
		s.cfg.ModulePath = strings.TrimSpace(req.ModulePath)
	}
	if strings.TrimSpace(req.TokenLabel) != "" {
		s.cfg.TokenLabel = strings.TrimSpace(req.TokenLabel)
	}
	if strings.TrimSpace(req.ApplicationLabel) != "" {
		s.cfg.ApplicationLabel = strings.TrimSpace(req.ApplicationLabel)
	}
	s.mu.Unlock()

	if manager != nil {
		_ = manager.Close()
	}
}

func (s *server) close() {
	s.mu.Lock()
	manager := s.manager
	s.manager = nil
	s.cfg.PIN = ""
	s.mu.Unlock()
	if manager != nil {
		_ = manager.Close()
	}
}

func (s *server) health() healthResponse {
	s.mu.Lock()
	manager := s.manager
	managerErr := s.managerErr
	cfg := s.cfg
	s.mu.Unlock()

	status := "ready"
	errText := ""
	if manager == nil {
		status = "not_configured"
	}
	if managerErr != nil {
		errText = managerErr.Error()
		if strings.Contains(errText, "not configured") || strings.Contains(errText, "PIN is required") {
			status = "not_configured"
		} else {
			status = "error"
		}
	}
	return healthResponse{
		Status:           status,
		ModulePath:       cfg.ModulePath,
		TokenLabel:       cfg.TokenLabel,
		ApplicationLabel: cfg.ApplicationLabel,
		StartedAt:        s.startedAt,
		Error:            errText,
	}
}

func (s *server) requireManager() (*pkcs11.Manager, bool) {
	manager, err := s.ensureManager()
	if err != nil {
		return nil, false
	}
	return manager, true
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.health())
}

func (s *server) handleSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req sessionRequest
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if strings.TrimSpace(req.PIN) == "" {
			writeError(w, http.StatusBadRequest, "PIN is required")
			return
		}
		s.configureSession(req)
		if _, err := s.ensureManager(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.health())
	case http.MethodDelete:
		s.close()
		writeJSON(w, http.StatusOK, s.health())
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *server) handleKeys(w http.ResponseWriter, r *http.Request) {
	manager, ok := s.requireManager()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, s.health().Error)
		return
	}

	switch r.Method {
	case http.MethodGet:
		keys, err := manager.ListKeys(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, keys)
	case http.MethodPost:
		var req createKeyRequest
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		key, err := manager.CreateKey(r.Context(), req.Type, req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, key)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *server) handleKeyAction(w http.ResponseWriter, r *http.Request) {
	manager, ok := s.requireManager()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, s.health().Error)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	if path == "" {
		writeError(w, http.StatusNotFound, "key id is required")
		return
	}

	switch r.Method {
	case http.MethodPost:
		keyID, ok := strings.CutSuffix(path, "/rotate")
		if !ok || keyID == "" {
			writeError(w, http.StatusNotFound, "unknown key action")
			return
		}
		decoded, err := url.PathUnescape(strings.TrimSuffix(keyID, "/"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid key id")
			return
		}
		key, err := manager.RotateKey(r.Context(), decoded)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, key)
	case http.MethodDelete:
		if strings.Contains(path, "/") {
			writeError(w, http.StatusNotFound, "unknown key action")
			return
		}
		decoded, err := url.PathUnescape(strings.TrimSuffix(path, "/"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid key id")
			return
		}
		if err := manager.DeleteKey(r.Context(), decoded); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	manager, ok := s.requireManager()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, s.health().Error)
		return
	}
	certs, err := manager.ListCertificates(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, certs)
}

func (s *server) handleCertificateCSR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	manager, ok := s.requireManager()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, s.health().Error)
		return
	}
	var req certificateCSRRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.KeyID) == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}
	if strings.TrimSpace(req.CommonName) == "" {
		writeError(w, http.StatusBadRequest, "common name is required")
		return
	}
	csr, err := manager.CreateCSR(r.Context(), strings.TrimSpace(req.KeyID), pkix.Name{
		CommonName:   strings.TrimSpace(req.CommonName),
		Organization: splitCSV(req.Organization),
	}, cleanedStrings(req.DNSNames))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, csr)
}

func (s *server) handleCertificateImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	manager, ok := s.requireManager()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, s.health().Error)
		return
	}
	var req certificateImportRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Label) == "" {
		writeError(w, http.StatusBadRequest, "certificate name is required")
		return
	}
	var data []byte
	if strings.TrimSpace(req.PEM) != "" {
		data = []byte(req.PEM)
	} else if strings.TrimSpace(req.DERBase64) != "" {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.DERBase64))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid DER certificate data")
			return
		}
		data = decoded
	} else {
		writeError(w, http.StatusBadRequest, "certificate data is required")
		return
	}
	certs, err := manager.ImportCertificates(r.Context(), strings.TrimSpace(req.Label), data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, certificateImportResponse{Certificates: certs})
}

func (s *server) handleCertificateAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	manager, ok := s.requireManager()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, s.health().Error)
		return
	}
	label := strings.TrimPrefix(r.URL.Path, "/api/certificates/")
	if label == "" || strings.Contains(label, "/") {
		writeError(w, http.StatusNotFound, "certificate label is required")
		return
	}
	decoded, err := url.PathUnescape(label)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid certificate label")
		return
	}
	if err := manager.DeleteCertificate(r.Context(), decoded); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleSelfSignedCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	manager, ok := s.requireManager()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, s.health().Error)
		return
	}

	var req selfSignRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Label) == "" {
		writeError(w, http.StatusBadRequest, "certificate label is required")
		return
	}
	if strings.TrimSpace(req.CommonName) == "" {
		writeError(w, http.StatusBadRequest, "common name is required")
		return
	}
	if req.ValidHours <= 0 {
		req.ValidHours = 24
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if req.IsCA {
		keyUsage |= x509.KeyUsageCertSign
	}
	now := time.Now().UTC()
	cert, err := manager.SelfSignCertificate(r.Context(), strings.TrimSpace(req.KeyID), strings.TrimSpace(req.Label), &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   strings.TrimSpace(req.CommonName),
			Organization: splitCSV(req.Organization),
		},
		DNSNames:              cleanedStrings(req.DNSNames),
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Duration(req.ValidHours) * time.Hour),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
		MaxPathLenZero:        req.IsCA,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info := pkcs11.NewCertificateInfo(strings.TrimSpace(req.Label), cert)
	info.KeyID = strings.TrimSpace(req.KeyID)
	writeJSON(w, http.StatusCreated, info)
}

func (s *server) handleLifecycleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	manager, ok := s.requireManager()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, s.health().Error)
		return
	}
	result, err := runLifecycle(r.Context(), manager)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *server) handleTPM2Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.tpm2.Status(ctx))
}

func (s *server) handleTPM2PCRs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		pcrs, err := s.tpm2.PCRs(ctx, "sha256", []int{0, 1, 2, 7})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, pcrs)
	case http.MethodPost:
		var req tpm2PCRRequest
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		pcrs, err := s.tpm2.PCRs(ctx, req.Bank, req.Indexes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, pcrs)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *server) handleTPM2Random(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	randomHex, err := s.tpm2.Random(ctx, 16)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"randomHex": randomHex})
}

func (s *server) handleTPM2Demo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	result, err := s.tpm2.Demo(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func runLifecycle(ctx context.Context, manager *pkcs11.Manager) (*lifecycleResponse, error) {
	suffix := time.Now().UTC().UnixNano()
	aesID := fmt.Sprintf("sample-aes-%d", suffix)
	signingID := fmt.Sprintf("sample-rsa-%d", suffix)
	certLabel := fmt.Sprintf("sample-cert-%d", suffix)

	if _, err := manager.CreateKey(ctx, keyring.KeyTypeAES256GCM, aesID); err != nil {
		return nil, err
	}
	oldCiphertext, err := manager.Encrypt(ctx, aesID, []byte("old payload"), []byte("keyman"))
	if err != nil {
		return nil, err
	}
	rotated, err := manager.RotateKey(ctx, aesID)
	if err != nil {
		return nil, err
	}
	oldPlaintext, err := manager.Decrypt(ctx, oldCiphertext)
	if err != nil {
		return nil, err
	}
	if _, err := manager.Encrypt(ctx, aesID, []byte("new payload"), nil); err != nil {
		return nil, err
	}

	if _, err := manager.CreateKey(ctx, keyring.KeyTypeRSA4096, signingID); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte("signed payload"))
	signature, err := manager.Sign(ctx, signingID, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	if err := manager.Verify(ctx, signingID, digest[:], signature, crypto.SHA256); err != nil {
		return nil, err
	}
	cert, err := manager.SelfSignCertificate(ctx, signingID, certLabel, &x509.Certificate{
		SerialNumber: big.NewInt(suffix),
		Subject: pkix.Name{
			CommonName:   "keyman sample",
			Organization: []string{"Example"},
		},
		NotBefore:             time.Now().UTC().Add(-time.Minute),
		NotAfter:              time.Now().UTC().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	if err != nil {
		return nil, err
	}
	tlsCert, err := manager.ManagedTLSCertificate(ctx, certLabel, signingID)
	if err != nil {
		return nil, err
	}
	tlsSignature, err := tlsCert.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	if err := rsa.VerifyPKCS1v15(tlsCert.Leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], tlsSignature); err != nil {
		return nil, err
	}

	return &lifecycleResponse{
		CreatedAESKey:      aesID,
		CreatedSigningKey:  signingID,
		CreatedCertificate: certLabel,
		OldKeyVersion:      oldCiphertext.KeyVersion,
		NewKeyVersion:      rotated.Version,
		SignatureBytes:     len(signature),
		TLSSignatureBytes:  len(tlsSignature),
		DecryptedPlaintext: string(oldPlaintext),
		Operations: []string{
			fmt.Sprintf("created AES-256-GCM key %s", aesID),
			fmt.Sprintf("encrypted payload with key version %d", oldCiphertext.KeyVersion),
			fmt.Sprintf("rotated AES key to version %d", rotated.Version),
			"decrypted version 1 ciphertext after rotation",
			fmt.Sprintf("created RSA-4096 signing key %s", signingID),
			fmt.Sprintf("signed and verified SHA-256 digest (%d byte signature)", len(signature)),
			fmt.Sprintf("stored self-signed certificate %s for %s", certLabel, cert.Subject.CommonName),
			fmt.Sprintf("loaded managed TLS certificate and signed through crypto.Signer (%d bytes)", len(tlsSignature)),
		},
	}, nil
}

func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	if strings.TrimSpace(message) == "" {
		message = http.StatusText(status)
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func spaHandler(staticDir string) http.Handler {
	fileServer := http.FileServer(http.Dir(staticDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
			return
		}
		path := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		fullPath := filepath.Join(staticDir, path)
		if !strings.HasPrefix(fullPath, filepath.Clean(staticDir)+string(os.PathSeparator)) {
			writeError(w, http.StatusBadRequest, "invalid path")
			return
		}
		info, err := os.Stat(fullPath)
		if err == nil && !info.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
	})
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return cleanedStrings(strings.Split(value, ","))
}

func cleanedStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func envDefault(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
