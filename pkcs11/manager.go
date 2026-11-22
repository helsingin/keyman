package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/helsingin/keyman"
	pkcs11lib "github.com/miekg/pkcs11"
)

// Manager stores and operates keys through a PKCS#11 token.
type Manager struct {
	ctx        *pkcs11lib.Ctx
	session    pkcs11lib.SessionHandle
	appLabel   string
	modulePath string

	mu     sync.Mutex
	closed bool
}

// New opens a read-write user session against a PKCS#11 token.
func New(cfg Config) (*Manager, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	p := pkcs11lib.New(strings.TrimSpace(cfg.ModulePath))
	if p == nil {
		return nil, fmt.Errorf("pkcs11: create module context")
	}
	if err := p.Initialize(); err != nil && !isPKCS11Error(err, pkcs11lib.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return nil, fmt.Errorf("pkcs11: initialize module: %w", err)
	}

	slot, err := findTokenSlot(p, strings.TrimSpace(cfg.TokenLabel))
	if err != nil {
		_ = p.Finalize()
		return nil, err
	}

	session, err := p.OpenSession(slot, pkcs11lib.CKF_SERIAL_SESSION|pkcs11lib.CKF_RW_SESSION)
	if err != nil {
		_ = p.Finalize()
		return nil, fmt.Errorf("pkcs11: open session: %w", err)
	}

	if err := p.Login(session, pkcs11lib.CKU_USER, cfg.PIN); err != nil && !isPKCS11Error(err, pkcs11lib.CKR_USER_ALREADY_LOGGED_IN) {
		_ = p.CloseSession(session)
		_ = p.Finalize()
		return nil, fmt.Errorf("pkcs11: login: %w", err)
	}

	return &Manager{
		ctx:        p,
		session:    session,
		appLabel:   cfg.applicationLabel(),
		modulePath: strings.TrimSpace(cfg.ModulePath),
	}, nil
}

// Close closes the PKCS#11 session and finalizes the module context.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true

	var err error
	if logoutErr := m.ctx.Logout(m.session); logoutErr != nil && !isPKCS11Error(logoutErr, pkcs11lib.CKR_USER_NOT_LOGGED_IN) {
		err = errors.Join(err, logoutErr)
	}
	if closeErr := m.ctx.CloseSession(m.session); closeErr != nil {
		err = errors.Join(err, closeErr)
	}
	if finalizeErr := m.ctx.Finalize(); finalizeErr != nil {
		err = errors.Join(err, finalizeErr)
	}
	return err
}

func findTokenSlot(ctx *pkcs11lib.Ctx, tokenLabel string) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: list slots: %w", err)
	}
	if len(slots) == 0 {
		return 0, fmt.Errorf("pkcs11: no initialized tokens found")
	}
	if tokenLabel == "" {
		return slots[0], nil
	}
	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err == nil && strings.TrimSpace(info.Label) == tokenLabel {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("pkcs11: token not found: %s", tokenLabel)
}

func (m *Manager) ensureOpen() error {
	if m == nil || m.ctx == nil {
		return fmt.Errorf("pkcs11: manager is nil")
	}
	if m.closed {
		return fmt.Errorf("pkcs11: manager is closed")
	}
	return nil
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func isPKCS11Error(err error, code uint) bool {
	if err == nil {
		return false
	}
	var pkcsErr pkcs11lib.Error
	if errors.As(err, &pkcsErr) {
		return uint(pkcsErr) == code
	}
	return strings.Contains(err.Error(), pkcs11lib.Error(code).Error())
}

func (m *Manager) now() time.Time {
	return time.Now().UTC()
}

var _ keyring.Manager = (*Manager)(nil)
