package pkcs11

import (
	"errors"
	"fmt"

	"github.com/helsingin/keyman"
	pkcs11lib "github.com/miekg/pkcs11"
)

func (m *Manager) findOneLocked(class uint, label string, requireApplicationLabel bool) (pkcs11lib.ObjectHandle, error) {
	template := []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_CLASS, class),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, label),
	}
	if requireApplicationLabel {
		template = append(template, pkcs11lib.NewAttribute(pkcs11lib.CKA_APPLICATION, m.appLabel))
	}

	if err := m.ctx.FindObjectsInit(m.session, template); err != nil {
		return 0, fmt.Errorf("pkcs11: find init: %w", err)
	}
	defer func() { _ = m.ctx.FindObjectsFinal(m.session) }()

	objs, _, err := m.ctx.FindObjects(m.session, 2)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: find object: %w", err)
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("%w: %s", keyring.ErrKeyNotFound, label)
	}
	if len(objs) > 1 {
		return 0, fmt.Errorf("pkcs11: multiple objects found for label %q", label)
	}
	return objs[0], nil
}

func (m *Manager) getValueLocked(obj pkcs11lib.ObjectHandle) ([]byte, error) {
	attrs, err := m.ctx.GetAttributeValue(m.session, obj, []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: get object value: %w", err)
	}
	if len(attrs) != 1 {
		return nil, fmt.Errorf("pkcs11: expected one value attribute")
	}
	return attrs[0].Value, nil
}

func (m *Manager) getMetadataLocked(name string) (keyMetadata, error) {
	obj, err := m.findOneLocked(pkcs11lib.CKO_DATA, metadataLabel(name), true)
	if err != nil {
		return keyMetadata{}, err
	}
	value, err := m.getValueLocked(obj)
	if err != nil {
		return keyMetadata{}, err
	}
	return decodeMetadata(value)
}

func (m *Manager) storeMetadataLocked(name string, meta keyMetadata) error {
	value, err := encodeMetadata(meta)
	if err != nil {
		return err
	}

	existing, err := m.findOneLocked(pkcs11lib.CKO_DATA, metadataLabel(name), true)
	if err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
		return err
	}
	// CKA_VALUE may be read-only even on a modifiable data object. Create the
	// replacement before retiring the old metadata, so failed writes preserve it.

	replacement, err := m.ctx.CreateObject(m.session, []*pkcs11lib.Attribute{
		pkcs11lib.NewAttribute(pkcs11lib.CKA_CLASS, pkcs11lib.CKO_DATA),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_LABEL, metadataLabel(name)),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_APPLICATION, m.appLabel),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_VALUE, value),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_TOKEN, true),
		pkcs11lib.NewAttribute(pkcs11lib.CKA_MODIFIABLE, true),
	})
	if err != nil {
		return fmt.Errorf("pkcs11: create metadata: %w", err)
	}
	if existing != 0 {
		if err := m.ctx.DestroyObject(m.session, existing); err != nil {
			return errors.Join(fmt.Errorf("pkcs11: retire metadata: %w", err), m.ctx.DestroyObject(m.session, replacement))
		}
	}
	return nil
}

func (m *Manager) destroyIfExistsLocked(class uint, label string, requireApplicationLabel bool) error {
	obj, err := m.findOneLocked(class, label, requireApplicationLabel)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil
		}
		return err
	}
	if err := m.ctx.DestroyObject(m.session, obj); err != nil {
		return fmt.Errorf("pkcs11: delete %s: %w", label, err)
	}
	return nil
}
