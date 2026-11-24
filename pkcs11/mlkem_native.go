package pkcs11

/*
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#define open_module(p) LoadLibraryA(p)
#define symbol(m,n) GetProcAddress(m,n)
#define close_module(m) FreeLibrary(m)
#pragma pack(push,1)
#else
#include <dlfcn.h>
#define open_module(p) dlopen(p,RTLD_NOW | RTLD_LOCAL)
#define symbol(m,n) dlsym(m,n)
#define close_module(m) dlclose(m)
#endif

// PKCS #11 v3.2 ABI. Our v2.40 Go binding already owns the logged-in
// session. Only these two newer calls need to go through this bridge.
typedef unsigned long word;
typedef struct { word type; void *value; word size; } attribute;
typedef struct { word type; void *params; word size; } mechanism;
#ifdef _WIN32
#pragma pack(pop)
#endif
typedef word (*enc_fn)(word, mechanism*, word, attribute*, word, unsigned char*, word*, word*);
typedef word (*dec_fn)(word, mechanism*, word, attribute*, word, unsigned char*, word, word*);

static word kem_call(const char *path, int encapsulate, int wrapping, word session, word key,
                     unsigned char *ciphertext, word *length, word *secret) {
    void *module = open_module(path);
    if (!module) return 0x5; // CKR_GENERAL_ERROR
    mechanism mech = {0x17, NULL, 0}; // CKM_ML_KEM
    word object_class = 4, key_type = wrapping ? 0x1f : 0x10; // CKK_AES or CKK_GENERIC_SECRET
    unsigned char yes = 1, no = 0;
    attribute attrs[] = {
        {0, &object_class, sizeof(word)}, {0x100, &key_type, sizeof(word)},
        {1, &no, 1},        // CKA_TOKEN
        {2, &yes, 1},       // CKA_PRIVATE
        {0x103, &yes, 1},   // CKA_SENSITIVE
        {0x162, &no, 1},    // CKA_EXTRACTABLE
        {0x108, wrapping ? &no : &yes, 1}, // CKA_SIGN (confirmation HMAC)
        {0x106, wrapping ? &yes : &no, 1}, // CKA_WRAP
        {0x107, wrapping ? &yes : &no, 1}  // CKA_UNWRAP
    };
    word count = sizeof(attrs) / sizeof(attrs[0]);
    word rv = 0x54; // CKR_FUNCTION_NOT_SUPPORTED
    if (encapsulate) {
        enc_fn fn = (enc_fn)symbol(module, "C_EncapsulateKey");
        if (fn) rv = fn(session, &mech, key, attrs, count, ciphertext, length, secret);
    } else {
        dec_fn fn = (dec_fn)symbol(module, "C_DecapsulateKey");
        if (fn) rv = fn(session, &mech, key, attrs, count, ciphertext, *length, secret);
    }
    close_module(module);
    return rv;
}
*/
import "C"

import (
	"crypto/mlkem"
	"errors"
	"unsafe"

	p11 "github.com/miekg/pkcs11"
)

func (m *Manager) nativeKEMLocked(encapsulate bool, key p11.ObjectHandle, ciphertext []byte) (p11.ObjectHandle, error) {
	return m.kemResultLocked(encapsulate, false, key, ciphertext)
}

func (m *Manager) kemResultLocked(encapsulate, wrapping bool, key p11.ObjectHandle, ciphertext []byte) (p11.ObjectHandle, error) {
	if len(ciphertext) != mlkem.CiphertextSize768 && len(ciphertext) != mlkem.CiphertextSize1024 {
		return 0, errors.New("invalid ML-KEM ciphertext length")
	}
	path := C.CString(m.modulePath)
	defer C.free(unsafe.Pointer(path))
	var mode C.int
	if encapsulate {
		mode = 1
	}
	var secret C.word
	var wrap C.int
	if wrapping {
		wrap = 1
	}
	length := C.word(len(ciphertext))
	rv := C.kem_call(path, mode, wrap, C.word(m.session), C.word(key), (*C.uchar)(&ciphertext[0]), &length, &secret)
	if rv != 0 {
		return 0, p11.Error(rv)
	}
	if int(length) != len(ciphertext) {
		return 0, errors.Join(errors.New("unexpected ML-KEM ciphertext size"), m.ctx.DestroyObject(m.session, p11.ObjectHandle(secret)))
	}
	return p11.ObjectHandle(secret), nil
}
