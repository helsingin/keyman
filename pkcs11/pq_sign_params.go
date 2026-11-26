package pkcs11

/*
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#pragma pack(push,1)
#endif
// CK_SIGN_ADDITIONAL_CONTEXT from PKCS#11 v3.2. CK_ULONG and CK_HEDGE_TYPE
// are unsigned long, including on Windows (where the ABI uses pack(1)).
typedef struct {
    unsigned long hedgeVariant;
    unsigned char *pContext;
    unsigned long ulContextLen;
} keyman_sign_context;
#ifdef _WIN32
#pragma pack(pop)
#endif

static keyman_sign_context *keyman_new_sign_context(unsigned long mode, const void *data, unsigned long length) {
    keyman_sign_context *p = (keyman_sign_context*)calloc(1, sizeof(*p) + length);
    if (!p) return NULL;
    p->hedgeVariant = mode;
    p->ulContextLen = length;
    if (length) {
        p->pContext = (unsigned char*)(p + 1);
        memcpy(p->pContext, data, length);
    }
    return p;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Both the nested context pointer and its target are C-owned. The Go PKCS#11
// binding copies the outer parameter bytes. Keep the allocation alive through
// the complete Sign/Verify operation and release it on every return path.
func marshalPQSigningOptions(options PQSigningOptions) ([]byte, func(), error) {
	var data unsafe.Pointer
	if len(options.Context) != 0 {
		data = unsafe.Pointer(&options.Context[0])
	}
	p := C.keyman_new_sign_context(C.ulong(options.Mode), data, C.ulong(len(options.Context)))
	if p == nil {
		return nil, nil, fmt.Errorf("pkcs11: allocate signing parameters")
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(C.sizeof_keyman_sign_context)), func() { C.free(unsafe.Pointer(p)) }, nil
}
