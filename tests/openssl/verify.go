package interop

/*
#cgo pkg-config: libcrypto
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

// Use EVP directly: OpenSSL 3.5 pkeyutl cannot allocate its one-shot input
// buffer for an empty file, although the algorithms support empty messages.
static int verify_signature(const unsigned char *der, size_t der_len,
                            const unsigned char *message, size_t message_len,
                            const unsigned char *sig, size_t sig_len,
                            const unsigned char *context, size_t context_len,
                            char *error, size_t error_len) {
    ERR_clear_error();
    const unsigned char *cursor = der;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &cursor, der_len);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int result = -1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            (void *)(context_len ? context : (const unsigned char *)""), context_len),
        OSSL_PARAM_construct_end()
    };
    if (!key || !md || cursor != der + der_len)
        goto done;
    if (EVP_DigestVerifyInit_ex(md, NULL, NULL, NULL, NULL, key, params) != 1)
        goto done;
    result = EVP_DigestVerify(md, sig, sig_len,
        message_len ? message : (const unsigned char *)"", message_len);
done:
    if (result < 0)
        ERR_error_string_n(ERR_get_error(), error, error_len);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
    return result;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func verifyOpenSSL(public, message, signature, context []byte) (bool, error) {
	ptr := func(b []byte) *C.uchar { return (*C.uchar)(unsafe.Pointer(unsafe.SliceData(b))) }
	var detail [256]C.char
	result := C.verify_signature(ptr(public), C.size_t(len(public)), ptr(message), C.size_t(len(message)),
		ptr(signature), C.size_t(len(signature)), ptr(context), C.size_t(len(context)), &detail[0], C.size_t(len(detail)))
	if result < 0 {
		return false, fmt.Errorf("%s", C.GoString(&detail[0]))
	}
	return result == 1, nil
}
