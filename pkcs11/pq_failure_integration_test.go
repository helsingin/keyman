//go:build integration && linux

package pkcs11

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	keyring "github.com/helsingin/keyman"
	p11 "github.com/miekg/pkcs11"
)

// A forwarding module injects failures at the PKCS#11 boundary. All other
// operations use the real disposable token, including object persistence.
func TestPQTokenFailures(t *testing.T) {
	module := os.Getenv("PKCS11_MODULE_PATH")
	if module == "" {
		t.Skip("requires disposable token")
	}
	dir := t.TempDir()
	headers, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/miekg/pkcs11").Output()
	if err != nil {
		t.Fatal(err)
	}
	source, shim := filepath.Join(dir, "fault.c"), filepath.Join(dir, "fault.so")
	if err := os.WriteFile(source, []byte(pqFaultModule), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-shared", "-fPIC", "-I"+strings.TrimSpace(string(headers)), source, "-ldl", "-o", shim).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	t.Setenv("KEYMAN_FAULT_MODULE", module)
	t.Setenv("KEYMAN_FAULT", "")
	m, err := New(Config{ModulePath: shim, TokenLabel: os.Getenv("PKCS11_TOKEN_LABEL"), PIN: os.Getenv("PKCS11_PIN")})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx := t.Context()
	for _, typ := range []keyring.KeyType{keyring.KeyTypeMLDSA65, keyring.KeyTypeMLDSA87, keyring.KeyTypeSLHDSASHA2192s, keyring.KeyTypeSLHDSASHA2256s} {
		t.Run(string(typ), func(t *testing.T) {
			id := "fault-" + string(typ)
			absent := func(version int) {
				t.Helper()
				for _, obj := range []struct {
					class uint
					label string
				}{{p11.CKO_PRIVATE_KEY, privateKeyManel(id, version)}, {p11.CKO_PUBLIC_KEY, publicKeyManel(id, version)}} {
					if _, err := m.findOneLocked(obj.class, obj.label, false); !errors.Is(err, keyring.ErrKeyNotFound) {
						t.Fatalf("partial key %s: %v", obj.label, err)
					}
				}
			}
			t.Setenv("KEYMAN_FAULT", "mechanism")
			caps, err := m.PQCapabilities(ctx, typ)
			if err != nil || caps.Generate || caps.Sign || caps.Verify {
				t.Fatalf("unsupported capabilities %+v: %v", caps, err)
			}
			if _, err := m.CreateKey(ctx, typ, id); !errors.Is(err, ErrUnsupportedPQOperation) {
				t.Fatalf("unsupported generation: %v", err)
			}
			absent(1)
			t.Setenv("KEYMAN_FAULT", "create")
			if _, err := m.CreateKey(ctx, typ, id); err == nil {
				t.Fatal("accepted failed metadata persistence")
			}
			absent(1)
			if _, err := m.GetKey(ctx, id); !errors.Is(err, keyring.ErrKeyNotFound) {
				t.Fatalf("partial metadata: %v", err)
			}
			t.Setenv("KEYMAN_FAULT", "")
			if _, err := m.CreateKey(ctx, typ, id); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := m.DeleteKey(ctx, id); err != nil {
					t.Error(err)
				}
			}()
			t.Setenv("KEYMAN_FAULT", "create")
			if _, err := m.RotateKey(ctx, id); err == nil {
				t.Fatal("accepted failed rotation metadata")
			}
			absent(2)
			key, err := m.GetKey(ctx, id)
			if err != nil || key.Version != 1 {
				t.Fatalf("lost original metadata: %+v %v", key, err)
			}
			t.Setenv("KEYMAN_FAULT", "retire")
			if _, err := m.RotateKey(ctx, id); err == nil {
				t.Fatal("accepted failed metadata retirement")
			}
			absent(2)
			key, err = m.GetKey(ctx, id)
			if err != nil || key.Version != 1 {
				t.Fatalf("metadata rollback: %+v %v", key, err)
			}
			t.Setenv("KEYMAN_FAULT", "context")
			opts := PQSigningOptions{Context: []byte("must not disappear"), Mode: PQDeterministic}
			if sig, err := m.Sign(ctx, id, []byte("message"), opts); !errors.Is(err, ErrUnsupportedPQOperation) || sig != nil {
				t.Fatalf("context fallback: %v", err)
			}
			if err := m.Verify(ctx, id, nil, nil, opts); !errors.Is(err, ErrUnsupportedPQOperation) {
				t.Fatalf("verify context fallback: %v", err)
			}
			t.Setenv("KEYMAN_FAULT", "")
			sig, err := m.Sign(ctx, id, []byte("still usable"), opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Verify(ctx, id, []byte("still usable"), sig, opts); err != nil {
				t.Fatal(err)
			}
			if key, err := m.RotateKey(ctx, id); err != nil || key.Version != 2 {
				t.Fatalf("retry rotation: %+v %v", key, err)
			}
		})
	}
}

const pqFaultModule = `
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType,name) returnType name
#define CK_DECLARE_FUNCTION(returnType,name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType,name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType,name) returnType (* name)
#define NULL_PTR 0
#include "pkcs11.h"
static CK_FUNCTION_LIST_PTR real;
static CK_FUNCTION_LIST table;
static int fault(const char *s) { const char *v=getenv("KEYMAN_FAULT"); return v && !strcmp(v,s); }
static CK_RV info(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR out) {
 if (fault("mechanism") && (mechanism==0x1c || mechanism==0x1d || mechanism==0x2d || mechanism==0x2e)) return CKR_MECHANISM_INVALID;
 return real->C_GetMechanismInfo(slot,mechanism,out);
}
static CK_RV create(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attrs, CK_ULONG n, CK_OBJECT_HANDLE_PTR out) {
 for (CK_ULONG i=0;i<n;i++) if (fault("create") && attrs[i].type==CKA_CLASS && *(CK_OBJECT_CLASS *)attrs[i].pValue==CKO_DATA) return CKR_DEVICE_MEMORY;
 return real->C_CreateObject(session,attrs,n,out);
}
static CK_RV retire(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj) {
 CK_OBJECT_CLASS cls=0; CK_ATTRIBUTE a={CKA_CLASS,&cls,sizeof(cls)};
 if (fault("retire") && real->C_GetAttributeValue(session,obj,&a,1)==CKR_OK && cls==CKO_DATA) {
  char data[1024]={0}; CK_ATTRIBUTE v={CKA_VALUE,data,sizeof(data)-1};
  if (real->C_GetAttributeValue(session,obj,&v,1)==CKR_OK && strstr(data,"\"version\":1")) return CKR_DEVICE_ERROR;
 }
 return real->C_DestroyObject(session,obj);
}
static CK_RV sign(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
 if (fault("context") && mechanism->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
 return real->C_SignInit(session,mechanism,key);
}
static CK_RV verify(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
 if (fault("context") && mechanism->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
 return real->C_VerifyInit(session,mechanism,key);
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
 if (!real) {
  void *module=dlopen(getenv("KEYMAN_FAULT_MODULE"),RTLD_NOW|RTLD_LOCAL);
  if (!module) return CKR_GENERAL_ERROR;
  CK_C_GetFunctionList get=(CK_C_GetFunctionList)dlsym(module,"C_GetFunctionList");
  if (!get || get(&real)!=CKR_OK) return CKR_GENERAL_ERROR;
  table=*real;
  table.C_GetMechanismInfo=info; table.C_CreateObject=create;
  table.C_DestroyObject=retire; table.C_SignInit=sign; table.C_VerifyInit=verify;
 }
 *out=&table; return CKR_OK;
}
`
