# Container Model

`keyman` should use one application container by default.

## Default Image

The default image should contain:

- the Go API/server binary
- the compiled TypeScript management console as static assets
- PKCS#11 runtime dependencies needed for local/demo mode
- optional SoftHSM tooling for repeatable local tests
- TPM2 runtime dependencies needed for local/demo mode
- optional `swtpm` tooling for repeatable TPM2 tests

The Go server should serve both:

- JSON API routes, for example `/api/keys` and `/api/certificates`
- TPM2 API routes, for example `/api/tpm2/health`, `/api/tpm2/pcrs`, and `/api/tpm2/demo`
- the compiled management console from embedded or packaged static files

The browser opens the token session by submitting the PKCS#11 user PIN to the
Go server. The server keeps that PIN only in process memory and does not require
`PKCS11_PIN` for the default web-console flow.

## Demo Mode

Demo mode can run SoftHSM and `swtpm` inside the same container. Token and TPM state should live in mounted volumes when keys, certificates, or TPM state need to survive container restarts.

Example shape:

```text
keyman
  Go API/server
  TypeScript static UI
  SoftHSM library
  SoftHSM token volume
  swtpm daemon
  TPM2 state volume
```

The default application image initializes a local SoftHSM token labeled
`KEYMAN` with user PIN `1234`; the management console still asks for the PIN
before opening the token session. The same image starts `swtpm` in TPM2 mode and
configures `TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321` for the TPM2 tab.

```sh
make demo
```

Then open `http://127.0.0.1:8080`. Connect the PKCS#11 token with PIN `1234`;
the TPM2 tab is available through the configured TCTI.

The Makefile uses Docker when `docker` is available and falls back to Podman
otherwise. Force a runtime or port when needed:

```sh
CONTAINER_RUNTIME=docker make demo
CONTAINER_RUNTIME=podman make demo
PORT=5080 make demo
```

## Hardware Mode

Hardware-backed mode should still use the same application container. The container receives the vendor PKCS#11 module path and any required device/socket mounts. TPM2 mode can target a mounted TPM device, a TPM resource manager device, or an external TCTI endpoint.

Typical configuration:

```text
PKCS11_MODULE_PATH=/usr/lib/vendor/pkcs11.so
PKCS11_TOKEN_LABEL=...
TPM2TOOLS_TCTI=device:/dev/tpmrm0
```

The browser never talks to PKCS#11 directly. It only calls the Go API.

## Optional External Services

External services should be optional examples, not required containers for the base management console.

- OpenBao can be added for separate PKI or transit workflows.
- A database can be added if persistent audit history is needed.
