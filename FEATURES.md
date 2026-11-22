# Features

`keyman` provides PKCS#11-backed key lifecycle operations and TPM2 exercises in Go. The project focuses on concrete secure-key workflows: HSM key generation, non-extractable private keys, key rotation, certificate creation, certificate object storage, TLS signing with an HSM-backed private key, TPM2 PCR inspection, TPM signing, and seal/unseal flows.

| Area | Current Support |
| --- | --- |
| Go API | Backend-neutral `keyring.Manager`, PKCS#11 implementation, CLI, HTTP API, unit tests, integration tests |
| Management console | BlueprintJS TypeScript console for PKCS#11 session login, key inventory, key rotation, certificate issuance, TPM2 status, PCR reads, and lifecycle runs |
| PKI | Self-signed X.509 certificate creation using an HSM-resident private key |
| Certificates | PKCS#11 certificate object storage with subject, issuer, serial, key ID, and DER value attributes |
| Key management | AES-256-GCM, RSA-4096, ECDSA P-256, and ML-DSA-65 key creation with metadata and versioning |
| P-256 agreement | `CreateP256SigningAndAgreementKey` enables signing and ECDH for one token key. `ECDH` returns a 32-byte shared secret. The private key stays inside the token. Rotation preserves the permitted uses. |
| Private key protection | Secret and private key templates use sensitive, non-extractable key attributes |
| HSM integration | SoftHSM-backed PKCS#11 integration test suite using a containerized token |
| PKCS#11 | Token discovery, session login, object lookup, key generation, AES-GCM, RSA/ECDSA/ML-DSA-65 signing, certificate objects |
| Rotation | Old decrypt versions remain available while new encryption uses the latest version |
| TLS | `crypto.Signer` adapter and managed TLS certificate loading for HSM-backed handshakes |
| OpenSSL | Standard X.509 certificate objects and conventional PKCS#11 object templates; command-line interop examples are planned |
| TPM2 | `swtpm` demo mode, TCTI status, TPM-generated random bytes, SHA-256 PCR reads, TPM ECC signing, and seal/unseal exercises |

## End-to-End Flow

The integration test runs this flow against SoftHSM:

1. initialize a PKCS#11 token
2. create a non-extractable AES key
3. encrypt data with version 1
4. rotate the AES key
5. decrypt version 1 ciphertext after rotation
6. encrypt new data with version 2
7. create a non-extractable RSA key
8. sign and verify a digest
9. create and store a self-signed X.509 certificate using the HSM private key
10. load a TLS certificate whose private key is a PKCS#11-backed `crypto.Signer`
11. create and verify a TLS signer signature
12. create an ECDSA key and sign/verify with it

The TPM2 console demo runs this flow against `swtpm` or another configured TCTI:

1. read TPM2 readiness through `tpm2-tools`
2. read SHA-256 PCR values
3. create an owner-hierarchy ECC primary
4. create a TPM-resident ECC signing key
5. sign a payload through the TPM
6. create a keyedhash sealed-data object
7. unseal the secret through the TPM

## Main Files

- `keyring.go`: backend-neutral API
- `pkcs11/manager.go`: token/session lifecycle
- `pkcs11/keys.go`: key generation and rotation
- `pkcs11/aes.go`: AES-GCM encryption with key version metadata
- `pkcs11/sign.go`: RSA/ECDSA/ML-DSA-65 signing plus `crypto.Signer`
- `pkcs11/certificate.go`: certificate creation and PKCS#11 object storage
- `pkcs11/certificates.go`: certificate inventory
- `tpm2/client.go`: TPM2 command adapter
- `cmd/keymand/main.go`: HTTP API and static console server
- `web/src/App.tsx`: management console
- `pkcs11/manager_integration_test.go`: lifecycle integration test
