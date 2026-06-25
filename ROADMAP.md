# Roadmap

## Near-Term

- Add OpenSSL interoperability examples for inspecting generated certificates and validating PKCS#11-backed TLS material.
- Add CSR generation with an HSM-backed private key.
- Add certificate import examples for externally issued certificates.
- Add optional JSON output to the `keyman` CLI for automation.
- Add a TypeScript management console served by the Go API from the same container.
- Add explicit vendor compatibility notes for SoftHSM and real HSMs as testing broadens.

## TPM2 Track

TPM2 support should be implemented as a separate backend rather than being hidden inside the PKCS#11 package.

Planned scope:

- discover TPM2 devices or simulator endpoints
- create or load persistent signing keys
- generate CSRs using TPM-resident private keys
- sign digests through TPM2 commands
- document provisioning flows and handle ownership assumptions

Out of scope for the initial TPM2 track:

- platform attestation policy
- device identity lifecycle beyond local examples
- vendor-specific fleet provisioning

## Stability Criteria

Before tagging a stable release:

- keep private key material non-extractable by default
- keep integration tests repeatable with SoftHSM
- add at least one OpenSSL interop workflow
- document key template choices and portability notes
- expand error handling around vendor-specific PKCS#11 behavior
