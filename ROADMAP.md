# Roadmap

## Near-Term

- Add OpenSSL interoperability examples for inspecting generated certificates and validating PKCS#11-backed TLS material.
- Add CSR generation with an HSM-backed private key.
- Add certificate import examples for externally issued certificates.
- Keep central authentication, authorization, certificate administration and
  service auditing in OpenBao. Keyman owns token provisioning and operations.
- Add integration work only for a concrete application requirement, verified
  against the selected OpenBao PKCS#11 plugin and token provider.
- Add explicit vendor compatibility notes for SoftHSM and real HSMs as testing broadens.

## TPM2 Track

This track is deferred until an application needs TPM-backed custody; it does
not authorize a second central key-management service.

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

## Withdrawn milestone release

The v0.6.1 GitHub release and tag were removed on 27 November 2026. Its M1
implementation was reverted locally to the v0.6.0 token implementation while
the shared application roadmap was corrected around OpenBao. The v0.6.0
SLH-DSA support remains. Do not reuse v0.6.1: existing Go module caches may
retain it. The next release, when requested, must use a fresh patch version.
