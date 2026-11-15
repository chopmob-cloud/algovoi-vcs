# Architecture

## Shape of the estate

The suite is one encrypted deliverable, `bundle.algv`, that expands into 25 post-quantum-signed
components. Your Falcon-1024-signed licence is both the decryption key and the runtime licence, so
there is no activation server and no phone-home; the estate installs and runs air-gapped.

| Layer | Components |
|---|---|
| Core | Substrate 2 (Falcon-1024 + ML-DSA-65, ML-KEM-1024, JCS canonicalisation, policy binding), control plane, Retention, Crypto-Agility, Keystone lifecycle evidence |
| Hub | Compliance Command Center: evidence console, one-posture dashboard, IQ/OQ/PQ self-validation pack, clean-box validation gauntlet |
| Records | Records Vault with `.epi` export, Recovery Vault, Archive Auditor, the Verifiable Archive engine, Volume Importer |
| Evidence | Sanctions Monitor, Travel Rule, Retention, Verifiable Audit Log |
| Controls | Compliance Gate: policy-bound ALLOW / REFER / DENY decision engine |
| Sealed delivery | `.acv` containers: ML-KEM-1024 to one recipient, opaque-names mode, offline revocation, k-of-n Shamir and console key-loss recovery |

## Data model

The Verifiable Archive engine stores content-addressed, write-once entries in a hash-linked chain. Each
entry binds the content digest, the signer's `kid`, and an RFC-3161 timestamp where one is available.
Integrity is a property of the chain, not of a database row: altering an entry breaks the link and
verification reports a named refusal.

Deletion is a two-step, evidenced operation. A legal or e-discovery hold blocks removal; when a hold is
lifted, a signed erasure tombstone records that the record existed and that its content was
cryptographically shredded. The tombstone remains verifiable after the content is gone.

## Cryptographic choices

| Purpose | Primitive |
|---|---|
| Signing | Falcon-1024, ML-DSA-65 (dual-signature profiles) |
| Key encapsulation / sealing | ML-KEM-1024 |
| Symmetric at-rest encryption | AES-256-GCM |
| Canonicalisation | JCS (RFC 8785) |
| Timestamps | RFC-3161 trusted timestamping, with a signed-chain fallback when air-gapped |

Pinned deliberately: `pqcrypto` is capped below 1.0 because 1.0.0 removed the ML-KEM-1024 and
Falcon-1024 APIs this suite uses, and `cryptography` has a floor of 50.0.0 because earlier versions
carry published advisories.

## Extension points

Two Protocols, both `runtime_checkable`, declared in `algovoi-doc-archive` 0.1.6:

- `algovoi_doc_archive.backend.StorageBackend` — `put`, `get`, `exists`, `list_prefix` (all async).
- `algovoi_doc_archive.signer.Signer` — `public_key`, `kid`, `sign`, `can_sign` (all synchronous).

AlgoVoi ships S3 storage and AWS KMS, PKCS#11/HSM and HashiCorp Vault custody on these contracts. See
[../addons/README.md](../addons/README.md).

## Trust boundaries

- The engine holds no private key when a `Signer` is in use; signing happens inside the custodian.
- Verification requires only the public key and the chain — no AlgoVoi service, no network.
- The Compliance Command Center recomputes every figure from the evidence it holds; it does not accept
  a component's self-reported status.
