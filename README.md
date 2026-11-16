# AlgoVoi VCS — documentation and addons

Documentation and extension points for the **AlgoVoi Verifiable Compliance Suite** — the verifiable
long-term data estate for regulated sectors: health, insurance, defence, and any records that must stay
provably intact and confidential for decades.

This repository holds the public documentation source and the addon interfaces. It does **not** contain
the commercial engine, the encrypted deliverable, or any key material. See [Scope](#scope).

- **Product documentation:** <https://docs.algovoi.co.uk/verifiable-compliance-suite>
- **Suite store:** <https://api.algovoi.co.uk/suite-store>

## What it is

The Verifiable Compliance Suite is a single encrypted deliverable. Your Falcon-1024-signed licence is
both the decryption key and the runtime licence, so the whole estate installs and runs fully offline,
air-gap capable, with no PyPI and no phone-home.

Documents are preserved write-once in a tamper-evident, content-addressed archive: encrypted at rest,
RFC-3161 timestamped, and offline-verifiable with no vendor in the loop. Post-quantum signing
(Falcon-1024 and ML-DSA-65) keeps the evidence verifiable as cryptography evolves. Records are removed
the compliant way: a legal hold blocks deletion, then a signed erasure tombstone leaves proof the record
existed while the content is irrecoverable. The Compliance Command Center re-verifies every signed chain
offline and shows one proven posture, where every figure is recomputed rather than asserted.

| Property | What it means in practice |
|---|---|
| One licence, 25 components | Substrate 2 core, Compliance Command Center and control plane, Records Vault, Recovery Vault, Archive Auditor, the doc-archive engine with HSM/KMS/Vault/S3 custody, Compliance Gate, Retention, Sanctions Monitor, Travel Rule, Verifiable Audit Log. One key runs them all. |
| Post-quantum by default | Falcon-1024 and ML-DSA-65 signatures over ML-KEM-1024-sealed records. Evidence signed today stays verifiable after the migration to post-quantum cryptography. |
| Long-term preservation | Write-once, tamper-evident, content-addressed archive; RFC-3161 trusted timestamps; legal and e-discovery holds; signed erasure tombstones. |
| One proven posture | The Compliance Command Center ingests each product's signed evidence, re-verifies every chain offline, and recomputes every figure on the dashboard. |
| Bring your own keys | Hold the Falcon-1024 signing and ML-KEM keys in your own HSM, AWS KMS, HashiCorp Vault, or PKCS#11. |
| Fail-closed archive | A truncated, re-ordered or malformed chain is refused rather than silently accepted; a damaged store reports a verification failure instead of crashing. |

## What is inside

| Layer | Components |
|---|---|
| Core | Substrate 2 (Falcon-1024 + ML-DSA-65, ML-KEM-1024, JCS canonicalisation, policy binding), control plane, Retention, Crypto-Agility, Keystone lifecycle evidence |
| Hub | Compliance Command Center: evidence console and one-posture dashboard, IQ/OQ/PQ self-validation pack, clean-box validation gauntlet |
| Records | Records Vault with `.epi` export, Recovery Vault, Archive Auditor, the Verifiable Archive engine with S3/KMS/PKCS#11/Vault custody, Volume Importer |
| Evidence | Sanctions Monitor, Travel Rule, Retention, Verifiable Audit Log |
| Controls | Compliance Gate: policy-bound ALLOW / REFER / DENY decision engine |
| Sealed delivery | Sealed encrypted containers (`.acv`): ML-KEM-1024 to one recipient, opaque-names mode, offline revocation, k-of-n Shamir and console key-loss recovery |

## Regulatory coverage

The evidence chains directly support the documentary requirements below. Your counsel certifies
compliance; the suite provides the tamper-evident, independently verifiable evidence that certification
rests on.

| Framework | Provision | Evidence the suite provides |
|---|---|---|
| HIPAA | §164.312(b) audit controls | Signed tamper-evident read-access log: principal, record, granted or denied, reason; exportable for SIEM and GRC |
| HIPAA | §164.312(c)(1) integrity | Write-once content-addressed archive; Falcon-1024-signed chain breaks on any alteration |
| GDPR | Art 17 right to erasure | Signed erasure tombstones: content crypto-shredded, a signed proof the record existed survives |
| GDPR | Art 5(1)(f) integrity and confidentiality | ML-KEM-1024-sealed records at rest; offline-verifiable chain integrity |
| eIDAS | Qualified timestamps | RFC-3161 tokens from an independent TSA; air-gap record falls back to a signed chain with no external call |
| 21 CFR Part 11 | §11.10(a) validation documentation | IQ/OQ/PQ self-validation pack generated on installation |

Full detail: [docs.algovoi.co.uk/verifiable-compliance-suite](https://docs.algovoi.co.uk/verifiable-compliance-suite)

## Install, in short

The suite is a one-time purchase on a perpetual licence, self-serve from the
[suite store](https://api.algovoi.co.uk/suite-store). The flow is **pay, download, key**:

```bash
# 1) prerequisites — pinned deliberately: pqcrypto 1.0.0 removed the ML-KEM-1024 and
#    Falcon-1024 APIs this suite uses, so an unbounded install silently breaks
#    post-quantum signing and at-rest encryption at first use.
python -m pip install "cryptography>=50.0.0" "pqcrypto>=0.4.0,<1.0" \
    "rfc8785>=0.1.4" "shamir-mnemonic>=0.3.0" "fastapi>=0.110,<1.0" "uvicorn>=0.29,<1.0" httpx

# 2) save your licence key to licence.key, then extract + install (offline, verified)
python algovoi_unbundle.py --license @licence.key --out ./algovoi --install bundle.algv

# 3) run the estate — your bundle licence runs them all
export ALGOVOI_LICENSE_KEY="$(cat licence.key)"
algovoi-substrate2-controlplane                                       # control panel + policy bridge
uvicorn algovoi_command_center.app:create_app --factory --port 8200   # Compliance Command Center
```

The extractor verifies your licence against the bundle before writing a single file, and verifies each
wheel as it unpacks. See [docs/install.md](docs/install.md) for the full sequence.

## Addons

The engine exposes two protocols you can implement in your own wheel: a **storage backend** and a
**signer**. AlgoVoi ships first-party providers for S3 (storage) and AWS KMS, PKCS#11/HSM and HashiCorp
Vault (key custody) on the same contracts.

Four more addons are free and in this repository under Apache-2.0:

| Addon | Kind | What it adds |
|---|---|---|
| [`algovoi-doc-archive-mirror`](addons/algovoi-doc-archive-mirror) | storage | Fan-out to N backends with a quorum, plus divergence detection across copies |
| [`algovoi-doc-archive-azure-blob`](addons/algovoi-doc-archive-azure-blob) | storage | Azure Blob Storage, Azure Stack Hub and Azurite |
| [`algovoi-doc-archive-inmodule`](addons/algovoi-doc-archive-inmodule) | signer | Signing delegated to an HSM or signing service; no key material in the engine process |
| [`algovoi-doc-archive-azure-kv`](addons/algovoi-doc-archive-azure-kv) | custody | Falcon-1024 key envelope-wrapped by Azure Key Vault or Managed HSM |

Every addon here is scored by [`addons/conformance`](addons/conformance), which asserts the contract
semantics the engine relies on — including that a produced signature actually verifies under the public
key.

→ [addons/README.md](addons/README.md) · [template](addons/template) · [manifest schema](addons/schema/addon.json) · [index](addons/index.json)

## Scope

**In this repository:** documentation source, the addon contract and schema, and four first-party addon
implementations with their conformance suite and CI. Code here is Apache-2.0.

**Not in this repository, by design:** the engine and component source, the encrypted `.algv`
deliverable, the extractor's trust material, licence-signing keys, and any key-custody material. The
suite is a commercial product delivered through the store; this repository documents it and lets you
extend it. Nothing here grants a licence to run the suite.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
