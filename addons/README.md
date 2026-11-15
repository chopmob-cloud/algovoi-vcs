# Addons

The Verifiable Archive engine (`algovoi-doc-archive`) exposes two extension points as
`runtime_checkable` Protocols. You implement either in your own wheel, with no changes to the engine.

Both interfaces below are transcribed from `algovoi-doc-archive` **0.1.6**. They are the contract as it
ships, not an aspiration — re-read them from the installed package before you build against a later
version.

```python
from algovoi_doc_archive.backend import StorageBackend
from algovoi_doc_archive.signer import Signer
```

## 1. Storage backend

Where archived bytes live. The engine ships a local-filesystem backend; AlgoVoi also ships an
S3/S3-compatible backend on this same contract.

```python
# algovoi_doc_archive/backend.py  (0.1.6)
@runtime_checkable
class StorageBackend(Protocol):
    async def put(self, key: str, data: bytes) -> None: ...
    async def get(self, key: str) -> bytes | None: ...
    async def exists(self, key: str) -> bool: ...
    async def list_prefix(self, prefix: str) -> list[str]: ...
```

Notes that matter for correctness:

- **`get` returns `None` for a missing key, not an exception.** The engine distinguishes "absent" from
  "damaged", and a backend that raises on absence collapses that distinction.
- **`list_prefix` returns keys, ordered or not.** The engine sorts. Return the full set under the prefix.
- **`put` is idempotent.** Re-writing an existing key must be safe.
- **Do not transform bytes.** The engine stores content-addressed data and verifies digests on read; a
  backend that re-encodes, strips or compresses transparently will fail verification.

## 2. Signer

Performs the private-key signing operation **without exposing the key to the engine** — the shape you
need for HSM, KMS or Vault custody.

```python
# algovoi_doc_archive/signer.py  (0.1.6)
@runtime_checkable
class Signer(Protocol):
    """Performs the private-key signing operation without exposing the key to the engine."""

    def public_key(self) -> bytes: ...
    def kid(self) -> str: ...
    def sign(self, message: bytes) -> bytes: ...
    def can_sign(self) -> bool: ...
```

- **`sign` is synchronous in 0.1.6.** A network-backed signer (KMS, Vault transit) either bridges to its
  client synchronously or exposes a synchronous facade.
- **`public_key` returns the raw public key bytes**, not a PEM wrapper.
- **`kid` is the key identifier** the engine records in the chain. It must be stable across restarts;
  a `kid` that changes per process makes previously written chains unverifiable.
- **`can_sign` is a live capability check**, not a configuration flag.

## 3. Key-custody providers (observed shape)

AlgoVoi ships four first-party wheels on these contracts:

| Wheel | Role | Extra dependency |
|---|---|---|
| `algovoi-doc-archive-s3` | Storage backend | `boto3>=1.34` |
| `algovoi-doc-archive-kms` | Key custody (AWS KMS) | `boto3>=1.34` |
| `algovoi-doc-archive-pkcs11` | Key custody (HSM) | `python-pkcs11>=0.7` |
| `algovoi-doc-archive-vault` | Key custody (HashiCorp Vault transit) | `hvac>=2.0` |

The three custody providers share an `unwrap` operation and raise a provider-specific
`<Provider>AdapterError(RuntimeError)` (`KmsAdapterError`, `Pkcs11AdapterError`, `VaultAdapterError`).
Custody is **not** declared as a public Protocol in 0.1.6 — this is the observed shape of the shipped
providers, so treat it as guidance rather than a stable interface. If your custody target fits `Signer`,
implement `Signer`: that is the stable one.

## 4. Packaging an addon

Declare the engine as a normal dependency so the resolver orders the install:

```toml
[project]
name = "yourorg-doc-archive-addon"
requires-python = ">=3.11"
dependencies = ["algovoi-doc-archive>=0.1.6"]
```

Then:

- **Import lazily inside the function, not at module import.** An addon whose module imports `boto3` at
  the top dies with a bare `ModuleNotFoundError` for a user who does not use your provider. Translate it
  into an actionable message naming the extra.
- **Never vendor or shadow `algovoi_doc_archive`.** Install alongside it.
- **Pin nothing the engine owns.** `pqcrypto` and `cryptography` ranges belong to the engine; an addon
  that caps them changes the suite's post-quantum behaviour for every component.
- Cross-check your wheel against the engine's declared floor before publishing; the engine requires
  `pqcrypto>=0.4.0,<1.0` because 1.0.0 removed the ML-KEM-1024 and Falcon-1024 APIs.

See [template/](template) for a copyable skeleton and [schema/addon.json](schema/addon.json) for the
manifest used to describe an addon to the console.

## Licensing

The engine is commercial and licence-gated: constructing its archive object without a valid licence
fails closed by design, and **licences are per package, not per vendor** — one package accepting a
licence says nothing about the next. Whether your own addon carries a licence of its own is your
decision; nothing in this repository grants a right to run the engine.

## Contributing an addon

Open a discussion or a pull request adding a directory under `community/` with your manifest, a README
and a link to your published wheel. We do not vendor third-party code here.
