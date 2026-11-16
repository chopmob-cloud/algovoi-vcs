# Addon conformance suite

One set of contract tests that every addon in this repository is scored against, so a provider is proven
against the semantics the engine relies on rather than against its own idea of them.

```bash
python -m pytest addons/conformance -q
```

## What it asserts

Storage (`StorageBackend`):

- bytes round-trip exactly, including NUL, CRLF, `0x1A` and high-bit octets;
- a missing key is `None`, never an exception;
- `put` is idempotent;
- `exists` agrees with `get`;
- `list_prefix` returns every key under the prefix and nothing outside it;
- an empty key is refused.

Signer (`Signer`):

- `public_key` returns the raw bytes it was built with;
- `kid` is stable across instances and derives as `sha256(public_key)[:16]`;
- `sign` produces a Falcon-1024 signature that verifies under that public key, and does not verify over a
  different message;
- `sign` refuses a non-bytes message;
- `can_sign` returns a bool.

## Scoring your own addon

Add a factory to `STORAGE_FACTORIES` or `SIGNER_FACTORIES` in
[`tests/test_contract.py`](tests/test_contract.py). A storage factory takes no arguments and returns a
backend; a signer factory takes `(public_key, secret_key)` and returns a signer. Then run the suite — your
provider is exercised by every test in that class.

The suite needs `pqcrypto` and `cryptography`: real signatures, not mocks. A signed assertion against a
fake primitive proves nothing about the deployment.
