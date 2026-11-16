# algovoi-doc-archive-inmodule

A `Signer` that never holds a private key. Signing is delegated to a callable you supply, which is
expected to be a vendor SDK talking to an HSM's secure execution environment — Entrust nShield with the
Post-Quantum Option Pack, Thales Luna T-Series with FALCON firmware, or an internal signing service.

This is the only shape that makes the suite's "the vendor never sees your key" claim literally true for
signing. The shipped `unwrap`-based custody adapters (KMS, Vault, PKCS#11) hold the wrapped key and
materialise the raw Falcon key in the engine process at sign time; this signer is never given a secret
key at all.

## Install

```bash
pip install ./addons/algovoi-doc-archive-inmodule
```

No third-party dependencies. The vendor SDK belongs to your adapter, not to this package.

## Use

```python
from algovoi_doc_archive import Archive
from algovoi_doc_archive_inmodule import InModuleSigner

# Your bridge to the module. One function, message bytes in, raw Falcon-1024 signature bytes out.
def module_sign(message: bytes) -> bytes:
    return seeworld.sign(handle=HANDLE, mechanism="FALCON-1024", data=message)

signer = InModuleSigner(
    public_key,                 # raw 1793-byte Falcon-1024 public key, not PEM
    module_sign,
    kid="hsm-eu-1",             # pin it: a kid that changes per process breaks old chains
    probe=lambda: seeworld.health() == "ok",   # live capability check
    # Verify every signature before returning it. One extra call turns a bridge wired to the wrong
    # module into an exception at the write, instead of an archive nobody can verify at examination.
    verify_fn=lambda message, signature: falcon_verify(public_key, message, signature),
)

archive = Archive(signer=signer, storage=..., encryptor=...)
```

## Contract

- `sign` is synchronous, as the engine's 0.1.6 `Signer` requires. Bridge to your client synchronously.
- `kid` defaults to `sha256(public_key)[:16]`, byte-identical to `algovoi_doc_archive.signing.kid_for`,
  so chains written through this signer verify alongside chains written by the engine for the same key.
  Pass an explicit `kid` if your estate already published one; never let it vary per process.
- `can_sign` is a live check when you pass `probe`; a probe that raises means "cannot sign now". Without
  a probe it reports configuration (a signing function exists), which is weaker — say so in your runbook.
- `sign` refuses a non-bytes message, a non-bytes return, and an empty signature. Vendor exceptions are
  re-raised as `SignerError` with the original as `__cause__`, so a support engineer sees the HSM's own
  message rather than a Falcon failure further downstream.

## What this does not do

It does not verify the signature it returns **unless you pass `verify_fn`**. A bridge wired to the wrong
module returns a perfectly valid signature made by the wrong key, and this class cannot tell: the
signature is bytes and the public key is a different public key. Pass a verifier closed over
`public_key` and a mismatch fails at the signing call rather than at examination, when the archive is
already sealed. The verifier is yours to supply because this package has no dependencies — Falcon-1024
verification in `pqcrypto` is one call.

It also does not know whether your module signed with the key matching the public key you passed, which
is the same problem one layer down: pin the public key from the module's key inventory, not from a file
that could be swapped.

## Tests

```bash
python -m pytest addons/algovoi-doc-archive-inmodule addons/conformance -q
```

The conformance suite signs with a real Falcon-1024 key through this class and verifies the result with
`pqcrypto`.
