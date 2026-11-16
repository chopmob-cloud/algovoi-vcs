# algovoi-doc-archive-azure-kv

Falcon-1024 key custody in Azure Key Vault or Managed HSM. The signing key is held wrapped; at sign time
the data key is unwrapped **inside the vault**, the signature is produced in this process, and both the
data key and the secret key are best-effort zeroized afterwards.

The vault never performs the Falcon operation — it performs a classical wrap/unwrap, which is why this
works with Key Vault today, with no post-quantum support required in the service.

## Why an envelope

AWS KMS accepts a 2.3 KB plaintext for symmetric `Encrypt`, so the KMS adapter wraps the Falcon key
directly. Key Vault's asymmetric `wrapKey` cannot: RSA-OAEP-256 against a 4096-bit key tops out at 446
bytes, well under the 2305-byte Falcon-1024 secret key. This adapter therefore:

1. generates a random AES-256 data key,
2. wraps that data key with your vault key (`RSA-OAEP-256`),
3. encrypts the Falcon key under the data key with AES-256-GCM, binding the public key in as
   associated data so a custody blob cannot be moved to a different key identity.

Blob format (version 1):

```
b"AVKV\x01" | wdek_len (2 bytes, big-endian) | wrapped_dek | nonce (12 bytes) | ciphertext+tag
```

## Install

```bash
pip install './addons/algovoi-doc-archive-azure-kv[azure]'
```

## Use

```python
from algovoi_doc_archive import Archive
from algovoi_doc_archive_azure_kv import AzureKeyVaultSigner, wrap_secret_key

# One-time, offline: wrap the Falcon key under the vault key. Store the blob; destroy the plaintext.
# The pair is checked before wrapping — a key that does not sign for this public key is refused here
# rather than discovered at examination.
blob = wrap_secret_key(secret_key, public_key, crypto_client)
Path("falcon-wrapped.bin").write_bytes(blob)

signer = AzureKeyVaultSigner(
    public_key,
    Path("falcon-wrapped.bin").read_bytes(),
    crypto_client=crypto_client,          # CryptographyClient for the KEK
    kid="kv-eu-1",                        # pin it; defaults to sha256(public_key)[:16]
)
archive = Archive(signer=signer, storage=..., encryptor=...)
```

## Contract and failure modes

- `wrap_secret_key` signs a probe with the secret key and verifies it under the public key before
  wrapping. A mismatched pair is the quietest way to build an archive nothing can verify: every
  signature is valid, under the wrong key. One extra Falcon signature at setup turns that into an error
  at the only moment anyone is watching.
- Construction parses the blob and refuses a truncated, mis-versioned or over-declaring one. Fail at
  construction, not halfway through writing a chain.
- `AzureKeyVaultError` covers a vault failure, a failed GCM authentication (wrong key, wrong public key,
  damaged blob) and a wrong-length unwrapped key. Vault error text is redacted before it is embedded.
- `can_sign` performs a real **wrap round-trip** against the vault: `CryptographyClient` has no
  metadata call, so a presence check is not writable. The result is cached for `probe_ttl` seconds
  (default 60) because the check is an auditable vault operation; pass `probe=` for your own signal,
  which is called every time and is not cached.
- `kid` derives as `sha256(public_key)[:16]`, byte-identical to `algovoi_doc_archive.signing.kid_for`.

## Limitation, stated rather than hidden

AES-GCM `decrypt` returns an immutable `bytes` object, which Python cannot wipe. That temporary is not
bound to a local, and the mutable buffer this module keeps is zeroized in `finally`. Two facts follow,
and both matter for a threat model that says "no key in process memory":

1. The plaintext key exists in this process at sign time. That is inherent to `unwrap`-based custody.
2. `wrap_secret_key` must receive the secret key, so its frame holds it for the duration of the call. A
   traceback that captures frame locals on that path will contain the key — run such hosts with
   local-variable capture disabled, and do not log frame locals from a wrapping failure.

If either is unacceptable, use [`algovoi-doc-archive-inmodule`](../algovoi-doc-archive-inmodule) instead:
it is never given a secret key.

## Tests

```bash
python -m pytest addons/algovoi-doc-archive-azure-kv addons/conformance -q
```

### Integration tests against Lowkey Vault

The unit tests drive a local RSA double, which cannot prove the SDK's response shapes or its challenge
flow. These run against a real Key Vault API surface:

```bash
docker run -d --name lowkey -p 8443:8443 nagyesta/lowkey-vault:7.3.48-ubi10-minimal
pip install 'algovoi-doc-archive-azure-kv[integration]'
LOWKEY_VAULT_URL=https://localhost:8443 \
    python -m pytest addons/algovoi-doc-archive-azure-kv -m integration -q
```

They found a defect the double could not: the current SDK returns `WrapResult.encrypted_key` for a wrap
and `UnwrapResult.key` for an unwrap, and this adapter only understood `.key`. The double now models the
real shapes, so the same slip fails in the portable suite.

Emulator-only concessions are confined to the test file: `connection_verify=False` (self-signed
certificate), `verify_challenge_resource=False` (localhost authority) and a static token credential. No
production path in this addon disables TLS verification.

`algovoi_doc_archive_azure_kv.testing.LocalRsaCryptoClient` performs real RSA-OAEP wrap/unwrap locally, so
the envelope, the associated-data binding and the zeroize path are exercised against real Falcon
signatures without an Azure subscription.
