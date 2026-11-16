# SPDX-License-Identifier: Apache-2.0
"""Azure Key Vault key custody for the AlgoVoi Verifiable Archive.

Holds the Falcon-1024 signing key wrapped by an Azure Key Vault (or Managed HSM) key. At sign time the
wrapped key is unwrapped **inside the vault**, the signature is produced in this process, and both the
data key and the secret key are best-effort zeroized afterwards. The vault never performs the Falcon
operation; it performs a classical wrap/unwrap, which is why this works with Key Vault today.

Why an envelope rather than a straight wrap
-------------------------------------------
AWS KMS accepts a 2.3 KB plaintext for symmetric ``Encrypt``, so the KMS adapter wraps the Falcon key
directly. Key Vault's asymmetric ``wrapKey`` cannot: RSA-OAEP-256 against a 4096-bit key tops out at
446 bytes, well under the 2305-byte Falcon-1024 secret key. This adapter therefore wraps a random
AES-256 data key with the vault key and encrypts the secret key with that data key (AES-256-GCM,
with the public key bound in as associated data so a wrapped blob cannot be moved to another key).

Blob format (version 1)::

    b"AVKV\\x01" | wdek_len (2 bytes, big-endian) | wrapped_dek | nonce (12 bytes) | ciphertext+tag

Limitation, stated rather than hidden: the AES-GCM ``decrypt`` call returns an immutable ``bytes``
object which Python cannot wipe. That temporary is not bound to a local, and the mutable buffer this
module keeps is zeroized in ``finally``; the immutable copy is released immediately and never
persisted. If your threat model requires the key never to exist in process memory at all, use
``algovoi-doc-archive-inmodule`` instead: it is never given a secret key.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections.abc import Callable
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__version__ = "0.1.0"

MAGIC = b"AVKV\x01"
_DEK_BYTES = 32
_NONCE_BYTES = 12
_TAG_BYTES = 16
_HEADER_BYTES = len(MAGIC) + 2
_AAD_LABEL = b"algovoi-doc-archive/azure-kv/v1\x00"
_PAIR_PROBE = b"algovoi-doc-archive/azure-kv key-pair self-check v1"

#: Falcon-1024 sizes, from ``algovoi_doc_archive.signing``.
FALCON_1024_PUBLIC_KEY_BYTES = 1793
FALCON_1024_SECRET_KEY_BYTES = 2305

DEFAULT_ALGORITHM = "RSA-OAEP-256"

_CREDENTIAL = re.compile(
    r"(?i)\b(sig|sv|se|sp|spr|sk|sr|st|accountkey|sharedaccesssignature)\s*=\s*[^&;\s'\"]+"
)


def _redact(text: object) -> str:
    return _CREDENTIAL.sub(lambda m: f"{m.group(1)}=<redacted>", str(text))


class AzureKeyVaultError(RuntimeError):
    """Wrapping, unwrapping or parsing the custody blob failed."""


def _zeroize(buf: Any) -> None:
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def _response_bytes(response: Any, what: str) -> bytes:
    """Normalise a Key Vault response to bytes.

    The shapes differ by operation and by SDK version: ``wrap_key`` returns ``WrapResult`` carrying
    ``.encrypted_key``, ``unwrap_key`` returns ``UnwrapResult`` carrying ``.key``, and some wrappers
    return bytes directly. Accept all three, refuse anything else rather than guessing.
    """
    if isinstance(response, (bytes, bytearray, memoryview)):
        return bytes(response)
    for attribute in ("encrypted_key", "key", "value"):
        inner = getattr(response, attribute, None)
        if isinstance(inner, (bytes, bytearray, memoryview)):
            return bytes(inner)
    raise AzureKeyVaultError(
        f"key vault returned no usable {what} (got {type(response).__name__} with "
        f"{[a for a in ('encrypted_key', 'key', 'value') if hasattr(response, a)]})"
    )


def _aad(public_key: bytes) -> bytes:
    return _AAD_LABEL + hashlib.sha256(public_key).digest()


@lru_cache(maxsize=8)
def _sdk_algorithm(algorithm: str) -> Any:
    """Return the SDK's ``KeyWrapAlgorithm`` when the SDK is installed, else the given string.

    The SDK decides between a local and a service operation by inspecting the algorithm. Handed a bare
    string it still works but logs a warning and attempts the local path first; handed its own enum it
    goes straight to the vault.
    """
    try:
        from azure.keyvault.keys.crypto import KeyWrapAlgorithm
    except ImportError:  # a non-Azure client, or the SDK is genuinely absent
        return algorithm
    try:
        return KeyWrapAlgorithm(algorithm)
    except ValueError:
        return algorithm


def _falcon_sign(secret_key: bytes, message: bytes) -> bytes:
    from pqcrypto.sign.falcon_1024 import sign as _sign

    return _sign(secret_key, message)


def _pair_matches(secret_key: bytes, public_key: bytes) -> bool:
    """Sign a probe and verify it under ``public_key``.

    A custody blob wrapped from the wrong secret key produces signatures that verify under a different
    key, and nothing downstream can tell until an examiner tries to verify the archive. One Falcon
    signature at wrap time turns that into an error at setup.
    """
    from pqcrypto.sign.falcon_1024 import sign as _sign
    from pqcrypto.sign.falcon_1024 import verify as _verify

    try:
        return bool(_verify(public_key, _PAIR_PROBE, _sign(secret_key, _PAIR_PROBE)))
    except Exception:  # noqa: BLE001 - a probe that cannot run is a refusal, not a pass
        return False


def wrap_secret_key(
    secret_key: bytes,
    public_key: bytes,
    crypto_client: Any,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
    secret_key_bytes: int | None = FALCON_1024_SECRET_KEY_BYTES,
) -> bytes:
    """One-time setup: wrap a raw Falcon-1024 secret key under a Key Vault key.

    Returns the custody blob to store beside ``public_key``. The plaintext key never needs to touch
    disk again; pass the blob to :class:`AzureKeyVaultSigner`. The pair is checked before wrapping: a
    secret key that does not match the public key is refused here rather than discovered at
    examination.
    """
    if not isinstance(secret_key, (bytes, bytearray)):
        raise TypeError(f"secret_key must be bytes, got {type(secret_key).__name__}")
    if secret_key_bytes is not None and len(secret_key) != secret_key_bytes:
        raise ValueError(f"secret_key must be {secret_key_bytes} bytes, got {len(secret_key)}")
    if not isinstance(public_key, (bytes, bytearray)):
        raise TypeError(f"public_key must be bytes, got {type(public_key).__name__}")
    pk = bytes(public_key)
    if not pk:
        raise ValueError("public_key must not be empty")
    if not _pair_matches(bytes(secret_key), pk):
        raise AzureKeyVaultError(
            "the secret key does not sign for this public key: wrapping it would produce an archive "
            "nothing can verify"
        )

    dek = bytearray(secrets.token_bytes(_DEK_BYTES))
    try:
        wrapped = _response_bytes(
            crypto_client.wrap_key(algorithm=_sdk_algorithm(algorithm), key=bytes(dek)), "wrapped key"
        )
        if not wrapped:
            raise AzureKeyVaultError("key vault returned an empty wrapped key")
        if len(wrapped) > 0xFFFF:
            raise AzureKeyVaultError("wrapped key is too large for the blob header")
        nonce = secrets.token_bytes(_NONCE_BYTES)
        ciphertext = AESGCM(bytes(dek)).encrypt(nonce, bytes(secret_key), _aad(pk))
        return MAGIC + len(wrapped).to_bytes(2, "big") + wrapped + nonce + ciphertext
    except AzureKeyVaultError:
        raise
    except Exception as exc:
        raise AzureKeyVaultError(f"key vault wrap failed: {_redact(exc)}") from exc
    finally:
        _zeroize(dek)


def parse_secret_key_blob(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """Split a custody blob into ``(wrapped_dek, nonce, ciphertext)``, refusing anything malformed."""
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError(f"blob must be bytes, got {type(blob).__name__}")
    raw = bytes(blob)
    if len(raw) < _HEADER_BYTES + _NONCE_BYTES + _TAG_BYTES:
        raise AzureKeyVaultError("custody blob is truncated")
    if not raw.startswith(MAGIC):
        raise AzureKeyVaultError("custody blob has an unknown format or version")
    wdek_len = int.from_bytes(raw[len(MAGIC):_HEADER_BYTES], "big")
    if wdek_len == 0:
        raise AzureKeyVaultError("custody blob carries an empty wrapped key")
    end = _HEADER_BYTES + wdek_len
    if len(raw) < end + _NONCE_BYTES + _TAG_BYTES:
        raise AzureKeyVaultError("custody blob declares a wrapped key longer than the blob")
    wrapped = raw[_HEADER_BYTES:end]
    nonce = raw[end:end + _NONCE_BYTES]
    ciphertext = raw[end + _NONCE_BYTES:]
    return wrapped, nonce, ciphertext


class AzureKeyVaultSigner:
    """``Signer`` whose Falcon-1024 key is unwrapped by Azure Key Vault at sign time.

    ``kid`` defaults to ``sha256(public_key)[:16]`` — byte-identical to
    ``algovoi_doc_archive.signing.kid_for``, so chains written through this signer match chains
    written by the engine for the same key.
    """

    def __init__(
        self,
        public_key: bytes,
        wrapped_secret_key: bytes,
        *,
        crypto_client: Any,
        kid: str | None = None,
        algorithm: str = DEFAULT_ALGORITHM,
        sign_fn: Callable[[bytes, bytes], bytes] | None = None,
        probe: Callable[[], bool] | None = None,
        probe_ttl: float = 60.0,
        public_key_bytes: int | None = FALCON_1024_PUBLIC_KEY_BYTES,
        secret_key_bytes: int | None = FALCON_1024_SECRET_KEY_BYTES,
    ) -> None:
        if not isinstance(public_key, (bytes, bytearray)):
            raise TypeError(f"public_key must be bytes, got {type(public_key).__name__}")
        pk = bytes(public_key)
        if not pk:
            raise ValueError("public_key must not be empty")
        if public_key_bytes is not None and len(pk) != public_key_bytes:
            raise ValueError(f"public_key must be {public_key_bytes} bytes, got {len(pk)}")
        if not isinstance(wrapped_secret_key, (bytes, bytearray)):
            raise TypeError("wrapped_secret_key must be bytes")
        if kid is not None and (not isinstance(kid, str) or not kid):
            raise ValueError("kid must be a non-empty str when supplied")
        if sign_fn is not None and not callable(sign_fn):
            raise TypeError("sign_fn must be callable")
        if probe is not None and not callable(probe):
            raise TypeError("probe must be callable when supplied")
        if probe_ttl < 0:
            raise ValueError("probe_ttl must be zero or positive")

        # Fail at construction, not mid-chain: a malformed blob must not become a half-written entry.
        parse_secret_key_blob(wrapped_secret_key)

        self._pk = pk
        self._wrapped = bytes(wrapped_secret_key)
        self._client = crypto_client
        self._algorithm = algorithm
        self._kid = kid or hashlib.sha256(pk).hexdigest()[:16]
        self._sign_fn = sign_fn or _falcon_sign
        self._probe = probe
        self._probe_ttl = float(probe_ttl)
        self._probe_at = 0.0
        self._probe_ok: bool | None = None
        self._secret_key_bytes = secret_key_bytes
        self._aad = _aad(pk)

    def public_key(self) -> bytes:
        return self._pk

    def kid(self) -> str:
        return self._kid

    def can_sign(self) -> bool:
        """Live capability check, answered by a real operation against the vault.

        ``CryptographyClient`` exposes no metadata call — there is no ``get_key()`` on it — so a
        presence check cannot be written. This wraps a throwaway 32-byte buffer with the key instead:
        the operation the signer actually depends on, refused if the key is disabled, deleted,
        unreachable, or missing its wrap permission. The result is cached for ``probe_ttl`` seconds so
        a readiness probe does not become a load source.

        Pass ``probe`` to use your own liveness signal instead; a custom probe is called on every
        ``can_sign()`` and is not cached, because it owns its own cost model. The built-in check is an
        ordinary vault operation, so it appears in the vault's audit log and counts against its rate
        limits once per ``probe_ttl`` second — that is the price of answering with an operation instead
        of a metadata read.
        """
        if self._probe is not None:
            try:
                return bool(self._probe())
            except Exception:  # noqa: BLE001 - an unavailable vault is "cannot sign now"
                return False
        now = time.monotonic()
        if self._probe_ok is not None and (now - self._probe_at) < self._probe_ttl:
            return self._probe_ok
        try:
            self._client.wrap_key(
                algorithm=_sdk_algorithm(self._algorithm), key=secrets.token_bytes(32)
            )
            ok = True
        except Exception:  # noqa: BLE001 - any refusal is "cannot sign now"
            ok = False
        self._probe_ok, self._probe_at = ok, now
        return ok

    def _unwrap(self) -> bytearray:
        wrapped, nonce, ciphertext = parse_secret_key_blob(self._wrapped)
        try:
            response = self._client.unwrap_key(
                algorithm=_sdk_algorithm(self._algorithm), encrypted_key=wrapped
            )
        except Exception as exc:
            raise AzureKeyVaultError(f"key vault unwrap failed: {_redact(exc)}") from exc
        dek = bytearray(_response_bytes(response, "unwrapped data key"))
        if len(dek) != _DEK_BYTES:
            _zeroize(dek)
            raise AzureKeyVaultError(f"unwrapped data key must be {_DEK_BYTES} bytes, got {len(dek)}")
        try:
            # The decrypt result is an immutable temporary: copy straight into the mutable buffer we
            # can wipe, and never bind the immutable copy to a local that an exception would retain.
            secret = bytearray(AESGCM(bytes(dek)).decrypt(nonce, ciphertext, self._aad))
        except Exception as exc:
            raise AzureKeyVaultError(f"custody blob failed authentication: {_redact(exc)}") from exc
        finally:
            _zeroize(dek)
        if self._secret_key_bytes is not None and len(secret) != self._secret_key_bytes:
            _zeroize(secret)
            raise AzureKeyVaultError(
                f"unwrapped secret key must be {self._secret_key_bytes} bytes, got {len(secret)}"
            )
        return secret

    def sign(self, message: bytes) -> bytes:
        if not isinstance(message, (bytes, bytearray, memoryview)):
            raise TypeError(f"message must be bytes-like, got {type(message).__name__}")
        secret = self._unwrap()
        try:
            try:
                signature = self._sign_fn(bytes(secret), bytes(message))
            except Exception as exc:
                raise AzureKeyVaultError(f"signing failed after unwrap: {_redact(exc)}") from exc
            if not isinstance(signature, (bytes, bytearray, memoryview)):
                raise AzureKeyVaultError(
                    f"signer returned {type(signature).__name__}, expected bytes"
                )
            raw = bytes(signature)
            if not raw:
                raise AzureKeyVaultError("signer returned an empty signature")
            return raw
        finally:
            _zeroize(secret)

    def __repr__(self) -> str:
        return f"AzureKeyVaultSigner(kid={self._kid!r}, algorithm={self._algorithm!r})"
