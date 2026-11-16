# SPDX-License-Identifier: Apache-2.0
"""In-module signer for the AlgoVoi Verifiable Archive.

A ``Signer`` whose private key never enters this process: every signature is produced by a callable
the operator supplies, which is expected to be a vendor SDK talking to an HSM's secure execution
environment (Entrust nShield CodeSafe / PQ Option Pack, Thales Luna T-Series with FALCON firmware, or
any signing service that keeps Falcon-1024 in-module).

This is the only shape that makes the suite's "the vendor never sees your key" claim literally true
for signing. The shipped ``unwrap``-based custody adapters hold the wrapped key and materialise the
raw secret key in this process at sign time (see ``WrappedKeySigner`` in the engine); this signer does
not, because it is never given a secret key at all.

``kid`` defaults to ``sha256(public_key)[:16]``, byte-identical to ``algovoi_doc_archive.signing.kid_for``,
so entries written through this signer chain correctly with entries written by the engine's own
signer for the same key.

Verification is not implicit: a bridge wired to the wrong module returns a valid signature made by the
wrong key, and nothing here can tell. Pass ``verify_fn`` and every signature is checked against
``public_key`` before it is returned, turning a silently unverifiable archive into an exception at the
write that caused it. This package has no dependencies, so the verifier is yours to supply.

No secret is stored, logged, or formatted into a ``repr``. This class holds the public key and two or
three callables.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable

__version__ = "0.1.0"

#: Falcon-1024 public key length, from ``algovoi_doc_archive.signing.PUBLIC_KEY_BYTES``.
FALCON_1024_PUBLIC_KEY_BYTES = 1793

#: Vendor error text can name a key, a partition or a signed URL. Redact the credential-bearing shapes.
_CREDENTIAL = re.compile(
    r"(?i)\b(sig|sv|se|sp|spr|sk|sr|st|accountkey|sharedaccesssignature)\s*=\s*[^&;\s'\"]+"
)


def _redact(text: object) -> str:
    return _CREDENTIAL.sub(lambda m: f"{m.group(1)}=<redacted>", str(text))


class SignerError(RuntimeError):
    """The vendor signing function refused, failed, or returned something unusable."""


def _kid_for(public_key: bytes) -> str:
    """Identical derivation to ``algovoi_doc_archive.signing.kid_for``."""
    return hashlib.sha256(public_key).hexdigest()[:16]


class InModuleSigner:
    """``Signer`` that delegates signing to a vendor in-module callable.

    Parameters
    ----------
    public_key:
        Raw Falcon-1024 public key bytes (not PEM). 1793 bytes unless ``public_key_bytes`` is set to
        something else for a different profile.
    sign_fn:
        ``Callable[[bytes], bytes]``. Receives the exact bytes the engine wants signed (JCS-canonical
        payload bytes) and returns raw Falcon-1024 signature bytes. It is the operator's bridge to the
        module and is the only place a private key exists.
    kid:
        Optional key identifier to pin. Must stay stable across restarts or previously written chains
        become unverifiable; defaults to the engine's derivation from the public key.
    probe:
        Optional ``Callable[[], bool]`` used by :meth:`can_sign` as a live capability check. Without
        one, ``can_sign`` reports whether a signing function was supplied, which is a configuration
        fact rather than a liveness one.
    verify_fn:
        Optional ``Callable[[bytes, bytes], bool]`` — ``(message, signature) -> bool`` — called on every
        signature before it is returned. Supply one closed over this signer's public key to make a
        mis-wired bridge fail at the signing call instead of at examination.
    public_key_bytes:
        Expected public key length, for a profile other than Falcon-1024. ``None`` disables the check.
    """

    def __init__(
        self,
        public_key: bytes,
        sign_fn: Callable[[bytes], bytes],
        *,
        kid: str | None = None,
        probe: Callable[[], bool] | None = None,
        verify_fn: Callable[[bytes, bytes], bool] | None = None,
        public_key_bytes: int | None = FALCON_1024_PUBLIC_KEY_BYTES,
    ) -> None:
        if not isinstance(public_key, (bytes, bytearray)):
            raise TypeError(f"public_key must be bytes, got {type(public_key).__name__}")
        key = bytes(public_key)
        if not key:
            raise ValueError("public_key must not be empty")
        if public_key_bytes is not None and len(key) != public_key_bytes:
            raise ValueError(
                f"public_key must be {public_key_bytes} bytes for this profile, got {len(key)}"
            )
        for name, value in (("sign_fn", sign_fn), ("probe", probe), ("verify_fn", verify_fn)):
            if value is not None and not callable(value):
                raise TypeError(f"{name} must be callable")
        if kid is not None and (not isinstance(kid, str) or not kid):
            raise ValueError("kid must be a non-empty str when supplied")
        self._pk = key
        self._sign_fn = sign_fn
        self._kid = kid or _kid_for(key)
        self._probe = probe
        self._verify_fn = verify_fn

    def public_key(self) -> bytes:
        return self._pk

    def kid(self) -> str:
        return self._kid

    def can_sign(self) -> bool:
        if self._probe is None:
            return True
        try:
            return bool(self._probe())
        except Exception:  # noqa: BLE001 - a probe that raises means "not available now"
            return False

    def sign(self, message: bytes) -> bytes:
        if not isinstance(message, (bytes, bytearray, memoryview)):
            raise TypeError(f"message must be bytes-like, got {type(message).__name__}")
        payload = bytes(message)
        try:
            signature = self._sign_fn(payload)
        except Exception as exc:
            raise SignerError(f"in-module signing failed: {_redact(exc)}") from exc
        if not isinstance(signature, (bytes, bytearray, memoryview)):
            raise SignerError(
                f"in-module signer returned {type(signature).__name__}, expected bytes"
            )
        raw = bytes(signature)
        if not raw:
            raise SignerError("in-module signer returned an empty signature")
        if self._verify_fn is not None:
            try:
                valid = bool(self._verify_fn(payload, raw))
            except Exception as exc:
                raise SignerError(f"signature self-check failed: {_redact(exc)}") from exc
            if not valid:
                raise SignerError(
                    "in-module signer returned a signature that does not verify under public_key "
                    "(wrong key, wrong module, or a truncated message)"
                )
        return raw

    def __repr__(self) -> str:
        return (
            f"InModuleSigner(kid={self._kid!r}, probe={'yes' if self._probe else 'no'}, "
            f"verify={'yes' if self._verify_fn else 'no'})"
        )
