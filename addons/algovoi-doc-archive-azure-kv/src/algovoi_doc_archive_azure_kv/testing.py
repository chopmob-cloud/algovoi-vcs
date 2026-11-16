# SPDX-License-Identifier: Apache-2.0
"""Test double for Azure Key Vault wrap/unwrap.

Not for production use. ``LocalRsaCryptoClient`` performs real RSA-OAEP-256 wrap and unwrap with a
locally generated key, so the envelope format, the associated-data binding and the zeroize path are
exercised for real without an Azure subscription. It is the same shape as ``CryptographyClient``:
``wrap_key(algorithm=..., key=...)`` and ``unwrap_key(algorithm=..., encrypted_key=...)``, both
returning an object carrying the bytes on ``.key``.
"""
from __future__ import annotations

import warnings

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class _Wrapped:
    def __init__(self, key: bytes) -> None:
        self.key = key


class LocalRsaCryptoClient:
    """Real RSA-OAEP wrap/unwrap, no network.

    A test double: the KEK is generated in this process and exists nowhere else. Using it in
    production gives custody that protects against nothing, so it warns on construction.
    """

    def __init__(self, key_size: int = 2048) -> None:
        warnings.warn(
            "LocalRsaCryptoClient is a test double: the KEK lives in this process, not in a vault",
            UserWarning,
            stacklevel=2,
        )
        self._private = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self._public = self._private.public_key()
        self._padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
        self.calls: list[str] = []

    def wrap_key(self, *, algorithm: str, key: bytes) -> _Wrapped:
        self.calls.append(f"wrap:{algorithm}")
        return _Wrapped(self._public.encrypt(bytes(key), self._padding))

    def unwrap_key(self, *, algorithm: str, encrypted_key: bytes) -> _Wrapped:
        self.calls.append(f"unwrap:{algorithm}")
        return _Wrapped(self._private.decrypt(bytes(encrypted_key), self._padding))

    def get_key(self) -> None:
        self.calls.append("get_key")
