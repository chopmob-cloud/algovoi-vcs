"""Template addon for the AlgoVoi Verifiable Archive engine.

Copy this package, rename it, and implement one or both of the Protocols the engine declares in
``algovoi-doc-archive`` 0.1.6. Nothing here is imported by the engine automatically — an operator
selects a backend or signer by configuration, so your class only has to satisfy the Protocol.

Both Protocols are ``runtime_checkable``, so ``isinstance(obj, StorageBackend)`` works as a smoke test.
That checks method *names*, not signatures: keep the signatures below exactly.
"""

from __future__ import annotations

__version__ = "0.1.0"


class ExampleStorageBackend:
    """Implements ``algovoi_doc_archive.backend.StorageBackend``.

    Contract notes that change whether the engine can trust your data:

    * ``get`` returns ``None`` for an absent key. Never raise for absence — the engine distinguishes
      "missing" from "damaged", and raising collapses that distinction.
    * ``put`` is idempotent; re-writing an existing key must be safe.
    * ``list_prefix`` returns every key under the prefix. The engine sorts; you do not have to.
    * Do not transform the bytes. The engine stores content-addressed data and verifies digests on
      read, so transparent compression or re-encoding fails verification.
    """

    def __init__(self, root: str) -> None:
        self._root = root

    async def put(self, key: str, data: bytes) -> None:
        raise NotImplementedError

    async def get(self, key: str) -> bytes | None:
        raise NotImplementedError

    async def exists(self, key: str) -> bool:
        raise NotImplementedError

    async def list_prefix(self, prefix: str) -> list[str]:
        raise NotImplementedError


class ExampleSigner:
    """Implements ``algovoi_doc_archive.signer.Signer``.

    This is the shape for custody that must never expose a private key to the engine (HSM, KMS,
    Vault transit).

    Contract notes:

    * ``sign`` is synchronous in 0.1.6 — bridge to your client synchronously.
    * ``public_key`` returns raw public-key bytes, not a PEM wrapper.
    * ``kid`` must be stable across restarts; a per-process value makes written chains unverifiable.
    * ``can_sign`` is a live capability check, not a configuration flag.
    """

    def public_key(self) -> bytes:
        raise NotImplementedError

    def kid(self) -> str:
        raise NotImplementedError

    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError

    def can_sign(self) -> bool:
        raise NotImplementedError
