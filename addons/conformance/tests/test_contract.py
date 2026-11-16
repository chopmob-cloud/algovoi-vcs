# SPDX-License-Identifier: Apache-2.0
"""Conformance suite for the engine's two extension points.

Every addon in this repository is scored against the same contract tests, so a new provider is proven
against the semantics the engine relies on rather than against its own idea of them.

Storage contract (``algovoi_doc_archive.backend.StorageBackend``)
    * bytes round-trip exactly, including NUL, CRLF, 0x1A and high-bit octets
    * a missing key is ``None``, never an exception
    * ``put`` is idempotent
    * ``exists`` agrees with ``get``
    * ``list_prefix`` returns every key under the prefix and nothing outside it
    * an empty key is refused

Signer contract (``algovoi_doc_archive.signer.Signer``)
    * ``public_key`` returns the raw bytes it was built with
    * ``kid`` is stable across instances and derives as ``sha256(public_key)[:16]``
    * ``sign`` produces a Falcon-1024 signature that verifies under that public key
    * ``sign`` refuses a non-bytes message
    * ``can_sign`` returns a bool

To score your own addon, add a factory to ``STORAGE_FACTORIES`` / ``SIGNER_FACTORIES`` and run
``python -m pytest addons/conformance -q``.
"""
from __future__ import annotations

import asyncio
import hashlib
import os

import pytest
from algovoi_doc_archive_azure_blob import AzureBlobBackend
from algovoi_doc_archive_azure_blob.testing import InMemoryContainerClient
from algovoi_doc_archive_azure_kv import AzureKeyVaultSigner, wrap_secret_key
from algovoi_doc_archive_azure_kv.testing import LocalRsaCryptoClient
from algovoi_doc_archive_inmodule import InModuleSigner
from algovoi_doc_archive_mirror import MirrorBackend
from pqcrypto.sign.falcon_1024 import generate_keypair, verify
from pqcrypto.sign.falcon_1024 import sign as falcon_sign


def run(coro):
    return asyncio.run(coro)


class MemoryBackend:
    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}

    async def put(self, key: str, data: bytes) -> None:
        self.data[key] = bytes(data)

    async def get(self, key: str) -> bytes | None:
        return self.data.get(key)

    async def exists(self, key: str) -> bool:
        return key in self.data

    async def list_prefix(self, prefix: str) -> list[str]:
        return [k for k in self.data if k.startswith(prefix)]


STORAGE_FACTORIES = {
    "mirror": lambda: MirrorBackend([MemoryBackend(), MemoryBackend()]),
    "mirror-verify-on-get": lambda: MirrorBackend(
        [MemoryBackend(), MemoryBackend()], verify_on_get=True
    ),
    "azure-blob": lambda: AzureBlobBackend("evidence", container_client=InMemoryContainerClient()),
    "azure-blob-prefixed": lambda: AzureBlobBackend(
        "evidence", prefix="tenant-a", container_client=InMemoryContainerClient()
    ),
    "mirror-of-azure-and-memory": lambda: MirrorBackend(
        [
            AzureBlobBackend("evidence", container_client=InMemoryContainerClient()),
            MemoryBackend(),
        ]
    ),
}

def _azure_kv_signer(pk: bytes, sk: bytes) -> AzureKeyVaultSigner:
    """Wrap and unwrap must use the same vault key, so one client instance spans both halves."""
    client = LocalRsaCryptoClient()
    return AzureKeyVaultSigner(pk, wrap_secret_key(sk, pk, client), crypto_client=client)


SIGNER_FACTORIES = {
    "inmodule": lambda pk, sk: InModuleSigner(
        pk,
        lambda message: falcon_sign(sk, message),
        verify_fn=lambda message, signature: verify(pk, message, signature),
    ),
    "azure-kv": _azure_kv_signer,
}


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.mark.parametrize("name", sorted(STORAGE_FACTORIES))
class TestStorageContract:
    def test_missing_key_is_none(self, name: str) -> None:
        backend = STORAGE_FACTORIES[name]()
        assert run(backend.get("sha256/absent")) is None
        assert run(backend.exists("sha256/absent")) is False

    def test_round_trip_is_byte_exact(self, name: str) -> None:
        backend = STORAGE_FACTORIES[name]()
        payload = os.urandom(8192)
        run(backend.put("sha256/aa/bb", payload))
        assert run(backend.get("sha256/aa/bb")) == payload

    def test_hostile_octets_survive(self, name: str) -> None:
        backend = STORAGE_FACTORIES[name]()
        payload = b"\x00\r\n\x1a\xff\xfe" * 512
        run(backend.put("k", payload))
        assert run(backend.get("k")) == payload

    def test_put_is_idempotent(self, name: str) -> None:
        backend = STORAGE_FACTORIES[name]()
        run(backend.put("k", b"same"))
        run(backend.put("k", b"same"))
        assert run(backend.get("k")) == b"same"

    def test_exists_agrees_with_get(self, name: str) -> None:
        backend = STORAGE_FACTORIES[name]()
        run(backend.put("k", b"v"))
        assert run(backend.exists("k")) is True
        assert run(backend.get("k")) == b"v"

    def test_list_prefix_is_complete_and_scoped(self, name: str) -> None:
        backend = STORAGE_FACTORIES[name]()
        for key in ("p/1", "p/2", "p/3", "q/1"):
            run(backend.put(key, key.encode()))
        listed = set(run(backend.list_prefix("p/")))
        assert listed == {"p/1", "p/2", "p/3"}

    def test_list_prefix_of_unknown_prefix_is_empty(self, name: str) -> None:
        assert run(STORAGE_FACTORIES[name]().list_prefix("zzz/")) == []

    def test_empty_key_is_refused(self, name: str) -> None:
        backend = STORAGE_FACTORIES[name]()
        with pytest.raises(ValueError):
            run(backend.put("", b"v"))


@pytest.mark.parametrize("name", sorted(SIGNER_FACTORIES))
class TestSignerContract:
    def test_public_key_is_returned_verbatim(self, name: str, keypair) -> None:
        pk, sk = keypair
        assert SIGNER_FACTORIES[name](pk, sk).public_key() == pk

    def test_kid_is_stable_and_derives_from_the_public_key(self, name: str, keypair) -> None:
        pk, sk = keypair
        first = SIGNER_FACTORIES[name](pk, sk).kid()
        second = SIGNER_FACTORIES[name](pk, sk).kid()
        assert first == second == hashlib.sha256(pk).hexdigest()[:16]

    def test_signature_verifies_under_the_public_key(self, name: str, keypair) -> None:
        pk, sk = keypair
        message = b'{"seq":7,"doc":"sha256:deadbeef","title":"M\\u00fcller"}'
        signature = SIGNER_FACTORIES[name](pk, sk).sign(message)
        assert isinstance(signature, bytes) and signature
        assert verify(pk, message, signature) is True

    def test_signature_does_not_verify_over_a_different_message(self, name: str, keypair) -> None:
        pk, sk = keypair
        signature = SIGNER_FACTORIES[name](pk, sk).sign(b"one")
        assert verify(pk, b"two", signature) is False

    def test_non_bytes_message_is_refused(self, name: str, keypair) -> None:
        pk, sk = keypair
        with pytest.raises(TypeError):
            SIGNER_FACTORIES[name](pk, sk).sign("text")  # type: ignore[arg-type]

    def test_can_sign_is_a_bool(self, name: str, keypair) -> None:
        pk, sk = keypair
        assert SIGNER_FACTORIES[name](pk, sk).can_sign() in (True, False)
