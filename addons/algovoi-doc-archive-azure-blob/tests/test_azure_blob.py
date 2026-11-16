# SPDX-License-Identifier: Apache-2.0
"""Tests for the Azure Blob backend, driven through an in-memory container client."""
from __future__ import annotations

import asyncio
import os

import pytest
from algovoi_doc_archive_azure_blob import AzureBlobBackend, AzureBlobError
from algovoi_doc_archive_azure_blob.testing import (
    BlobForbidden,
    InMemoryContainerClient,
)


def run(coro):
    return asyncio.run(coro)


def backend(client: InMemoryContainerClient, **kwargs) -> AzureBlobBackend:
    return AzureBlobBackend("evidence", container_client=client, **kwargs)


def test_round_trip_is_byte_exact() -> None:
    client = InMemoryContainerClient()
    b = backend(client)
    payload = os.urandom(4096)
    run(b.put("sha256/ab/cd", payload))
    assert run(b.get("sha256/ab/cd")) == payload
    assert client.blobs["sha256/ab/cd"] == payload


def test_missing_blob_is_none_not_an_exception() -> None:
    b = backend(InMemoryContainerClient())
    assert run(b.get("nope")) is None
    assert run(b.exists("nope")) is False


def test_put_is_idempotent() -> None:
    client = InMemoryContainerClient()
    b = backend(client)
    run(b.put("k", b"one"))
    run(b.put("k", b"one"))
    assert client.blobs["k"] == b"one"


def test_put_overwrites_through_overwrite_true() -> None:
    client = InMemoryContainerClient()
    b = backend(client)
    run(b.put("k", b"one"))
    run(b.put("k", b"two"))
    assert run(b.get("k")) == b"two"


def test_exists_agrees_with_get() -> None:
    b = backend(InMemoryContainerClient())
    run(b.put("k", b"v"))
    assert run(b.exists("k")) is True and run(b.get("k")) == b"v"


def test_prefix_namespaces_keys_without_leaking_into_returned_keys() -> None:
    client = InMemoryContainerClient()
    b = backend(client, prefix="tenant-a")
    run(b.put("docs/1", b"x"))
    assert "tenant-a/docs/1" in client.blobs
    assert run(b.get("docs/1")) == b"x"
    assert run(b.list_prefix("docs/")) == ["docs/1"]


def test_prefix_is_normalised_with_a_separator() -> None:
    client = InMemoryContainerClient()
    b = backend(client, prefix="tenant-a/")
    run(b.put("k", b"x"))
    assert list(client.blobs) == ["tenant-a/k"]


def test_list_prefix_returns_only_matching_names() -> None:
    client = InMemoryContainerClient(
        {"p/1": b"a", "p/2": b"b", "q/1": b"c", "pp/1": b"d"}
    )
    b = backend(client)
    assert sorted(run(b.list_prefix("p/"))) == ["p/1", "p/2"]


def test_list_prefix_of_empty_string_returns_everything() -> None:
    client = InMemoryContainerClient({"a": b"1", "b": b"2"})
    assert sorted(run(backend(client).list_prefix(""))) == ["a", "b"]


def test_list_prefix_strips_the_namespace() -> None:
    client = InMemoryContainerClient({"ns/p/1": b"a"})
    assert run(backend(client, prefix="ns").list_prefix("p/")) == ["p/1"]


def test_absent_is_distinguished_from_forbidden() -> None:
    class Forbidden(InMemoryContainerClient):
        def download_blob(self, name: str):
            raise BlobForbidden("authorization failure")

    with pytest.raises(AzureBlobError) as err:
        run(backend(Forbidden()).get("k"))
    assert not isinstance(err.value, FileNotFoundError)
    assert "authorization failure" in str(err.value)


def test_a_foreign_not_found_is_not_treated_as_absence() -> None:
    """Only a 404, or the Azure SDK's own not-found, may read as absence. A different library's
    ``ResourceNotFoundError`` must surface as a failure: a storage fault reported as a missing record
    is the one error an evidence archive cannot absorb."""

    class ResourceNotFoundError(Exception):
        pass

    class Foreign(InMemoryContainerClient):
        def download_blob(self, name: str):
            raise ResourceNotFoundError("no such row in the index")

    with pytest.raises(AzureBlobError):
        run(backend(Foreign()).get("k"))


def test_an_azure_sdk_not_found_with_the_blob_code_is_absence() -> None:
    class ResourceNotFoundError(Exception):
        error_code = "BlobNotFound"

    ResourceNotFoundError.__module__ = "azure.core.exceptions"

    class AzureLike(InMemoryContainerClient):
        def download_blob(self, name: str):
            raise ResourceNotFoundError("The specified blob does not exist")

    assert run(backend(AzureLike()).get("k")) is None


def test_a_container_not_found_without_an_error_code_raises() -> None:
    """The class is the same for a missing blob and a missing container; without the error code there
    is nothing to tell them apart, so the backend refuses to call it absence."""

    class ResourceNotFoundError(Exception):
        status_code = 404

    ResourceNotFoundError.__module__ = "azure.core.exceptions"

    class Ambiguous(InMemoryContainerClient):
        def download_blob(self, name: str):
            raise ResourceNotFoundError("The specified resource does not exist")

    with pytest.raises(AzureBlobError):
        run(backend(Ambiguous()).get("k"))


def test_upload_failure_is_wrapped() -> None:
    class Broken(InMemoryContainerClient):
        def upload_blob(self, name: str, data: bytes, overwrite: bool = False) -> None:
            raise BlobForbidden("no write access")

    with pytest.raises(AzureBlobError):
        run(backend(Broken()).put("k", b"v"))


def test_listing_failure_is_wrapped() -> None:
    class Broken(InMemoryContainerClient):
        def list_blobs(self, name_starts_with: str = ""):
            raise BlobForbidden("no list access")

    with pytest.raises(AzureBlobError):
        run(backend(Broken()).list_prefix("p/"))


def test_empty_key_is_refused() -> None:
    b = backend(InMemoryContainerClient())
    with pytest.raises(ValueError):
        run(b.put("", b"v"))
    with pytest.raises(ValueError):
        run(b.get(""))


def test_leading_slash_and_nul_are_refused() -> None:
    b = backend(InMemoryContainerClient())
    with pytest.raises(ValueError):
        run(b.get("/absolute"))
    with pytest.raises(ValueError):
        run(b.get("has\x00nul"))


def test_non_bytes_payload_is_refused() -> None:
    b = backend(InMemoryContainerClient())
    with pytest.raises(TypeError):
        run(b.put("k", "text"))  # type: ignore[arg-type]


def test_list_prefix_rejects_a_nul() -> None:
    b = backend(InMemoryContainerClient())
    with pytest.raises(ValueError):
        run(b.list_prefix("docs\x00"))


def test_no_client_and_no_credentials_fails_closed() -> None:
    b = AzureBlobBackend("evidence")
    # SDK absent -> ModuleNotFoundError naming the extra; SDK present -> AzureBlobError naming the
    # missing setting. Either way it must refuse rather than silently write nowhere.
    with pytest.raises((ModuleNotFoundError, AzureBlobError)):
        run(b.put("k", b"v"))


def test_repr_names_no_credentials() -> None:
    b = AzureBlobBackend("evidence", prefix="ns", connection_string="AccountKey=supersecret")
    assert "supersecret" not in repr(b)
    assert repr(b) == "AzureBlobBackend(container='evidence', prefix='ns/')"


def test_cannot_be_pickled() -> None:
    """A pickled backend would carry the SDK client's authenticated pipeline."""
    import pickle

    with pytest.raises(TypeError):
        pickle.dumps(backend(InMemoryContainerClient()))


def test_credentials_are_cleared_once_the_client_exists(monkeypatch) -> None:
    import sys
    import types

    class FakeService:
        @staticmethod
        def from_connection_string(connection_string: str) -> FakeService:
            return FakeService()

        def get_container_client(self, name: str) -> InMemoryContainerClient:
            return InMemoryContainerClient()

    fake_blob = types.ModuleType("azure.storage.blob")
    fake_blob.BlobServiceClient = FakeService  # type: ignore[attr-defined]
    fake_storage = types.ModuleType("azure.storage")
    fake_storage.blob = fake_blob  # type: ignore[attr-defined]
    fake_azure = types.ModuleType("azure")
    fake_azure.storage = fake_storage  # type: ignore[attr-defined]
    for name, module in (("azure", fake_azure), ("azure.storage", fake_storage),
                         ("azure.storage.blob", fake_blob)):
        monkeypatch.setitem(sys.modules, name, module)

    b = AzureBlobBackend("evidence", connection_string="AccountKey=supersecret")
    assert b._connection_string == "AccountKey=supersecret"
    client = b._container_client()
    assert isinstance(client, InMemoryContainerClient)
    assert b._connection_string is None
    assert b._credential is None


def test_credentials_are_cleared_when_client_construction_fails(monkeypatch) -> None:
    """A failed build is exactly when a debug dump gets taken: the secret must not still be on it."""
    import sys
    import types

    class FailingService:
        @staticmethod
        def from_connection_string(connection_string: str) -> FailingService:
            raise ValueError("could not parse the connection string")

    fake_blob = types.ModuleType("azure.storage.blob")
    fake_blob.BlobServiceClient = FailingService  # type: ignore[attr-defined]
    fake_storage = types.ModuleType("azure.storage")
    fake_storage.blob = fake_blob  # type: ignore[attr-defined]
    fake_azure = types.ModuleType("azure")
    fake_azure.storage = fake_storage  # type: ignore[attr-defined]
    for name, module in (("azure", fake_azure), ("azure.storage", fake_storage),
                         ("azure.storage.blob", fake_blob)):
        monkeypatch.setitem(sys.modules, name, module)

    b = AzureBlobBackend("evidence", connection_string="AccountKey=supersecret")
    with pytest.raises(ValueError):
        b._container_client()
    assert b._connection_string is None
    assert b._credential is None


def test_a_missing_container_raises_instead_of_reading_as_absence() -> None:
    """A renamed, deleted or wrong-account container returns 404 ContainerNotFound. Reading that as
    "blob absent" makes an unreachable archive look empty and healthy — the one failure an evidence
    store must never present as a clean answer."""

    class NotFound(Exception):
        status_code = 404
        error_code = "ContainerNotFound"

    class Broken(InMemoryContainerClient):
        def download_blob(self, name: str):
            raise NotFound("The specified container does not exist")

        def get_blob_properties(self, name: str):
            raise NotFound("The specified container does not exist")

    with pytest.raises(AzureBlobError):
        run(backend(Broken()).get("k"))
    with pytest.raises(AzureBlobError):
        run(backend(Broken()).exists("k"))


def test_a_blob_not_found_error_code_is_absence() -> None:
    class NotFound(Exception):
        status_code = 404
        error_code = "BlobNotFound"

    class Missing(InMemoryContainerClient):
        def download_blob(self, name: str):
            raise NotFound("The specified blob does not exist")

    assert run(backend(Missing()).get("k")) is None


def test_a_non_404_in_the_azure_namespace_is_not_absence() -> None:
    class ResourceNotFoundError(Exception):
        status_code = 409

    ResourceNotFoundError.__module__ = "azure.core.exceptions"

    class Conflict(InMemoryContainerClient):
        def download_blob(self, name: str):
            raise ResourceNotFoundError("CannotVerifyCopySource")

    with pytest.raises(AzureBlobError):
        run(backend(Conflict()).get("k"))


def test_upload_asks_the_sdk_to_validate_content() -> None:
    client = InMemoryContainerClient()
    run(backend(client).put("k", b"payload"))
    assert client.last_upload["overwrite"] is True
    assert client.last_upload["validate_content"] is True


def test_get_does_not_block_the_event_loop() -> None:
    """The Azure SDK is synchronous; a 300 ms call must not freeze every other archive operation."""
    import time

    class Slow(InMemoryContainerClient):
        def download_blob(self, name: str):
            time.sleep(0.3)
            return super().download_blob(name)

    async def scenario() -> int:
        b = backend(Slow())
        await b.put("k", b"v")
        ticks = 0

        async def ticker() -> None:
            nonlocal ticks
            for _ in range(20):
                await asyncio.sleep(0.01)
                ticks += 1

        task = asyncio.create_task(ticker())
        assert await b.get("k") == b"v"
        observed = ticks
        await task
        return observed

    assert run(scenario()) >= 5


def test_a_plaintext_account_url_is_refused() -> None:
    with pytest.raises(ValueError):
        AzureBlobBackend("evidence", account_url="http://acct.blob.core.windows.net")


def test_upload_error_text_is_redacted() -> None:
    class Leaky(InMemoryContainerClient):
        def upload_blob(self, name: str, data: bytes, overwrite: bool = False,
                        validate_content: bool = False) -> None:
            raise BlobForbidden("PUT https://acct/c/b?sv=2021&sig=SUPERSECRETSASVALUE failed")

    with pytest.raises(AzureBlobError) as err:
        run(backend(Leaky()).put("k", b"v"))
    assert "SUPERSECRETSASVALUE" not in str(err.value)
    assert "sig=<redacted>" in str(err.value)


def test_the_in_memory_double_warns_that_it_persists_nothing() -> None:
    with pytest.warns(UserWarning, match="test double"):
        InMemoryContainerClient()


def test_a_404_from_an_untrusted_module_is_not_absence() -> None:
    """Absence requires the ``BlobNotFound`` error code; a bare 404 from another library is a failure."""

    class ResourceNotFoundError(Exception):
        status_code = 404

    ResourceNotFoundError.__module__ = "somevendor.http"

    class Foreign(InMemoryContainerClient):
        def download_blob(self, name: str):
            raise ResourceNotFoundError("gone")

    with pytest.raises(AzureBlobError):
        run(backend(Foreign()).get("k"))
