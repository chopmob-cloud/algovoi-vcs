# SPDX-License-Identifier: Apache-2.0
"""Integration tests against a real Azure Blob endpoint (Azurite).

These are marked ``integration`` and deselected by default: they need a live service and the
``azure-storage-blob`` SDK, neither of which belongs in the portable gate. Run them explicitly:

    docker run -d --name azurite -p 10000:10000 mcr.microsoft.com/azure-storage/azurite \
        azurite-blob --blobHost 0.0.0.0 --blobPort 10000
    pip install 'algovoi-doc-archive-azure-blob[integration]'
    AZURITE_CONNECTION_STRING='UseDevelopmentStorage=true' \
        python -m pytest addons/algovoi-doc-archive-azure-blob -m integration -q

The Azurite account key below is the well-known public development key published by Microsoft. It is
not a secret and it authorises nothing: it exists so this backend can be exercised against the real
Azure Storage wire protocol instead of a double.
"""
from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from algovoi_doc_archive_azure_blob import AzureBlobBackend, AzureBlobError

pytestmark = pytest.mark.integration

#: Microsoft's published Azurite development account. Public by design, not a credential.
AZURITE_CONNECTION_STRING = os.environ.get("AZURITE_CONNECTION_STRING", "UseDevelopmentStorage=true")


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(scope="module")
def service() -> Any:
    """Imported here, not at module scope: the SDK is an optional extra, and collection must work
    without it so the marker can deselect this module instead of erroring on import."""
    from azure.storage.blob import BlobServiceClient

    return BlobServiceClient.from_connection_string(AZURITE_CONNECTION_STRING)


@pytest.fixture()
def container(service: Any) -> Iterator[str]:
    name = "vcs" + uuid.uuid4().hex[:12]
    service.create_container(name)
    yield name
    try:
        service.delete_container(name)
    except Exception:  # noqa: BLE001, S110 - best-effort teardown, never masks a test result
        pass


def backend(container_name: str, **kwargs) -> AzureBlobBackend:
    return AzureBlobBackend(
        container_name,
        connection_string=AZURITE_CONNECTION_STRING,
        allow_insecure=True,
        **kwargs,
    )


def test_round_trip_over_the_real_protocol(container: str) -> None:
    b = backend(container)
    payload = os.urandom(8192)
    run(b.put("sha256/aa/bb", payload))
    assert run(b.get("sha256/aa/bb")) == payload


def test_hostile_octets_survive_the_wire(container: str) -> None:
    b = backend(container)
    payload = b"\x00\r\n\x1a\xff\xfe" * 512
    run(b.put("k", payload))
    assert run(b.get("k")) == payload


def test_a_missing_blob_is_none_on_a_real_404(container: str) -> None:
    """The unit tests simulate ``BlobNotFound``; this is the SDK's own error on a real response."""
    assert run(backend(container).get("definitely-not-here")) is None
    assert run(backend(container).exists("definitely-not-here")) is False


def test_a_missing_container_raises_on_a_real_404() -> None:
    """The defect the doubles could only imitate: Azure answers a missing container with the same
    ``ResourceNotFoundError`` and a different error code, and it must not read as an absent record."""
    missing = "nosuchcontainer" + uuid.uuid4().hex[:8]
    with pytest.raises(AzureBlobError):
        run(backend(missing).get("k"))
    with pytest.raises(AzureBlobError):
        run(backend(missing).exists("k"))


def test_put_is_idempotent_and_overwrites(container: str) -> None:
    b = backend(container)
    run(b.put("k", b"one"))
    run(b.put("k", b"one"))
    assert run(b.get("k")) == b"one"
    run(b.put("k", b"two"))
    assert run(b.get("k")) == b"two"


def test_list_prefix_is_scoped_and_keyed_as_the_engine_sees_it(container: str) -> None:
    b = backend(container)
    for key in ("p/1", "p/2", "q/1"):
        run(b.put(key, key.encode()))
    assert sorted(run(b.list_prefix("p/"))) == ["p/1", "p/2"]


def test_a_namespace_prefix_round_trips(container: str) -> None:
    b = backend(container, prefix="tenant-a")
    run(b.put("docs/1", b"x"))
    assert run(b.get("docs/1")) == b"x"
    assert run(b.list_prefix("docs/")) == ["docs/1"]


def test_a_plaintext_connection_string_needs_an_explicit_opt_in(container: str) -> None:
    with pytest.raises(ValueError):
        AzureBlobBackend(container, connection_string=AZURITE_CONNECTION_STRING)
