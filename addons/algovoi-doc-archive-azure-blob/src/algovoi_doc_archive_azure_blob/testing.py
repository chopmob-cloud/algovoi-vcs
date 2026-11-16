# SPDX-License-Identifier: Apache-2.0
"""Test doubles for the Azure Blob backend.

Not for production use. ``InMemoryContainerClient`` mimics the four Azure client calls this backend
makes, so the full code path (key mapping, absent-versus-damaged handling, listing) can be exercised
without a network or an Azure subscription.
"""
from __future__ import annotations

import warnings
from collections.abc import Iterable


class BlobNotFound(Exception):
    """Stands in for ``azure.core.exceptions.ResourceNotFoundError`` — carries a 404 status and the
    error code the backend uses to distinguish a missing blob from a missing container."""

    status_code = 404
    error_code = "BlobNotFound"


class BlobForbidden(Exception):
    """Stands in for a 403 from an expired SAS or a bad role assignment."""

    status_code = 403


class _Download:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def readall(self) -> bytes:
        return self._data


class _BlobProps:
    def __init__(self, name: str, size: int) -> None:
        self.name = name
        self.size = size


class _BlobEntry:
    def __init__(self, name: str) -> None:
        self.name = name


class InMemoryContainerClient:
    """Minimal stand-in for ``ContainerClient`` backed by a dict.

    A test double: nothing is persisted anywhere. Using it in production silently discards evidence,
    so it warns on construction.
    """

    def __init__(self, blobs: dict[str, bytes] | None = None) -> None:
        warnings.warn(
            "InMemoryContainerClient is a test double: blobs are held in memory and never persisted",
            UserWarning,
            stacklevel=2,
        )
        self.blobs: dict[str, bytes] = dict(blobs or {})
        self.calls: list[tuple[str, str]] = []
        self.last_upload: dict[str, object] = {}

    def upload_blob(
        self,
        name: str,
        data: bytes,
        overwrite: bool = False,
        validate_content: bool = False,
    ) -> None:
        self.calls.append(("upload_blob", name))
        self.last_upload = {"name": name, "overwrite": overwrite, "validate_content": validate_content}
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Azure uploads bytes")
        if name in self.blobs and not overwrite:
            raise RuntimeError(f"blob {name!r} exists and overwrite is False")
        self.blobs[name] = bytes(data)

    def download_blob(self, name: str) -> _Download:
        self.calls.append(("download_blob", name))
        if name not in self.blobs:
            raise BlobNotFound(f"The specified blob does not exist: {name}")
        return _Download(self.blobs[name])

    def get_blob_properties(self, name: str) -> _BlobProps:
        self.calls.append(("get_blob_properties", name))
        if name not in self.blobs:
            raise BlobNotFound(f"The specified blob does not exist: {name}")
        return _BlobProps(name, len(self.blobs[name]))

    def list_blobs(self, name_starts_with: str = "") -> Iterable[_BlobEntry]:
        self.calls.append(("list_blobs", name_starts_with))
        for name in sorted(self.blobs):
            if name.startswith(name_starts_with):
                yield _BlobEntry(name)
