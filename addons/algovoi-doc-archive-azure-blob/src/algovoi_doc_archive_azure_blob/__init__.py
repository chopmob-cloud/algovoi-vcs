# SPDX-License-Identifier: Apache-2.0
"""Azure Blob Storage backend for the AlgoVoi Verifiable Archive.

Implements the engine's ``StorageBackend`` contract (async ``put`` / ``get`` / ``exists`` /
``list_prefix``) over Azure Blob Storage, including Azure Stack Hub and Azurite.

The engine encrypts and content-addresses before it calls a backend, so this package only ever sees
ciphertext under digest-derived keys. It does not transform, compress or re-encode the bytes, and it
must not: a backend that does fails the engine's digest verification on read.

Absence and failure are different answers. ``get`` returns ``None`` for a blob that is genuinely not
there and raises for everything else, because the engine separates "absent" from "damaged" and a
backend that collapses the two corrupts the evidence model. A missing **container** is a configuration
fault, not an absent record, so it raises.

The Azure SDK is synchronous. Every call is dispatched to a worker thread with ``asyncio.to_thread``
so a slow blob operation does not stall the event loop the engine is serving on.

The SDK is imported lazily, so this package imports, installs and is testable without it. A client can
be injected with ``container_client=``, which is how the test suite drives a real code path without a
network.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

__version__ = "0.1.0"

_ABSENT_ERROR_CODES = frozenset({"BlobNotFound"})

_CREDENTIAL = re.compile(
    r"(?i)\b(sig|sv|se|sp|spr|sk|sr|st|accountkey|sharedaccesssignature)\s*=\s*[^&;\s'\"]+"
)


def _redact(text: object) -> str:
    """A blob SDK message can carry a signed URL; strip the credential before it enters a message."""
    return _CREDENTIAL.sub(lambda m: f"{m.group(1)}=<redacted>", str(text))


class AzureBlobError(RuntimeError):
    """A Blob Storage call failed for a reason other than the blob being absent."""


def _is_absent(exc: BaseException) -> bool:
    """True only for a genuine blob-level not-found.

    Absence needs a **positive identification**: HTTP 404 (or no status at all) carrying the
    ``BlobNotFound`` error code. Nothing is inferred from a class name, because the same
    ``ResourceNotFoundError`` is raised for a missing blob and for a missing container, and the error
    code is the only field that distinguishes them. A 404 without a code therefore raises:
    a backend that cannot tell "record absent" from "container gone" must not answer "absent", or a
    broken deployment reads as an empty and healthy archive.

    The cost is stated plainly: if a future SDK stops populating ``error_code``, reads of missing keys
    raise instead of returning ``None``. That is a loud failure an operator can see, not silent
    corruption an examiner discovers.
    """
    status = getattr(exc, "status_code", None)
    if status is not None and status != 404:
        return False
    return getattr(exc, "error_code", None) in _ABSENT_ERROR_CODES


def _check_key(key: str) -> str:
    if not isinstance(key, str):
        raise TypeError(f"key must be str, got {type(key).__name__}")
    if not key:
        raise ValueError("key must not be empty")
    if key.startswith("/"):
        raise ValueError("key must not start with '/'")
    if "\x00" in key:
        raise ValueError("key must not contain NUL")
    return key


class AzureBlobBackend:
    """``StorageBackend`` over one blob container.

    Parameters
    ----------
    container:
        Container name. With ``container_client`` supplied it is used only for messages.
    prefix:
        Optional key namespace inside the container; normalised to end with ``/``.
    connection_string / account_url / credential:
        Passed to ``BlobServiceClient`` when no client is injected. Never logged and never formatted;
        cleared from the object once the authenticated client exists.
    container_client:
        An injected client (anything exposing ``upload_blob``, ``download_blob``,
        ``get_blob_properties`` and ``list_blobs``). Injection keeps the SDK optional.
    """

    def __init__(
        self,
        container: str,
        *,
        prefix: str = "",
        connection_string: str | None = None,
        account_url: str | None = None,
        credential: Any | None = None,
        container_client: Any | None = None,
    ) -> None:
        if not isinstance(container, str) or not container:
            raise ValueError("container must be a non-empty str")
        if prefix and not isinstance(prefix, str):
            raise TypeError("prefix must be str")
        if account_url is not None and not str(account_url).startswith("https://"):
            raise ValueError(
                "account_url must be https:// — a plaintext endpoint would put archive traffic and "
                "credentials on the wire in clear"
            )
        self._container = container
        self._prefix = prefix if not prefix or prefix.endswith("/") else prefix + "/"
        self._connection_string = connection_string
        self._account_url = account_url
        self._credential = credential
        self._client = container_client

    # -- client construction -------------------------------------------------
    def _container_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from azure.storage.blob import BlobServiceClient
        except ModuleNotFoundError as exc:  # pragma: no cover - exercised by the extra test
            raise ModuleNotFoundError(
                "azure-storage-blob is not installed. Install the Azure extra: "
                "pip install 'algovoi-doc-archive-azure-blob[azure]'"
            ) from exc
        if self._connection_string:
            service = self._build_from_connection_string(BlobServiceClient)
        elif self._account_url:
            service = self._build_from_account_url(BlobServiceClient)
        else:
            raise AzureBlobError(
                "no Azure credentials configured: pass container_client, connection_string or account_url"
            )
        self._client = service.get_container_client(self._container)
        # The client now holds its own authenticated pipeline, so this object no longer needs the
        # secret. Clear it: a backend whose __dict__ is logged or copied must not carry an account key
        # for the life of the process.
        self._clear_credentials()
        return self._client

    def _clear_credentials(self) -> None:
        self._connection_string = None
        self._credential = None

    def _build_from_connection_string(self, service_cls: Any) -> Any:
        try:
            return service_cls.from_connection_string(self._connection_string)
        except BaseException:
            # A failed build must not leave the secret on the object for a debug dump to find. The
            # object is left unusable rather than quietly retryable with a credential it no longer has.
            self._clear_credentials()
            raise

    def _build_from_account_url(self, service_cls: Any) -> Any:
        try:
            return service_cls(account_url=self._account_url, credential=self._credential)
        except BaseException:
            self._clear_credentials()
            raise

    def __getstate__(self) -> dict:
        """Refuse serialisation: the client's pipeline carries credentials that pickle would copy."""
        raise TypeError(
            "AzureBlobBackend holds storage credentials and cannot be pickled; "
            "construct it inside the process that uses it"
        )

    # -- key mapping ---------------------------------------------------------
    def _name(self, key: str) -> str:
        return self._prefix + _check_key(key)

    def _scope(self, prefix: str) -> str:
        if not isinstance(prefix, str):
            raise TypeError(f"prefix must be str, got {type(prefix).__name__}")
        if prefix.startswith("/"):
            raise ValueError("prefix must not start with '/'")
        if "\x00" in prefix:
            raise ValueError("prefix must not contain NUL")
        return self._prefix + prefix

    def _unscope(self, name: str) -> str:
        return name[len(self._prefix):] if self._prefix and name.startswith(self._prefix) else name

    # -- blocking work, run in a worker thread -------------------------------
    def _upload(self, name: str, payload: bytes) -> None:
        self._container_client().upload_blob(
            name=name, data=payload, overwrite=True, validate_content=True
        )

    def _download(self, name: str) -> bytes:
        return self._container_client().download_blob(name).readall()

    def _properties(self, name: str) -> None:
        self._container_client().get_blob_properties(name)

    def _list(self, scope: str) -> list[str]:
        return [
            name
            for name in (
                getattr(blob, "name", None)
                for blob in self._container_client().list_blobs(name_starts_with=scope)
            )
            if isinstance(name, str) and name.startswith(scope)
        ]

    # -- StorageBackend ------------------------------------------------------
    async def put(self, key: str, data: bytes) -> None:
        name = self._name(key)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"data must be bytes-like, got {type(data).__name__}")
        payload = bytes(data)
        try:
            await asyncio.to_thread(self._upload, name, payload)
        except Exception as exc:
            raise AzureBlobError(f"upload of {name!r} failed: {_redact(exc)}") from exc

    async def get(self, key: str) -> bytes | None:
        name = self._name(key)
        try:
            return await asyncio.to_thread(self._download, name)
        except Exception as exc:
            if _is_absent(exc):
                return None
            raise AzureBlobError(f"download of {name!r} failed: {_redact(exc)}") from exc

    async def exists(self, key: str) -> bool:
        name = self._name(key)
        try:
            await asyncio.to_thread(self._properties, name)
            return True
        except Exception as exc:
            if _is_absent(exc):
                return False
            raise AzureBlobError(f"properties of {name!r} failed: {_redact(exc)}") from exc

    async def list_prefix(self, prefix: str) -> list[str]:
        scope = self._scope(prefix)
        try:
            names = await asyncio.to_thread(self._list, scope)
        except Exception as exc:
            raise AzureBlobError(f"listing {scope!r} failed: {_redact(exc)}") from exc
        return [self._unscope(name) for name in names]

    def __repr__(self) -> str:
        return f"AzureBlobBackend(container={self._container!r}, prefix={self._prefix!r})"
