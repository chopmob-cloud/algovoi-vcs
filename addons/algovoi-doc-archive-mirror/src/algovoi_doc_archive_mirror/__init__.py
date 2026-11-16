# SPDX-License-Identifier: Apache-2.0
"""Mirror storage backend for the AlgoVoi Verifiable Archive.

Fans writes out to several independent ``StorageBackend`` implementations and fails closed when fewer
than a quorum accept the write. Reads return the first copy found, and with ``verify_on_get`` enabled
they also read the remaining copies and refuse to return bytes that disagree.

Presence is not durability. ``exists`` answers "is it stored anywhere", which is what the engine's
contract asks; ``durable`` answers "is it on at least quorum backends", which is the question an audit
asks. A write that failed below quorum leaves the copies that landed in place — they are complete,
content-addressed blobs, so retrying is safe. Nothing is rolled back: a delete on failure would race
another writer that has just written the same key, and deleting evidence is worse than leaving an
unreferenced copy.

Reads degrade rather than fail: with the default ``verify_on_get=False``, a backend that raises is
skipped and the next healthy copy answers, and the read raises only when no backend could be read at
all. With ``verify_on_get=True`` an unreadable backend is an error, because a verifying read that
silently skipped a copy would be claiming verification it did not perform.

The engine stores content-addressed data: the bytes under a key are fixed by the digest in the key, so
two copies of one key must be byte-identical. A disagreement is corruption or a misconfigured backend,
never a legitimate difference, so it is reported rather than papered over.

No secret material is handled here and no session or credential is retained: the backends own their
own authentication. Provider error text is redacted before it is embedded in an exception, because a
storage SDK's message can carry a signed URL.
"""
from __future__ import annotations

import re
import warnings
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

__version__ = "0.1.0"

#: Query parameters and header fields that carry credentials in a provider error message.
_CREDENTIAL = re.compile(
    r"(?i)\b(sig|sv|se|sp|spr|sk|sr|st|accountkey|sharedaccesssignature)\s*=\s*[^&;\s'\"]+"
)


def _redact(text: object) -> str:
    """Strip credential-bearing parameters from provider text before it enters a message."""
    return _CREDENTIAL.sub(lambda m: f"{m.group(1)}=<redacted>", str(text))


@runtime_checkable
class StorageBackend(Protocol):
    """The engine's storage contract (``algovoi_doc_archive.backend.StorageBackend``), restated here so
    this package imports without the commercial engine installed."""

    async def put(self, key: str, data: bytes) -> None: ...
    async def get(self, key: str) -> bytes | None: ...
    async def exists(self, key: str) -> bool: ...
    async def list_prefix(self, prefix: str) -> list[str]: ...


class MirrorError(RuntimeError):
    """Base class for mirror failures."""


class MirrorWriteError(MirrorError):
    """Fewer than ``quorum`` backends accepted a write."""


class MirrorDivergence(MirrorError):
    """Two backends returned different bytes for the same content-addressed key."""


def _check_key(key: str) -> str:
    """Apply the same key rules as the backends this composes, so composition cannot widen the key
    space into a shape one backend accepts and another refuses."""
    if not isinstance(key, str):
        raise TypeError(f"key must be str, got {type(key).__name__}")
    if not key:
        raise ValueError("key must not be empty")
    if key.startswith("/"):
        raise ValueError("key must not start with '/'")
    if "\x00" in key:
        raise ValueError("key must not contain NUL")
    return key


def _as_bytes(data: bytes) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"data must be bytes-like, got {type(data).__name__}")


class MirrorBackend:
    """A ``StorageBackend`` that writes to every wrapped backend.

    A write that fails below quorum leaves the successful copies in place. Those are complete,
    content-addressed blobs — not half-written ones — so retrying is safe and completes the set. This
    backend deliberately does not roll them back: a delete on failure would race another writer that has
    just written the same key, and deleting evidence is worse than leaving an unreferenced copy.

    Parameters
    ----------
    backends:
        One or more storage backends.
    quorum:
        How many backends must accept a ``put`` before it is considered successful. Defaults to all
        of them, which is the only safe default for an evidence archive: a partial write that reports
        success is how a "we hold two copies" claim becomes false. A lower quorum warns, because it
        changes what the archive promises.
    verify_on_get:
        When true, ``get`` reads every backend that holds the key and raises
        :class:`MirrorDivergence` if two copies differ. Off by default, in which case ``get`` returns on
        the first copy found — that is both faster and why divergence is not detected by default.
        :meth:`durable` and :meth:`copies` answer the durability question either way.
    """

    def __init__(
        self,
        backends: Sequence[StorageBackend],
        *,
        quorum: int | None = None,
        verify_on_get: bool = False,
    ) -> None:
        wrapped = tuple(backends)
        if not wrapped:
            raise ValueError("MirrorBackend needs at least one backend")
        for index, backend in enumerate(wrapped):
            if not isinstance(backend, StorageBackend):
                raise TypeError(
                    f"backend {index} ({type(backend).__name__}) does not implement StorageBackend: "
                    "it needs async put, get, exists and list_prefix"
                )
        self._backends = wrapped
        self._quorum = len(wrapped) if quorum is None else int(quorum)
        if not 1 <= self._quorum <= len(wrapped):
            raise ValueError(f"quorum must be between 1 and {len(wrapped)}, got {self._quorum}")
        if self._quorum < len(wrapped):
            warnings.warn(
                f"MirrorBackend quorum {self._quorum} of {len(wrapped)}: a write can report success "
                f"with only {self._quorum} copies stored",
                UserWarning,
                stacklevel=2,
            )
        self.verify_on_get = bool(verify_on_get)

    @property
    def backends(self) -> tuple[StorageBackend, ...]:
        return self._backends

    @property
    def quorum(self) -> int:
        return self._quorum

    async def put(self, key: str, data: bytes) -> None:
        name = _check_key(key)
        payload = _as_bytes(data)
        failures: list[tuple[int, BaseException]] = []
        succeeded: list[int] = []
        for index, backend in enumerate(self._backends):
            try:
                await backend.put(name, payload)
            except Exception as exc:  # noqa: BLE001 - one backend's failure must not stop the others
                failures.append((index, exc))
            else:
                succeeded.append(index)
        tolerated = len(self._backends) - self._quorum
        if len(failures) > tolerated:
            first_index, first_error = failures[0]
            raise MirrorWriteError(
                f"mirror write of {name!r} reached {len(succeeded)} of {len(self._backends)} backends "
                f"(quorum {self._quorum}); succeeded: {succeeded}; "
                f"first failure: backend {first_index}: {type(first_error).__name__}: "
                f"{_redact(first_error)}"
            ) from first_error

    async def get(self, key: str) -> bytes | None:
        name = _check_key(key)
        if not self.verify_on_get:
            first_error: BaseException | None = None
            for backend in self._backends:
                try:
                    value = await backend.get(name)
                except Exception as exc:  # noqa: BLE001 - a dead backend must not fail a healthy read
                    if first_error is None:
                        first_error = exc
                    continue
                if value is not None:
                    return value
            if first_error is not None:
                # No copy was found, but at least one backend could not be read: "absent" is not
                # proven, and reporting it as such would be inventing a fact about the archive.
                raise MirrorError(
                    f"no readable copy of {name!r}; first failure: "
                    f"{type(first_error).__name__}: {_redact(first_error)}"
                ) from first_error
            return None

        outcomes: list[tuple[int, bytes | None, BaseException | None]] = []
        for index, backend in enumerate(self._backends):
            try:
                outcomes.append((index, await backend.get(name), None))
            except Exception as exc:  # noqa: BLE001 - collected, then refused below
                outcomes.append((index, None, exc))

        # A verifying read claims every copy was checked. A backend that could not be read makes that
        # claim false, so it is an error rather than a silently weaker answer.
        unreadable = [(index, error) for index, _value, error in outcomes if error is not None]
        if unreadable:
            first_index, first_error = unreadable[0]
            raise MirrorError(
                f"cannot verify {name!r}: backend {first_index} could not be read: "
                f"{type(first_error).__name__}: {_redact(first_error)}"
            ) from first_error

        found: bytes | None = None
        found_at: int | None = None
        divergent: list[int] = []
        for index, value, _error in outcomes:
            if value is None:
                continue
            if found is None:
                found, found_at = value, index
            elif value != found:
                divergent.append(index)
        if divergent:
            raise MirrorDivergence(
                f"mirror copies of {name!r} disagree: backend {found_at} returned "
                f"{len(found or b'')} bytes, backend(s) {divergent} returned different bytes"
            )
        return found

    async def exists(self, key: str) -> bool:
        """True if any backend holds the key. Use :meth:`durable` for the quorum question."""
        name = _check_key(key)
        for backend in self._backends:
            if await backend.exists(name):
                return True
        return False

    async def copies(self, key: str) -> int:
        """How many backends provably hold the key.

        A backend that raises during the check counts as zero copies: an unreachable store proves
        nothing about what it holds, and counting it would overstate durability.
        """
        name = _check_key(key)
        proven: list[bool] = []
        for backend in self._backends:
            try:
                proven.append(await backend.get(name) is not None)
            except Exception:  # noqa: BLE001 - an unreachable store proves nothing about its copies
                proven.append(False)
        return sum(proven)

    async def durable(self, key: str) -> bool:
        """True when at least ``quorum`` backends hold the key."""
        return await self.copies(key) >= self._quorum

    async def list_prefix(self, prefix: str) -> list[str]:
        if not isinstance(prefix, str):
            raise TypeError(f"prefix must be str, got {type(prefix).__name__}")
        keys: set[str] = set()
        for backend in self._backends:
            keys.update(await backend.list_prefix(prefix))
        return sorted(keys)

    def __repr__(self) -> str:
        return (
            f"MirrorBackend(backends={len(self._backends)}, quorum={self._quorum}, "
            f"verify_on_get={self.verify_on_get})"
        )
