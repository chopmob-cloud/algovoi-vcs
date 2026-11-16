# SPDX-License-Identifier: Apache-2.0
"""Tests for the mirror storage backend. No third-party dependencies."""
from __future__ import annotations

import asyncio
import os

import pytest
from algovoi_doc_archive_mirror import (
    MirrorBackend,
    MirrorDivergence,
    MirrorError,
    MirrorWriteError,
)


def run(coro):
    return asyncio.run(coro)


class MemoryBackend:
    """Minimal in-memory StorageBackend with failure switches."""

    def __init__(self, name: str = "mem") -> None:
        self.name = name
        self.data: dict[str, bytes] = {}
        self.fail_put = False
        self.fail_get = False
        self.puts = 0

    async def put(self, key: str, data: bytes) -> None:
        self.puts += 1
        if self.fail_put:
            raise RuntimeError(f"{self.name} is down")
        self.data[key] = bytes(data)

    async def get(self, key: str) -> bytes | None:
        if self.fail_get:
            raise RuntimeError(f"{self.name} is down")
        return self.data.get(key)

    async def exists(self, key: str) -> bool:
        return key in self.data

    async def list_prefix(self, prefix: str) -> list[str]:
        return [k for k in self.data if k.startswith(prefix)]


def test_writes_reach_every_backend_and_read_returns_bytes() -> None:
    a, b = MemoryBackend("a"), MemoryBackend("b")
    mirror = MirrorBackend([a, b])
    run(mirror.put("sha256:aa", b"payload"))
    assert a.data == {"sha256:aa": b"payload"}
    assert b.data == {"sha256:aa": b"payload"}
    assert run(mirror.get("sha256:aa")) == b"payload"


def test_missing_key_is_none_not_an_exception() -> None:
    mirror = MirrorBackend([MemoryBackend(), MemoryBackend()])
    assert run(mirror.get("sha256:missing")) is None
    assert run(mirror.exists("sha256:missing")) is False


def test_put_is_idempotent() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b])
    run(mirror.put("k", b"one"))
    run(mirror.put("k", b"one"))
    assert run(mirror.get("k")) == b"one"
    assert a.puts == 2 and b.puts == 2


def test_put_does_not_transform_bytes() -> None:
    payload = os.urandom(64 * 1024)
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b])
    run(mirror.put("k", payload))
    assert a.data["k"] == payload
    assert run(mirror.get("k")) == payload


def test_bytearray_input_is_stored_as_immutable_bytes() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b])
    run(mirror.put("k", bytearray(b"abc")))
    assert type(a.data["k"]) is bytes
    assert a.data["k"] == b"abc"


def test_quorum_two_of_three_tolerates_one_failure() -> None:
    a, b, c = MemoryBackend("a"), MemoryBackend("b"), MemoryBackend("c")
    c.fail_put = True
    mirror = MirrorBackend([a, b, c], quorum=2)
    run(mirror.put("k", b"v"))
    assert "k" in a.data and "k" in b.data and "k" not in c.data


def test_default_quorum_is_all_and_fails_closed() -> None:
    a, b, c = MemoryBackend("a"), MemoryBackend("b"), MemoryBackend("c")
    b.fail_put = True
    mirror = MirrorBackend([a, b, c])
    with pytest.raises(MirrorWriteError) as err:
        run(mirror.put("sha256:cc", b"v"))
    message = str(err.value)
    assert "sha256:cc" in message
    assert "succeeded: [0, 2]" in message
    assert "backend 1" in message


def test_failed_put_names_no_payload_bytes() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    b.fail_put = True
    mirror = MirrorBackend([a, b])
    secret_payload = b"super-secret-document"
    with pytest.raises(MirrorWriteError) as err:
        run(mirror.put("k", secret_payload))
    assert b"super-secret-document" not in str(err.value).encode()


def test_divergence_is_refused_when_verifying_on_get() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b], verify_on_get=True)
    a.data["k"] = b"one"
    b.data["k"] = b"two"
    with pytest.raises(MirrorDivergence):
        run(mirror.get("k"))


def test_divergence_is_ignored_when_not_verifying() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b])
    a.data["k"] = b"one"
    b.data["k"] = b"two"
    assert run(mirror.get("k")) == b"one"


def test_one_copy_missing_is_not_divergence() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b], verify_on_get=True)
    a.data["k"] = b"one"
    assert run(mirror.get("k")) == b"one"


def test_exists_true_when_any_copy_exists() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b])
    b.data["k"] = b"v"
    assert run(mirror.exists("k")) is True


def test_list_prefix_is_a_sorted_union() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b])
    a.data.update({"x/1": b"", "x/2": b""})
    b.data.update({"x/2": b"", "x/3": b""})
    assert run(mirror.list_prefix("x/")) == ["x/1", "x/2", "x/3"]
    assert run(mirror.list_prefix("y/")) == []


def test_constructor_rejects_no_backends() -> None:
    with pytest.raises(ValueError):
        MirrorBackend([])


def test_constructor_rejects_a_non_backend() -> None:
    class NotABackend:
        pass

    with pytest.raises(TypeError):
        MirrorBackend([MemoryBackend(), NotABackend()])  # type: ignore[list-item]


@pytest.mark.parametrize("quorum", [0, 3, -1])
def test_constructor_rejects_out_of_range_quorum(quorum: int) -> None:
    with pytest.raises(ValueError):
        MirrorBackend([MemoryBackend(), MemoryBackend()], quorum=quorum)


def test_empty_key_is_refused() -> None:
    mirror = MirrorBackend([MemoryBackend()])
    with pytest.raises(ValueError):
        run(mirror.put("", b"v"))
    with pytest.raises(ValueError):
        run(mirror.get(""))


def test_non_str_key_is_refused() -> None:
    mirror = MirrorBackend([MemoryBackend()])
    with pytest.raises(TypeError):
        run(mirror.get(b"bytes-key"))  # type: ignore[arg-type]


def test_non_bytes_payload_is_refused() -> None:
    mirror = MirrorBackend([MemoryBackend()])
    with pytest.raises(TypeError):
        run(mirror.put("k", "a string"))  # type: ignore[arg-type]


def test_repr_names_no_keys() -> None:
    mirror = MirrorBackend([MemoryBackend(), MemoryBackend()], quorum=1)
    assert repr(mirror) == "MirrorBackend(backends=2, quorum=1, verify_on_get=False)"


def test_a_failed_write_leaves_a_complete_copy_and_a_retry_finishes_it() -> None:
    """Partial state is deliberate: the copies that landed are complete content-addressed blobs, not
    half-written ones, so a retry completes the set. Nothing is rolled back — a delete on failure would
    race another writer that has just written the same key."""
    a, b = MemoryBackend(), MemoryBackend()
    b.fail_put = True
    mirror = MirrorBackend([a, b])
    with pytest.raises(MirrorWriteError):
        run(mirror.put("k", b"payload"))
    assert a.data["k"] == b"payload"
    assert "k" not in b.data

    b.fail_put = False
    run(mirror.put("k", b"payload"))
    assert a.data["k"] == b.data["k"] == b"payload"


def test_a_partial_write_is_readable_from_the_copy_that_landed() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    b.fail_put = True
    mirror = MirrorBackend([a, b])
    with pytest.raises(MirrorWriteError):
        run(mirror.put("k", b"payload"))
    assert run(mirror.get("k")) == b"payload"


class CountingBackend(MemoryBackend):
    def __init__(self, name: str = "count") -> None:
        super().__init__(name)
        self.gets = 0

    async def get(self, key: str) -> bytes | None:
        self.gets += 1
        return await super().get(key)


def test_get_returns_on_the_first_copy_when_not_verifying() -> None:
    a, b = CountingBackend("a"), CountingBackend("b")
    mirror = MirrorBackend([a, b])
    run(mirror.put("k", b"v"))
    a.gets = b.gets = 0
    assert run(mirror.get("k")) == b"v"
    assert (a.gets, b.gets) == (1, 0)


def test_verifying_get_reads_every_copy() -> None:
    a, b = CountingBackend("a"), CountingBackend("b")
    mirror = MirrorBackend([a, b], verify_on_get=True)
    run(mirror.put("k", b"v"))
    a.gets = b.gets = 0
    assert run(mirror.get("k")) == b"v"
    assert (a.gets, b.gets) == (1, 1)


def test_durable_answers_the_quorum_question_not_presence() -> None:
    a, b, c = MemoryBackend("a"), MemoryBackend("b"), MemoryBackend("c")
    c.fail_put = True
    mirror = MirrorBackend([a, b, c])
    with pytest.raises(MirrorWriteError):
        run(mirror.put("k", b"v"))
    assert run(mirror.exists("k")) is True       # it is somewhere
    assert run(mirror.copies("k")) == 2
    assert run(mirror.durable("k")) is False     # but not on quorum


def test_durable_is_true_once_the_set_is_complete() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b])
    run(mirror.put("k", b"v"))
    assert run(mirror.copies("k")) == 2
    assert run(mirror.durable("k")) is True


def test_a_low_quorum_warns() -> None:
    with pytest.warns(UserWarning, match="quorum 1 of 3"):
        MirrorBackend([MemoryBackend(), MemoryBackend(), MemoryBackend()], quorum=1)


def test_an_unreachable_backend_counts_as_zero_copies() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b])
    run(mirror.put("k", b"v"))
    b.fail_get = True
    assert run(mirror.copies("k")) == 1
    assert run(mirror.durable("k")) is False


def test_key_rules_match_the_backends_this_composes() -> None:
    mirror = MirrorBackend([MemoryBackend()])
    with pytest.raises(ValueError):
        run(mirror.put("/absolute", b"v"))
    with pytest.raises(ValueError):
        run(mirror.get("has\x00nul"))


def test_backend_error_text_is_redacted() -> None:
    class Leaky(MemoryBackend):
        async def put(self, key: str, data: bytes) -> None:
            raise RuntimeError(
                "PUT https://acct.blob.core.windows.net/c/b?sv=2021&sig=SUPERSECRETSASVALUE failed"
            )

    mirror = MirrorBackend([Leaky(), MemoryBackend()])
    with pytest.raises(MirrorWriteError) as err:
        run(mirror.put("k", b"v"))
    assert "SUPERSECRETSASVALUE" not in str(err.value)
    assert "sig=<redacted>" in str(err.value)


def test_get_survives_one_dead_backend() -> None:
    """A mirror exists so a read survives a lost store; failing the read because the first backend is
    down defeats the point."""
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b])
    run(mirror.put("k", b"v"))
    a.fail_get = True
    assert run(mirror.get("k")) == b"v"


def test_get_raises_when_no_backend_can_be_read() -> None:
    a, b = MemoryBackend(), MemoryBackend()
    a.fail_get = b.fail_get = True
    with pytest.raises(MirrorError):
        run(MirrorBackend([a, b]).get("k"))


def test_get_returns_none_when_every_backend_answers_absent() -> None:
    assert run(MirrorBackend([MemoryBackend(), MemoryBackend()]).get("k")) is None


def test_verifying_get_refuses_when_a_copy_cannot_be_read() -> None:
    """A verifying read claims every copy was checked. Skipping an unreadable one would be claiming
    verification it did not perform."""
    a, b = MemoryBackend(), MemoryBackend()
    mirror = MirrorBackend([a, b], verify_on_get=True)
    run(mirror.put("k", b"v"))
    b.fail_get = True
    with pytest.raises(MirrorError):
        run(mirror.get("k"))
