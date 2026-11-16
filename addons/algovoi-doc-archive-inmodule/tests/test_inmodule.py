# SPDX-License-Identifier: Apache-2.0
"""Tests for the in-module signer. No third-party dependencies: the vendor callable is a stub here,
and the real Falcon signature check lives in the conformance suite."""
from __future__ import annotations

import hashlib

import pytest
from algovoi_doc_archive_inmodule import InModuleSigner, SignerError

PK = bytes(range(256)) * 7 + b"\x01"  # 1793 bytes, the Falcon-1024 public key length


def signer(**kwargs) -> InModuleSigner:
    return InModuleSigner(PK, lambda message: b"sig:" + message, **kwargs)


def test_public_key_is_returned_verbatim() -> None:
    assert signer().public_key() == PK


def test_default_kid_matches_the_engine_derivation() -> None:
    expected = hashlib.sha256(PK).hexdigest()[:16]
    assert signer().kid() == expected
    assert len(expected) == 16


def test_explicit_kid_is_pinned() -> None:
    assert signer(kid="fleet-key-1").kid() == "fleet-key-1"


def test_kid_is_stable_across_instances() -> None:
    assert signer().kid() == signer().kid()


def test_sign_delegates_exactly_the_message_bytes() -> None:
    seen: list[bytes] = []

    def vendor(message: bytes) -> bytes:
        seen.append(message)
        return b"sig"

    s = InModuleSigner(PK, vendor)
    assert s.sign(b'{"a":1}') == b"sig"
    assert seen == [b'{"a":1}']


def test_sign_accepts_bytearray_and_memoryview() -> None:
    s = signer()
    assert s.sign(bytearray(b"x")) == b"sig:x"
    assert s.sign(memoryview(b"y")) == b"sig:y"


def test_sign_rejects_non_bytes() -> None:
    with pytest.raises(TypeError):
        signer().sign("a string")  # type: ignore[arg-type]


def test_vendor_failure_becomes_a_typed_error() -> None:
    def vendor(message: bytes) -> bytes:
        raise TimeoutError("hsm busy")

    with pytest.raises(SignerError) as err:
        InModuleSigner(PK, vendor).sign(b"m")
    assert isinstance(err.value.__cause__, TimeoutError)
    assert "hsm busy" in str(err.value)


def test_vendor_returning_a_str_is_refused() -> None:
    with pytest.raises(SignerError):
        InModuleSigner(PK, lambda message: "not bytes").sign(b"m")  # type: ignore[arg-type,return-value]


def test_vendor_returning_nothing_is_refused() -> None:
    with pytest.raises(SignerError):
        InModuleSigner(PK, lambda message: b"").sign(b"m")


def test_can_sign_follows_a_live_probe() -> None:
    assert signer(probe=lambda: True).can_sign() is True
    assert signer(probe=lambda: False).can_sign() is False


def test_can_sign_is_false_when_the_probe_raises() -> None:
    def probe() -> bool:
        raise ConnectionError("module offline")

    assert signer(probe=probe).can_sign() is False


def test_can_sign_without_a_probe_reports_configuration() -> None:
    assert signer().can_sign() is True


def test_wrong_public_key_length_is_refused() -> None:
    with pytest.raises(ValueError):
        InModuleSigner(b"too short", lambda m: b"sig")


def test_public_key_length_check_can_be_disabled_for_another_profile() -> None:
    s = InModuleSigner(b"short", lambda m: b"sig", public_key_bytes=None)
    assert s.public_key() == b"short"


def test_empty_public_key_is_refused() -> None:
    with pytest.raises(ValueError):
        InModuleSigner(b"", lambda m: b"sig", public_key_bytes=None)


def test_non_callable_signer_is_refused() -> None:
    with pytest.raises(TypeError):
        InModuleSigner(PK, b"not callable")  # type: ignore[arg-type]


def test_empty_kid_is_refused() -> None:
    with pytest.raises(ValueError):
        signer(kid="")


def test_repr_leaks_no_key_material() -> None:
    text = repr(signer())
    assert PK.hex() not in text
    assert hashlib.sha256(PK).hexdigest() not in text
    assert "InModuleSigner(kid=" in text


def test_verify_fn_accepts_a_good_signature() -> None:
    s = signer(verify_fn=lambda message, signature: signature == b"sig:" + message)
    assert s.sign(b"payload") == b"sig:payload"


def test_verify_fn_turns_a_wrong_key_signature_into_an_error() -> None:
    """A bridge wired to the wrong module returns a valid signature made by another key; without a
    verifier nothing here can tell, and the archive is only discovered to be unverifiable later."""
    s = signer(verify_fn=lambda message, signature: False)
    with pytest.raises(SignerError) as err:
        s.sign(b"payload")
    assert "does not verify" in str(err.value)


def test_verify_fn_failure_is_a_signer_error() -> None:
    def verifier(message: bytes, signature: bytes) -> bool:
        raise ValueError("bad signature encoding")

    with pytest.raises(SignerError) as err:
        signer(verify_fn=verifier).sign(b"m")
    assert isinstance(err.value.__cause__, ValueError)


def test_non_callable_verify_fn_is_refused() -> None:
    with pytest.raises(TypeError):
        signer(verify_fn=b"nope")  # type: ignore[arg-type]


def test_vendor_error_text_is_redacted() -> None:
    def vendor(message: bytes) -> bytes:
        raise RuntimeError("HSM https://svc/sign?sv=2021&sig=SUPERSECRETSASVALUE refused")

    with pytest.raises(SignerError) as err:
        InModuleSigner(PK, vendor).sign(b"m")
    assert "SUPERSECRETSASVALUE" not in str(err.value)
    assert "sig=<redacted>" in str(err.value)


def test_repr_reports_whether_verification_is_on() -> None:
    assert "verify=no" in repr(signer())
    assert "verify=yes" in repr(signer(verify_fn=lambda m, s: True))
