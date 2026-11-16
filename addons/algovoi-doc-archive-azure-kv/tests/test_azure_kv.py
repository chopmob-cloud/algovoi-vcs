# SPDX-License-Identifier: Apache-2.0
"""Tests for Azure Key Vault custody, driven through a local RSA wrap/unwrap double and real Falcon
signatures."""
from __future__ import annotations

import pytest
from algovoi_doc_archive_azure_kv import (
    MAGIC,
    AzureKeyVaultError,
    AzureKeyVaultSigner,
    parse_secret_key_blob,
    wrap_secret_key,
)
from algovoi_doc_archive_azure_kv.testing import LocalRsaCryptoClient
from pqcrypto.sign.falcon_1024 import generate_keypair, verify


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    pk, sk = generate_keypair()
    return pk, sk


@pytest.fixture()
def client() -> LocalRsaCryptoClient:
    return LocalRsaCryptoClient()


def test_wrap_then_sign_produces_a_verifiable_falcon_signature(keypair, client) -> None:
    pk, sk = keypair
    blob = wrap_secret_key(sk, pk, client)
    signer = AzureKeyVaultSigner(pk, blob, crypto_client=client)
    message = b'{"seq":1,"doc":"sha256:abc"}'
    signature = signer.sign(message)
    assert verify(pk, message, signature) is True


def test_two_signatures_over_one_message_both_verify(keypair, client) -> None:
    pk, sk = keypair
    signer = AzureKeyVaultSigner(pk, wrap_secret_key(sk, pk, client), crypto_client=client)
    first, second = signer.sign(b"m"), signer.sign(b"m")
    assert verify(pk, b"m", first) and verify(pk, b"m", second)
    assert first != second  # Falcon signing is randomised


def test_kid_defaults_to_the_engine_derivation(keypair, client) -> None:
    import hashlib

    pk, sk = keypair
    signer = AzureKeyVaultSigner(pk, wrap_secret_key(sk, pk, client), crypto_client=client)
    assert signer.kid() == hashlib.sha256(pk).hexdigest()[:16]


def test_explicit_kid_is_pinned(keypair, client) -> None:
    pk, sk = keypair
    signer = AzureKeyVaultSigner(
        pk, wrap_secret_key(sk, pk, client), crypto_client=client, kid="vault-key-1"
    )
    assert signer.kid() == "vault-key-1"


def test_blob_binds_to_the_public_key_it_was_wrapped_for(keypair, client) -> None:
    pk, sk = keypair
    other_pk, _ = generate_keypair()
    blob = wrap_secret_key(sk, pk, client)
    signer = AzureKeyVaultSigner(other_pk, blob, crypto_client=client)
    with pytest.raises(AzureKeyVaultError) as err:
        signer.sign(b"m")
    assert "authentication" in str(err.value)


def test_a_flipped_ciphertext_byte_is_refused(keypair, client) -> None:
    pk, sk = keypair
    blob = bytearray(wrap_secret_key(sk, pk, client))
    blob[-1] ^= 0x01
    signer = AzureKeyVaultSigner(pk, bytes(blob), crypto_client=client)
    with pytest.raises(AzureKeyVaultError):
        signer.sign(b"m")


def test_a_truncated_blob_fails_authentication(keypair, client) -> None:
    """Structure is checked at construction; truncation inside the ciphertext can only be caught by the
    GCM tag, which is checked when the key is unwrapped."""
    pk, sk = keypair
    blob = wrap_secret_key(sk, pk, client)
    signer = AzureKeyVaultSigner(pk, blob[:-1], crypto_client=client)
    with pytest.raises(AzureKeyVaultError):
        signer.sign(b"m")


def test_a_blob_truncated_inside_the_wrapped_dek_is_refused_at_construction(keypair, client) -> None:
    pk, sk = keypair
    blob = wrap_secret_key(sk, pk, client)
    wdek_len = int.from_bytes(blob[5:7], "big")
    cut = 5 + 2 + wdek_len  # drop the nonce and ciphertext entirely
    with pytest.raises(AzureKeyVaultError):
        AzureKeyVaultSigner(pk, blob[:cut], crypto_client=client)


def test_unknown_format_version_is_refused(keypair, client) -> None:
    pk, sk = keypair
    blob = bytearray(wrap_secret_key(sk, pk, client))
    blob[4] = 0x02
    with pytest.raises(AzureKeyVaultError):
        AzureKeyVaultSigner(pk, bytes(blob), crypto_client=client)


def test_declared_length_longer_than_the_blob_is_refused(keypair, client) -> None:
    pk, sk = keypair
    blob = bytearray(wrap_secret_key(sk, pk, client))
    blob[5:7] = (0xFFFF).to_bytes(2, "big")
    with pytest.raises(AzureKeyVaultError):
        parse_secret_key_blob(bytes(blob))


def test_empty_wrapped_key_is_refused(keypair, client) -> None:
    pk, sk = keypair
    blob = bytearray(wrap_secret_key(sk, pk, client))
    blob[5:7] = (0).to_bytes(2, "big")
    with pytest.raises(AzureKeyVaultError):
        parse_secret_key_blob(bytes(blob))


def test_magic_prefix_is_present_and_stable(keypair, client) -> None:
    pk, sk = keypair
    assert wrap_secret_key(sk, pk, client).startswith(MAGIC)


def test_wrong_secret_key_length_is_refused(client) -> None:
    pk, _ = generate_keypair()
    with pytest.raises(ValueError):
        wrap_secret_key(b"too short", pk, client)


def test_public_key_of_the_wrong_length_is_refused(keypair, client) -> None:
    pk, sk = keypair
    blob = wrap_secret_key(sk, pk, client)
    with pytest.raises(ValueError):
        AzureKeyVaultSigner(b"short", blob, crypto_client=client)


def test_vault_failure_is_a_typed_error(keypair) -> None:
    pk, sk = keypair

    class Down(LocalRsaCryptoClient):
        def unwrap_key(self, *, algorithm: str, encrypted_key: bytes):
            raise ConnectionError("vault unreachable")

    client = LocalRsaCryptoClient()
    blob = wrap_secret_key(sk, pk, client)
    signer = AzureKeyVaultSigner(pk, blob, crypto_client=Down())
    with pytest.raises(AzureKeyVaultError) as err:
        signer.sign(b"m")
    assert isinstance(err.value.__cause__, ConnectionError)


def test_sign_rejects_non_bytes(keypair, client) -> None:
    pk, sk = keypair
    signer = AzureKeyVaultSigner(pk, wrap_secret_key(sk, pk, client), crypto_client=client)
    with pytest.raises(TypeError):
        signer.sign("text")  # type: ignore[arg-type]


def test_can_sign_runs_a_real_operation(keypair, client) -> None:
    pk, sk = keypair
    blob = wrap_secret_key(sk, pk, client)
    assert AzureKeyVaultSigner(pk, blob, crypto_client=client).can_sign() is True

    class Revoked(LocalRsaCryptoClient):
        def wrap_key(self, *, algorithm: str, key: bytes):
            raise PermissionError("key disabled")

    assert AzureKeyVaultSigner(pk, blob, crypto_client=Revoked()).can_sign() is False


def test_can_sign_is_cached_for_the_ttl(keypair) -> None:
    pk, sk = keypair
    client = LocalRsaCryptoClient()
    blob = wrap_secret_key(sk, pk, client)
    signer = AzureKeyVaultSigner(pk, blob, crypto_client=client, probe_ttl=60)
    client.calls.clear()
    assert signer.can_sign() is True
    assert signer.can_sign() is True
    assert sum(1 for call in client.calls if call.startswith("wrap:")) == 1


def test_can_sign_reprobes_after_the_ttl(keypair) -> None:
    pk, sk = keypair
    client = LocalRsaCryptoClient()
    blob = wrap_secret_key(sk, pk, client)
    signer = AzureKeyVaultSigner(pk, blob, crypto_client=client, probe_ttl=0)
    client.calls.clear()
    assert signer.can_sign() is True
    assert signer.can_sign() is True
    assert sum(1 for call in client.calls if call.startswith("wrap:")) == 2


def test_a_negative_probe_ttl_is_refused(keypair, client) -> None:
    pk, sk = keypair
    blob = wrap_secret_key(sk, pk, client)
    with pytest.raises(ValueError):
        AzureKeyVaultSigner(pk, blob, crypto_client=client, probe_ttl=-1)


def test_can_sign_works_with_a_client_that_has_no_metadata_call(keypair) -> None:
    """``CryptographyClient`` has no ``get_key()``; a capability check built on metadata would report
    "cannot sign" for a healthy key. Only ``wrap_key`` is required."""
    pk, sk = keypair
    client = LocalRsaCryptoClient()
    blob = wrap_secret_key(sk, pk, client)

    class WrapOnly:
        def __init__(self, inner: LocalRsaCryptoClient) -> None:
            self._inner = inner

        def wrap_key(self, *, algorithm: str, key: bytes):
            return self._inner.wrap_key(algorithm=algorithm, key=key)

    assert AzureKeyVaultSigner(pk, blob, crypto_client=WrapOnly(client)).can_sign() is True


def test_probe_overrides_the_default_liveness_check(keypair, client) -> None:
    pk, sk = keypair
    blob = wrap_secret_key(sk, pk, client)
    signer = AzureKeyVaultSigner(pk, blob, crypto_client=client, probe=lambda: False)
    assert signer.can_sign() is False


def test_plaintext_secret_key_is_not_retained_on_the_object(keypair, client) -> None:
    pk, sk = keypair
    signer = AzureKeyVaultSigner(pk, wrap_secret_key(sk, pk, client), crypto_client=client)
    signer.sign(b"m")
    for name, value in vars(signer).items():
        assert value != sk, f"attribute {name} holds the plaintext secret key"
        assert value != bytes(sk), f"attribute {name} holds the plaintext secret key"


def test_repr_leaks_no_key_material(keypair, client) -> None:
    pk, sk = keypair
    signer = AzureKeyVaultSigner(pk, wrap_secret_key(sk, pk, client), crypto_client=client)
    text = repr(signer)
    assert sk.hex() not in text and pk.hex() not in text
    assert "AzureKeyVaultSigner(kid=" in text


def test_wrapping_a_mismatched_key_pair_is_refused(keypair, client) -> None:
    """A blob wrapped from the wrong secret key signs perfectly and verifies under a different key:
    the archive is unverifiable and nothing says so until an examiner tries."""
    pk, _ = keypair
    _, other_sk = generate_keypair()
    with pytest.raises(AzureKeyVaultError) as err:
        wrap_secret_key(other_sk, pk, client)
    assert "does not sign for this public key" in str(err.value)


def test_a_wrap_failure_adds_no_extra_copy_of_the_secret_key(keypair) -> None:
    """The function must receive the key, so its frame necessarily holds ``secret_key``. What it must
    not do is bind further immutable copies that a captured traceback would also retain."""
    pk, sk = keypair

    class Failing:
        def wrap_key(self, *, algorithm: str, key: bytes) -> bytes:
            raise PermissionError("no wrap permission")

    with pytest.raises(AzureKeyVaultError) as err:
        wrap_secret_key(sk, pk, Failing())
    frame = err.value.__traceback__
    while frame is not None:
        if frame.tb_frame.f_globals.get("__name__") == "algovoi_doc_archive_azure_kv":
            held = {name for name, value in frame.tb_frame.f_locals.items() if value == sk}
            assert held <= {"secret_key"}, f"extra copy of the secret key in a frame: {sorted(held)}"
        frame = frame.tb_next


def test_can_sign_is_false_when_the_vault_refuses(keypair) -> None:
    """A refusal of the operation — not a missing metadata call — is what "cannot sign" means."""
    pk, sk = keypair

    class NoProbe:
        def wrap_key(self, *, algorithm: str, key: bytes):
            raise PermissionError("key is disabled")

        def unwrap_key(self, *, algorithm: str, encrypted_key: bytes):
            raise AssertionError("not used")

    client = LocalRsaCryptoClient()
    blob = wrap_secret_key(sk, pk, client)
    assert AzureKeyVaultSigner(pk, blob, crypto_client=NoProbe()).can_sign() is False
    assert AzureKeyVaultSigner(pk, blob, crypto_client=NoProbe(), probe=lambda: True).can_sign() is True


def test_vault_error_text_is_redacted(keypair) -> None:
    pk, sk = keypair

    class Leaky(LocalRsaCryptoClient):
        def unwrap_key(self, *, algorithm: str, encrypted_key: bytes):
            raise PermissionError("POST https://vault/keys/k/unwrap?api-version=7.4&sig=SUPERSECRETVALUE")

    client = LocalRsaCryptoClient()
    blob = wrap_secret_key(sk, pk, client)
    with pytest.raises(AzureKeyVaultError) as err:
        AzureKeyVaultSigner(pk, blob, crypto_client=Leaky()).sign(b"m")
    assert "SUPERSECRETVALUE" not in str(err.value)
    assert "sig=<redacted>" in str(err.value)


def test_a_wrap_result_carrying_encrypted_key_is_accepted(keypair) -> None:
    """The current SDK returns ``WrapResult.encrypted_key``, not ``.key``. A double that returns
    ``.key`` for both operations hides that, which is how this was found against a real vault."""
    import types

    pk, sk = keypair
    rsa = LocalRsaCryptoClient()
    wrapped = rsa._public.encrypt(b"k" * 32, rsa._padding)

    class WrapResultOnly:
        def wrap_key(self, *, algorithm: str, key: bytes):
            return types.SimpleNamespace(encrypted_key=wrapped)

    blob = wrap_secret_key(sk, pk, WrapResultOnly())
    assert blob.startswith(b"AVKV")


def test_plain_bytes_responses_are_accepted(keypair) -> None:
    pk, sk = keypair

    class BytesClient(LocalRsaCryptoClient):
        def wrap_key(self, *, algorithm: str, key: bytes) -> bytes:
            return super().wrap_key(algorithm=algorithm, key=key).encrypted_key

        def unwrap_key(self, *, algorithm: str, encrypted_key: bytes) -> bytes:
            return super().unwrap_key(algorithm=algorithm, encrypted_key=encrypted_key).key

    client = BytesClient()
    signer = AzureKeyVaultSigner(pk, wrap_secret_key(sk, pk, client), crypto_client=client)
    assert verify(pk, b"m", signer.sign(b"m")) is True


def test_a_response_with_no_usable_bytes_is_refused(keypair) -> None:
    import types

    pk, sk = keypair

    class Empty:
        def wrap_key(self, *, algorithm: str, key: bytes):
            return types.SimpleNamespace(nothing=b"x")

    with pytest.raises(AzureKeyVaultError) as err:
        wrap_secret_key(sk, pk, Empty())
    assert "no usable wrapped key" in str(err.value)
