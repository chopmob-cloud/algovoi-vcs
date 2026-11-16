# SPDX-License-Identifier: Apache-2.0
"""Integration tests against a real Key Vault API surface (Lowkey Vault).

Marked ``integration`` and deselected by default: they need a live emulator and the
``azure-keyvault-keys`` SDK. Run them explicitly:

    docker run -d --name lowkey -p 8443:8443 nagyesta/lowkey-vault:7.3.48-ubi10-minimal
    pip install 'algovoi-doc-archive-azure-kv[integration]'
    LOWKEY_VAULT_URL=https://localhost:8443 \
        python -m pytest addons/algovoi-doc-archive-azure-kv -m integration -q

Emulator-only concessions, all confined to this file:

* ``connection_verify=False`` — the emulator presents a self-signed certificate. No production code
  path in this addon disables TLS verification.
* ``verify_challenge_resource=False`` — the emulator's vault URI is a localhost authority.
* a static token credential — the emulator checks that a bearer token is present and ignores its value.
* ``api_version="7.4"`` — the SDK's default API version is newer than this emulator implements.

These tests found two defects the shipped double could not: the current SDK returns
``WrapResult.encrypted_key`` for a wrap and ``UnwrapResult.key`` for an unwrap (the adapter only
understood ``.key``), and ``CryptographyClient`` has no ``get_key()``, so a ``can_sign()`` built on a
metadata read reported "cannot sign" for a perfectly healthy key.
"""
from __future__ import annotations

import os
import time
import uuid

import pytest
from algovoi_doc_archive_azure_kv import (
    AzureKeyVaultError,
    AzureKeyVaultSigner,
    wrap_secret_key,
)
from pqcrypto.sign.falcon_1024 import generate_keypair, verify

pytestmark = pytest.mark.integration

VAULT_URL = os.environ.get("LOWKEY_VAULT_URL", "https://localhost:8443")
API_VERSION = "7.4"


class _StaticToken:
    """The emulator requires a bearer token and ignores its value."""

    def get_token(self, *scopes: object, **kwargs: object):
        from azure.core.credentials import AccessToken

        return AccessToken("lowkey-vault-test-token", int(time.time()) + 3600)


def _client_kwargs() -> dict:
    # A guard against the obvious misuse of a copied test file: these clients disable TLS
    # verification, so the URL must be a local emulator. A real vault has to be tested with a real
    # certificate and real verification.
    if not VAULT_URL.startswith(("https://localhost", "https://127.0.0.1")):
        raise RuntimeError(
            "these tests disable TLS verification and are for a local emulator only; "
            f"refusing LOWKEY_VAULT_URL={VAULT_URL!r}"
        )
    return {
        "credential": _StaticToken(),
        "connection_verify": False,
        "verify_challenge_resource": False,
        "api_version": API_VERSION,
    }


@pytest.fixture(scope="module")
def key_client():
    from azure.keyvault.keys import KeyClient

    return KeyClient(vault_url=VAULT_URL, **_client_kwargs())


@pytest.fixture(scope="module")
def vault_key(key_client):
    from azure.keyvault.keys import KeyOperation, KeyType

    operations = [
        KeyOperation.encrypt,
        KeyOperation.decrypt,
        KeyOperation.wrap_key,
        KeyOperation.unwrap_key,
    ]
    name = "kek-" + uuid.uuid4().hex[:10]
    key = key_client.create_key(name, KeyType.rsa, size=2048, key_operations=operations)
    return key_client, name, key


@pytest.fixture(scope="module")
def crypto_client(vault_key):
    """Built from the key **id**, not the key object.

    A client constructed from a ``KeyVaultKey`` that carries local key material will try the wrap
    locally before calling the vault. Binding by id removes that path, so every operation provably goes
    to the service — which is what custody means.
    """
    from azure.keyvault.keys.crypto import CryptographyClient

    _key_client, _name, key = vault_key
    return CryptographyClient(key.id, **_client_kwargs())


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


def test_wrap_then_sign_produces_a_verifiable_signature(keypair, crypto_client) -> None:
    pk, sk = keypair
    blob = wrap_secret_key(sk, pk, crypto_client)
    signer = AzureKeyVaultSigner(pk, blob, crypto_client=crypto_client)
    message = b'{"seq":1,"doc":"sha256:abc"}'
    assert verify(pk, message, signer.sign(message)) is True


def test_kid_defaults_to_the_engine_derivation(keypair, crypto_client) -> None:
    import hashlib

    pk, sk = keypair
    signer = AzureKeyVaultSigner(pk, wrap_secret_key(sk, pk, crypto_client), crypto_client=crypto_client)
    assert signer.kid() == hashlib.sha256(pk).hexdigest()[:16]


def test_can_sign_is_true_for_an_enabled_key(keypair, crypto_client) -> None:
    pk, sk = keypair
    signer = AzureKeyVaultSigner(pk, wrap_secret_key(sk, pk, crypto_client), crypto_client=crypto_client)
    assert signer.can_sign() is True


def test_can_sign_is_false_when_the_vault_refuses(keypair, crypto_client) -> None:
    """A key that does not exist is refused by the service, and that is what ``can_sign`` reports.

    The emulator does not implement ``update_key_properties``, so this uses a key id the vault answers
    404 for rather than disabling a real key.
    """
    from azure.keyvault.keys.crypto import CryptographyClient

    pk, sk = keypair
    blob = wrap_secret_key(sk, pk, crypto_client)
    missing = f"{VAULT_URL}/keys/nosuchkey{uuid.uuid4().hex[:8]}"
    signer = AzureKeyVaultSigner(
        pk, blob, crypto_client=CryptographyClient(missing, **_client_kwargs())
    )
    assert signer.can_sign() is False
    with pytest.raises(AzureKeyVaultError):
        signer.sign(b"m")


def test_a_tampered_blob_is_refused(keypair, crypto_client) -> None:
    pk, sk = keypair
    blob = bytearray(wrap_secret_key(sk, pk, crypto_client))
    blob[-1] ^= 0x01
    signer = AzureKeyVaultSigner(pk, bytes(blob), crypto_client=crypto_client)
    with pytest.raises(AzureKeyVaultError):
        signer.sign(b"m")


def test_a_blob_wrapped_for_another_key_is_refused(keypair, crypto_client) -> None:
    pk, sk = keypair
    other_pk, _ = generate_keypair()
    blob = wrap_secret_key(sk, pk, crypto_client)
    with pytest.raises(AzureKeyVaultError):
        AzureKeyVaultSigner(other_pk, blob, crypto_client=crypto_client).sign(b"m")


def test_a_mismatched_pair_is_refused_before_the_vault_is_called(keypair, crypto_client) -> None:
    pk, _ = keypair
    _, other_sk = generate_keypair()
    with pytest.raises(AzureKeyVaultError):
        wrap_secret_key(other_sk, pk, crypto_client)


def test_the_operation_really_reached_the_vault(keypair, vault_key, crypto_client) -> None:
    """A custody adapter that never talks to the service would still produce valid signatures. Read the
    key back from the vault and check it is the enabled one this signer was built for."""
    key_client, name, _key = vault_key
    pk, sk = keypair
    wrap_secret_key(sk, pk, crypto_client)
    stored = key_client.get_key(name)
    assert stored.id.startswith(VAULT_URL)
    assert stored.properties.enabled is True
