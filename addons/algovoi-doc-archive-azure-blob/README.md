# algovoi-doc-archive-azure-blob

`StorageBackend` over Azure Blob Storage, including Azure Stack Hub and Azurite.

The engine encrypts and content-addresses before it calls a backend, so the container only ever holds
ciphertext under digest-derived keys. This backend does not transform, compress or re-encode the bytes,
and must not: the engine verifies digests on read.

## Install

```bash
pip install './addons/algovoi-doc-archive-azure-blob[azure]'
```

The Azure SDK is imported lazily, so the package installs and its tests run without it.

## Use

```python
from algovoi_doc_archive import Archive
from algovoi_doc_archive_azure_blob import AzureBlobBackend

storage = AzureBlobBackend(
    "evidence",
    prefix="tenant-a",                                       # optional key namespace
    account_url="https://acct.blob.core.windows.net",
    credential=credential,                                   # DefaultAzureCredential, SAS, token
)

archive = Archive(signer=signer, storage=storage, encryptor=encryptor)
```

`connection_string=` is also accepted for emulators and test subscriptions. It is never logged and never
appears in `repr`.

## Contract

| Call | Behaviour |
|---|---|
| `put` | `upload_blob(..., overwrite=True, validate_content=True)` — re-writing a key is safe, and the SDK checks the payload hash in transit. Bytes are uploaded verbatim. |
| `get` | Returns `None` for an absent **blob**, identified positively by the Azure `BlobNotFound` error code on a 404. A 403, a timeout, a 409 or a damaged response raises `AzureBlobError`. A missing **container** (`ContainerNotFound`) raises, and so does a 404 that carries no error code: the class is identical for both cases, so an unidentified 404 must not be reported as "record absent" — that is how an unreachable archive reads as empty and healthy. |
| `exists` | Properties call; a blob-level 404 → `False`, anything else → `AzureBlobError`. |
| `list_prefix` | `list_blobs(name_starts_with=...)`, with the configured namespace stripped from the returned keys. `prefix` is a prefix, not a directory: pass the trailing separator (`"docs/"`) if you mean a directory. |

Every SDK call runs in a worker thread via `asyncio.to_thread`. The Azure client is synchronous, and
calling it directly from an `async def` would stall the event loop for the length of a blob operation —
one slow download freezing every other archive request.

`account_url` must be `https://`; a plaintext endpoint is refused at construction. The backend refuses
to be pickled, because its client carries an authenticated pipeline.

Keys are validated: empty, leading `/` and embedded NUL are refused, because each of those produces a
blob name that Azure resolves differently from the key the engine recorded.

## Immutability

An Object Lock or immutability policy on the container adds store-level WORM beneath the chain's
tamper-evidence. Set it at container creation — Azure cannot retro-fit a time-based policy to existing
blobs — and record the policy ID in your evidence pack. This backend does not set it for you and cannot
verify it.

## Tests

```bash
python -m pytest addons/algovoi-doc-archive-azure-blob addons/conformance -q
```

### Integration tests against Azurite

The unit tests drive an injected client, which cannot prove the SDK's own 404 semantics. These run
against a real Azure Storage endpoint:

```bash
docker run -d --name azurite -p 10000:10000 mcr.microsoft.com/azure-storage/azurite \
    azurite-blob --blobHost 0.0.0.0 --blobPort 10000
pip install 'algovoi-doc-archive-azure-blob[integration]'
AZURITE_CONNECTION_STRING='UseDevelopmentStorage=true' \
    python -m pytest addons/algovoi-doc-archive-azure-blob -m integration -q
```

They are marked `integration` and deselected from the portable gate. The Azurite account key is
Microsoft's published development key — public by design, not a credential. A plaintext endpoint needs
`allow_insecure=True` at construction, so the emulator cannot be reached by accident from an estate.

These found a defect the double could not: `get_blob_properties` belongs to `BlobClient`, not
`ContainerClient`. The unit suite now includes a strict fake that exposes only the calls the real SDK
offers, so the same slip fails without an emulator.

`algovoi_doc_archive_azure_blob.testing.InMemoryContainerClient` is a shipped double for the four Azure
client calls this backend makes; it is what the portable suite drives, so the full key-mapping and
absent-versus-damaged paths are exercised without a subscription.
