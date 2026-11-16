# algovoi-doc-archive-mirror

A `StorageBackend` that writes every entry to several independent backends and fails closed when fewer
than a quorum accept it.

The engine stores content-addressed data: the bytes under a key are fixed by the digest in the key. Two
copies of one key are therefore either identical or one of them is damaged, and this backend refuses to
return bytes that disagree with another copy when `verify_on_get` is enabled.

## Install

```bash
pip install ./addons/algovoi-doc-archive-mirror
```

No third-party dependencies.

## Use

```python
from algovoi_doc_archive import Archive, HybridPqcEncryptor
from algovoi_doc_archive_s3 import S3Backend
from algovoi_doc_archive_azure_blob import AzureBlobBackend
from algovoi_doc_archive_mirror import MirrorBackend

mirror = MirrorBackend(
    [
        S3Backend("evidence-eu-west-2", region_name="eu-west-2"),
        AzureBlobBackend("evidence", account_url="https://acct.blob.core.windows.net",
                         credential=credential),
    ],
    quorum=2,
    verify_on_get=True,   # reads every copy and refuses disagreement
)

archive = Archive(signer=signer, storage=mirror, encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
```

## Semantics

| Call | Behaviour |
|---|---|
| `put` | Writes to **every** backend. Succeeds only if at least `quorum` accepted; failures are collected and the error names the first one and which backends succeeded. Provider text is redacted, because a storage SDK's message can carry a signed URL. |
| `get` | Returns the first copy found, or `None`. With `verify_on_get`, reads every copy and raises `MirrorDivergence` if two differ. |
| `exists` | True if **any** backend holds the key. |
| `copies` | How many backends provably hold the key. A backend that raises counts as zero. |
| `durable` | True when `copies >= quorum` — the question an audit asks, which `exists` cannot answer. |
| `list_prefix` | Sorted union across backends. |

`quorum` defaults to all backends. That is deliberate: a partial write reported as success is how a
"we hold two independent copies" claim becomes false, and the whole point of this backend is that claim.
A lower quorum is accepted but warns at construction.

`exists` and `durable` are different questions, and conflating them is how a one-copy archive passes a
two-copy check. After a sub-quorum write, `exists` is True (the record is there) while `durable` is
False (it is not on quorum backends). Nothing is rolled back on failure, so an `exists`-guarded retry
will not repair the set — retry on `durable`, or unconditionally, since `put` is idempotent.

## Failure modes are typed

- `MirrorWriteError` — fewer than `quorum` backends accepted a write. The message names the key, the
  backends that succeeded, and the first failure. `put` is idempotent, so retrying is safe.
- `MirrorDivergence` — two copies of one content-addressed key disagree. Treat it as corruption on the
  backend named in the message; the engine cannot tell you which copy is correct, and neither can this
  backend.

No payload bytes appear in any exception message or `repr`.

## Tests

```bash
python -m pytest addons/algovoi-doc-archive-mirror addons/conformance -q
```
