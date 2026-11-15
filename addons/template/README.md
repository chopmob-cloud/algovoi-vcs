# Addon template

A copyable skeleton for an addon against `algovoi-doc-archive` 0.1.6. It builds, installs and imports;
it implements nothing — every method raises `NotImplementedError` on purpose.

```bash
cp -r addons/template ~/my-addon && cd ~/my-addon
# rename the package and project, then:
python -m build --wheel
```

Replace `ExampleStorageBackend` and/or `ExampleSigner` with your implementation, or delete the one you
do not need. Keep the method signatures identical — `StorageBackend` and `Signer` are `runtime_checkable`
Protocols, and `isinstance()` checks method presence, not correctness.

## What to keep

- `dependencies = ["algovoi-doc-archive>=0.1.6"]` — states the Protocol version you built against.
- Provider SDKs in `[project.optional-dependencies]`, never in base dependencies, so you do not force
  `boto3` on a user who chose a filesystem backend.
- Lazy imports inside functions, with `ModuleNotFoundError` translated into a message naming the extra.
- No caps on `pqcrypto` or `cryptography` — those ranges belong to the engine and govern the suite's
  post-quantum behaviour.

See [../README.md](../README.md) for the full contract.
