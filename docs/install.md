# Install

The flow is **pay, download, key**. You buy a perpetual licence from the
[suite store](https://api.algovoi.co.uk/suite-store), receive a download link and a Falcon-1024 bundle
licence, then extract offline.

## 1. Prerequisites

```bash
python -m pip install "cryptography>=50.0.0" "pqcrypto>=0.4.0,<1.0" \
    "rfc8785>=0.1.4" "shamir-mnemonic>=0.3.0" "fastapi>=0.110,<1.0" "uvicorn>=0.29,<1.0" httpx
```

The pins are load-bearing, not cosmetic:

- **`pqcrypto<1.0`** — 1.0.0 removed the ML-KEM-1024 and Falcon-1024 APIs this suite uses. An unbounded
  install succeeds and then silently breaks post-quantum signing and at-rest encryption at first use.
- **`cryptography>=50.0.0`** — earlier releases carry published advisories.

## 2. Extract and install (offline, verified)

Save your licence key to `licence.key`, then:

```bash
python algovoi_unbundle.py --license @licence.key --out ./algovoi --install bundle.algv
```

The extractor verifies the licence against the bundle before writing a file, and verifies each wheel as
it unpacks, so a tampered deliverable fails before anything lands on disk.

## 3. Run

```bash
export ALGOVOI_LICENSE_KEY="$(cat licence.key)"
algovoi-substrate2-controlplane                                       # control panel + policy bridge
uvicorn algovoi_command_center.app:create_app --factory --port 8200   # Compliance Command Center
```

One bundle licence runs every component in the estate. Component packages that carry their own gate
compare the licence's `package` to their own distribution name — licences are per package, so a
deployment that shares one key across separately gated packages half-starts.

## Air-gap notes

- No PyPI access is required after the prerequisite line: the bundle carries its own wheel set.
- No phone-home and no activation server; the licence is verified locally against the bundle.
- RFC-3161 timestamping needs a TSA reachable at write time. When air-gapped, the chain records a signed
  fallback and marks the timestamp accordingly.

## Verifying without AlgoVoi software

Evidence is verifiable with the public key and the chain alone. The free `av-reseal-verify` tool
(PyPI, Apache-2.0) checks seals and signatures; nothing in the trust path requires AlgoVoi.
