# Security policy

## Reporting a vulnerability

Do not open a public issue. Email **security@algovoi.co.uk** with a description, the affected component,
and a reproduction if you have one. We acknowledge receipt and will tell you our assessment and
timeline.

Please do not test against production systems you do not own, and do not exfiltrate data. If you are
testing the live store or an AlgoVoi host, tell us first.

## What is in scope

This repository contains documentation, the addon contract, and four addon implementations. Vulnerabilities
in the **engine or any shipped component** are in scope for the product, even though their source is not
here — report them the same way. So are vulnerabilities in the addons in `addons/`: they run inside a
customer's estate with custody of a signing key, so a defect there is a product defect.

Out of scope for this repository: typo and style issues, and vulnerabilities in third-party provider
SDKs (report those upstream, and tell us if the engine's use of them is affected).

## Key handling in addons

An addon that touches custody is held to these rules, and a pull request that breaks one is rejected
rather than reviewed:

- **No secret is persisted, logged, or formatted into a `repr`, error message or exception chain.** Key
  identifiers and lengths are fine; key bytes are not.
- **Mutable key buffers are zeroized in a `finally` block.** Where an API returns an immutable `bytes`
  that Python cannot wipe, the limitation is documented in the module docstring rather than hidden, and
  the immutable temporary is not bound to a named local.
- **Do not log frame locals from a key-handling path.** A function that wraps or unwraps a key must
  receive it, so its own frame necessarily holds it; a traceback renderer that captures local variables
  will write the key out. Run key-handling hosts with local-variable capture disabled and never attach
  frame locals from `wrap_secret_key` to a support bundle.
- **Custody blobs are authenticated and fail closed.** A truncated, mis-versioned or wrong-key blob is an
  error, never a fallback; a public key is bound in as associated data so a blob cannot be moved between
  key identities.
- **TLS verification is never disabled** and credentials are never passed as a query parameter.
- **Absence and failure are different answers**, because the engine distinguishes "missing" from
  "damaged" and a backend that collapses them corrupts the evidence model.

## What this repository must never contain

The engine and component source, the encrypted `.algv` deliverable, the extractor, licence-signing keys,
or any customer key material. `.gitignore` blocks the common shapes (`*.algv`, `*.key`, `*_sk.*`,
`*ceks*`, `.env`), but a `.gitignore` is a guard rail, not a proof — if you see any of these in a pull
request, treat it as a security report rather than a review comment.
