# Security policy

## Reporting a vulnerability

Do not open a public issue. Email **security@algovoi.co.uk** with a description, the affected component,
and a reproduction if you have one. We acknowledge receipt and will tell you our assessment and
timeline.

Please do not test against production systems you do not own, and do not exfiltrate data. If you are
testing the live store or an AlgoVoi host, tell us first.

## What is in scope

This repository contains documentation and an addon template. Vulnerabilities in the **engine or any
shipped component** are in scope for the product, even though their source is not here — report them the
same way.

Out of scope for this repository: typo and style issues, and vulnerabilities in third-party provider
SDKs (report those upstream, and tell us if the engine's use of them is affected).

## What this repository must never contain

The engine and component source, the encrypted `.algv` deliverable, the extractor, licence-signing keys,
or any customer key material. `.gitignore` blocks the common shapes (`*.algv`, `*.key`, `*_sk.*`,
`*ceks*`, `.env`), but a `.gitignore` is a guard rail, not a proof — if you see any of these in a pull
request, treat it as a security report rather than a review comment.
