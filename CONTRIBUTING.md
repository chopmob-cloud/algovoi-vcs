# Contributing

Thanks for helping. This repository holds the public documentation, the addon contract, and four
first-party addon implementations. The engine itself is developed separately and its source is not here.

## What we accept

- **Documentation corrections** — anything that disagrees with the shipped product. If a page here
  disagrees with <https://docs.algovoi.co.uk>, the rendered docs win; tell us which is wrong.
- **Addon contract clarifications** — a real integration that found a gap in
  [addons/README.md](addons/README.md). Please include the engine version you tested.
- **Addons** — either an in-tree first-party addon under `addons/<distribution-name>/`, or a community
  listing under `community/` with your manifest (see `addons/schema/addon.json`), a README, and a link to
  your published wheel. We do not vendor third-party code.

## In-tree addon requirements

A pull request adding or changing an addon is accepted when all of these hold:

1. **The manifest is valid and current.** `addon.json` matches `addons/schema/addon.json` and its version
   agrees with `pyproject.toml`. Run `python tools/build_index.py` and commit `addons/index.json`; CI runs
   `--check` and fails on drift.
2. **It imports without the engine and without the provider SDK.** The engine is not on a public index,
   so it is not a dependency; implement the Protocol structurally and declare the target in `addon.json`.
   A provider SDK belongs in `[project.optional-dependencies]` and is imported inside the function that
   needs it, with a `ModuleNotFoundError` translated into a message naming the extra.
3. **It is scored by the conformance suite.** Add a factory to
   `addons/conformance/tests/test_contract.py`; a storage factory takes no arguments, a signer factory
   takes `(public_key, secret_key)`.
4. **The gate is green.** `python -m pytest -q`, `ruff check addons tools`, `bandit -q -r addons/*/src tools`.
5. **The commit is signed off.** `git commit -s` adds the DCO line; contributions are accepted under the
   Developer Certificate of Origin 1.1, and the repository licence is Apache-2.0.

## What we do not accept

- Copies or excerpts of engine or component source.
- Bundles, wheels of first-party commercial components, licence files, or key material.
- An addon that persists, logs or formats secret key material — see [SECURITY.md](SECURITY.md).
- Changes that advertise a price: prices live on the store, and a number in this repo would go stale.

## Ground rules

- UK spelling in documentation.
- A claim about behaviour should name the version it applies to.
- Do not add a Protocol method or field to the docs without checking it against the installed package;
  the interfaces here are transcribed from a specific release, not designed here.
