# Contributing

Thanks for helping. This repository is documentation and addon interfaces; the product itself is
developed separately and its source is not here.

## What we accept

- **Documentation corrections** — anything that disagrees with the shipped product. If a page here
  disagrees with <https://docs.algovoi.co.uk>, the rendered docs win; tell us which is wrong.
- **Addon contract clarifications** — a real integration that found a gap in
  [addons/README.md](addons/README.md). Please include the engine version you tested.
- **Community addon listings** — a directory under `community/` with your manifest
  (see `addons/schema/addon.json`), a README, and a link to your published wheel. We do not vendor
  third-party code.

## What we do not accept

- Copies or excerpts of engine or component source.
- Bundles, wheels of first-party components, licence files, or key material.
- Changes that advertise a price: prices live on the store, and a number in this repo would go stale.

## Ground rules

- UK spelling in documentation.
- A claim about behaviour should name the version it applies to.
- Do not add a Protocol method or field to the docs without checking it against the installed package;
  the interfaces here are transcribed from a specific release, not designed here.
