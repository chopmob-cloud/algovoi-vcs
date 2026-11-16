#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build and check ``addons/index.json`` from the per-addon manifests.

Every addon directory carries an ``addon.json`` conforming to ``addons/schema/addon.json``. This tool
validates each manifest, cross-checks it against the package's own ``pyproject.toml`` and source tree,
and writes the aggregate index the console and store consume.

Usage::

    python tools/build_index.py            # write addons/index.json
    python tools/build_index.py --check    # exit 1 if missing, invalid or stale

Standard library only, so CI can run it before anything is installed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADDONS = ROOT / "addons"
INDEX = ADDONS / "index.json"

ALLOWED_KEYS = {
    "name",
    "version",
    "kind",
    "engine",
    "entry",
    "requires",
    "notes",
    "homepage",
    "wheel_url",
    "wheel_sha256",
}
KINDS = {"storage", "signer", "custody"}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
# PEP 440 public versions only: N(.N)* with an optional pre/post/dev tail. Deliberately not a full
# PEP 440 parser — this rejects the malformed shapes that would break a wheel name at build time.
VERSION_RE = re.compile(
    r"^(?:\d+!)?\d+(\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[A-Za-z0-9.]+)?$"
)
ENTRY_RE = re.compile(r"^[A-Za-z_][\w.]*:[A-Za-z_]\w*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ENGINE_DIST = "algovoi-doc-archive"
#: Directories under ``addons/`` that are not addons. Anything else must carry a ``pyproject.toml``:
#: a renamed or half-created directory would otherwise vanish from the index without a word.
NOT_ADDONS = {"schema", "template", "conformance", "__pycache__"}


def _fail(errors: list[str], path: Path, message: str) -> None:
    try:
        where = path.relative_to(ROOT)
    except ValueError:  # a caller validating a tree outside this repository (tests do)
        where = path
    errors.append(f"{where}: {message}")


def _pyproject_version(path: Path) -> str | None:
    """Read ``version`` out of a PEP 621 project table without a TOML parser (3.11 has tomllib)."""
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - 3.11+ always has tomllib
        return None
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    value = data.get("project", {}).get("version")
    return value if isinstance(value, str) else None


def validate(addon_dir: Path, errors: list[str]) -> dict | None:
    manifest_path = addon_dir / "addon.json"
    if not manifest_path.is_file():
        _fail(errors, addon_dir, "missing addon.json")
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail(errors, manifest_path, f"invalid JSON: {exc}")
        return None
    if not isinstance(manifest, dict):
        _fail(errors, manifest_path, "manifest must be a JSON object")
        return None

    unknown = set(manifest) - ALLOWED_KEYS
    if unknown:
        _fail(errors, manifest_path, f"unknown keys: {sorted(unknown)}")
    for required in ("name", "version", "kind", "engine"):
        if required not in manifest:
            _fail(errors, manifest_path, f"missing required key {required!r}")

    name = manifest.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        _fail(errors, manifest_path, f"name {name!r} does not match {NAME_RE.pattern}")
    elif name != addon_dir.name:
        _fail(errors, manifest_path, f"name {name!r} does not match directory {addon_dir.name!r}")

    version = manifest.get("version")
    if not isinstance(version, str) or not VERSION_RE.match(version):
        _fail(errors, manifest_path, f"version {version!r} is not PEP 440-ish")

    kind = manifest.get("kind")
    if kind not in KINDS:
        _fail(errors, manifest_path, f"kind {kind!r} is not one of {sorted(KINDS)}")

    engine = manifest.get("engine")
    if not isinstance(engine, dict):
        _fail(errors, manifest_path, "engine must be an object")
    else:
        if set(engine) - {"distribution", "specifier"}:
            _fail(errors, manifest_path, f"unknown engine keys: {sorted(set(engine))}")
        if engine.get("distribution") != ENGINE_DIST:
            _fail(errors, manifest_path, f"engine.distribution must be {ENGINE_DIST!r}")

    entry = manifest.get("entry")
    if entry is not None:
        if not isinstance(entry, str) or not ENTRY_RE.match(entry):
            _fail(errors, manifest_path, "entry must look like 'pkg.mod:ClassName'")
        else:
            module = entry.split(":", 1)[0]
            base = addon_dir / "src"
            candidates = [
                base.joinpath(*module.split(".")).with_suffix(".py"),
                base.joinpath(*module.split("."), "__init__.py"),
            ]
            if not any(c.is_file() for c in candidates):
                _fail(errors, manifest_path, f"entry module {module!r} not found under src/")

    requires = manifest.get("requires")
    if requires is not None and (
        not isinstance(requires, list) or not all(isinstance(r, str) for r in requires)
    ):
        _fail(errors, manifest_path, "requires must be a list of strings")

    for key in ("homepage", "wheel_url"):
        value = manifest.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not value.startswith("https://"):
            # https only: an index entry that resolves over plaintext installs whatever the network
            # hands back, and "httpjunk" satisfies a bare startswith("http") check.
            _fail(errors, manifest_path, f"{key} must be an https:// URL")

    wheel_url = manifest.get("wheel_url")
    wheel_sha = manifest.get("wheel_sha256")
    if wheel_sha is not None:
        if not isinstance(wheel_sha, str) or not SHA256_RE.match(wheel_sha):
            _fail(errors, manifest_path, "wheel_sha256 must be 64 lower-case hex characters")
        if wheel_url is None:
            _fail(errors, manifest_path, "wheel_sha256 is set but there is no wheel_url to bind")
    elif wheel_url is not None:
        # A URL without a digest binds the manifest to whatever the host serves today.
        _fail(errors, manifest_path, "wheel_url requires wheel_sha256 so the wheel is pinned by bytes")

    pyproject = addon_dir / "pyproject.toml"
    if not pyproject.is_file():
        _fail(errors, addon_dir, "missing pyproject.toml")
    else:
        declared = _pyproject_version(pyproject)
        if declared is None:
            _fail(errors, pyproject, "could not read project.version")
        elif isinstance(version, str) and declared != version:
            _fail(
                errors,
                manifest_path,
                f"version {version!r} disagrees with pyproject.toml {declared!r}",
            )

    return manifest


def build(errors: list[str]) -> dict:
    manifests: list[dict] = []
    for addon_dir in sorted(p for p in ADDONS.iterdir() if p.is_dir()):
        if addon_dir.name in NOT_ADDONS or addon_dir.name.startswith("."):
            continue
        if not (addon_dir / "pyproject.toml").is_file():
            _fail(
                errors,
                addon_dir,
                "directory is not an addon: no pyproject.toml (rename it, or add it to NOT_ADDONS)",
            )
            continue
        manifest = validate(addon_dir, errors)
        if manifest is not None:
            manifests.append(manifest)
    if not manifests:
        errors.append("addons/: no manifests found")
    names = [m.get("name") for m in manifests]
    duplicates = {n for n in names if isinstance(n, str) and names.count(n) > 1}
    if duplicates:
        errors.append(f"addons/: duplicate names {sorted(duplicates)}")
    return {
        "schema": "https://algovoi.co.uk/schemas/vcs-addon-v1.json",
        "schema_version": 1,
        "engine": {"distribution": ENGINE_DIST, "specifier": ">=0.1.6"},
        "addons": sorted(manifests, key=lambda m: str(m.get("name"))),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify index.json is current")
    args = parser.parse_args(argv)

    errors: list[str] = []
    index = build(errors)
    if errors:
        for error in errors:
            print(f"INVALID {error}", file=sys.stderr)
        return 1

    rendered = json.dumps(index, indent=2) + "\n"
    if args.check:
        if not INDEX.is_file():
            print(f"STALE {INDEX.relative_to(ROOT)} is missing", file=sys.stderr)
            return 1
        if INDEX.read_text(encoding="utf-8") != rendered:
            print(
                f"STALE {INDEX.relative_to(ROOT)} does not match the manifests; "
                "run python tools/build_index.py",
                file=sys.stderr,
            )
            return 1
        print(f"OK {len(index['addons'])} addon manifests, index current")
        return 0

    INDEX.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"wrote {INDEX.relative_to(ROOT)} with {len(index['addons'])} addons")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
