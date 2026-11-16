# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/build_index.py — the manifest validator and index generator."""
from __future__ import annotations

import json

import build_index
import pytest


def make_addon(root, name="algovoi-doc-archive-example", *, version="0.1.0", manifest=None,
               pyproject_version="0.1.0", entry_module="algovoi_doc_archive_example"):
    addon = root / name
    (addon / "src" / entry_module).mkdir(parents=True)
    (addon / "src" / entry_module / "__init__.py").write_text("", encoding="utf-8")
    (addon / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "{pyproject_version}"\n', encoding="utf-8"
    )
    body = manifest if manifest is not None else {
        "name": name,
        "version": version,
        "kind": "storage",
        "engine": {"distribution": "algovoi-doc-archive", "specifier": ">=0.1.6"},
        "entry": f"{entry_module}:Something",
    }
    (addon / "addon.json").write_text(json.dumps(body), encoding="utf-8")
    return addon


@pytest.mark.parametrize("version", ["0.1.0", "1", "2.10.3", "1.0.0rc1", "1.0.0.post2", "1.0.0.dev3",
                                     "1.0.0+a1b2", "1!0.1.0"])
def test_accepts_release_versions(version: str) -> None:
    assert build_index.VERSION_RE.match(version)


@pytest.mark.parametrize("version", ["1.0-", "1.0++", "v1.0", "1.0.0.rc1", "", "latest"])
def test_rejects_malformed_versions(version: str) -> None:
    assert not build_index.VERSION_RE.match(version)


def test_a_good_manifest_validates(tmp_path) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path)
    assert build_index.validate(addon, errors) is not None
    assert errors == []


def test_version_must_match_pyproject(tmp_path) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path, version="0.2.0", pyproject_version="0.1.0")
    build_index.validate(addon, errors)
    assert any("disagrees with pyproject.toml" in e for e in errors)


def test_unknown_keys_are_rejected(tmp_path) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path, manifest={
        "name": "algovoi-doc-archive-example",
        "version": "0.1.0",
        "kind": "storage",
        "engine": {"distribution": "algovoi-doc-archive"},
        "wheel": "https://example.invalid/x.whl",
    })
    build_index.validate(addon, errors)
    assert any("unknown keys" in e for e in errors)


def test_kind_must_be_one_of_the_enum(tmp_path) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path, manifest={
        "name": "algovoi-doc-archive-example",
        "version": "0.1.0",
        "kind": "timestamp",
        "engine": {"distribution": "algovoi-doc-archive"},
    })
    build_index.validate(addon, errors)
    assert any("kind 'timestamp' is not one of" in e for e in errors)


def test_entry_module_must_exist_in_the_tree(tmp_path) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path, manifest={
        "name": "algovoi-doc-archive-example",
        "version": "0.1.0",
        "kind": "signer",
        "engine": {"distribution": "algovoi-doc-archive"},
        "entry": "algovoi_doc_archive_nowhere:Thing",
    })
    build_index.validate(addon, errors)
    assert any("entry module" in e for e in errors)


def test_name_must_match_the_directory(tmp_path) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path, manifest={
        "name": "algovoi-doc-archive-other",
        "version": "0.1.0",
        "kind": "storage",
        "engine": {"distribution": "algovoi-doc-archive"},
    })
    build_index.validate(addon, errors)
    assert any("does not match directory" in e for e in errors)


def test_the_repository_index_is_valid_and_matches() -> None:
    errors: list[str] = []
    index = build_index.build(errors)
    assert errors == []
    assert len(index["addons"]) >= 4
    assert build_index.main(["--check"]) == 0


def test_a_directory_without_pyproject_is_an_error(tmp_path, monkeypatch) -> None:
    """A renamed or half-created addon directory must not vanish from the index silently."""
    monkeypatch.setattr(build_index, "ADDONS", tmp_path)
    make_addon(tmp_path)
    (tmp_path / "algovoi-doc-archive-typo").mkdir()
    errors: list[str] = []
    build_index.build(errors)
    assert any("no pyproject.toml" in e for e in errors)


def test_a_top_level_json_file_does_not_confuse_the_index(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(build_index, "ADDONS", tmp_path)
    make_addon(tmp_path)
    (tmp_path / "index.json").write_text("{}", encoding="utf-8")
    errors: list[str] = []
    index = build_index.build(errors)
    assert errors == []
    assert [a["name"] for a in index["addons"]] == ["algovoi-doc-archive-example"]


def _manifest_with(**extra):
    base = {
        "name": "algovoi-doc-archive-example",
        "version": "0.1.0",
        "kind": "storage",
        "engine": {"distribution": "algovoi-doc-archive"},
    }
    base.update(extra)
    return base


@pytest.mark.parametrize("url", ["http://example.invalid/x.whl", "httpjunk", "ftp://x/y.whl"])
def test_non_https_urls_are_rejected(tmp_path, url: str) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path, manifest=_manifest_with(
        wheel_url=url, wheel_sha256="a" * 64))
    build_index.validate(addon, errors)
    assert any("must be an https:// URL" in e for e in errors)


def test_wheel_url_requires_a_digest(tmp_path) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path, manifest=_manifest_with(wheel_url="https://example.invalid/x.whl"))
    build_index.validate(addon, errors)
    assert any("requires wheel_sha256" in e for e in errors)


def test_a_digest_without_a_url_is_rejected(tmp_path) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path, manifest=_manifest_with(wheel_sha256="b" * 64))
    build_index.validate(addon, errors)
    assert any("no wheel_url to bind" in e for e in errors)


@pytest.mark.parametrize("digest", ["short", "A" * 64, "g" * 64])
def test_malformed_digests_are_rejected(tmp_path, digest: str) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path, manifest=_manifest_with(
        wheel_url="https://example.invalid/x.whl", wheel_sha256=digest))
    build_index.validate(addon, errors)
    assert any("wheel_sha256 must be" in e for e in errors)


def test_a_pinned_wheel_is_accepted(tmp_path) -> None:
    errors: list[str] = []
    addon = make_addon(tmp_path, manifest=_manifest_with(
        wheel_url="https://example.invalid/x.whl", wheel_sha256="c" * 64))
    assert build_index.validate(addon, errors) is not None
    assert errors == []
