"""Integrity and fail-closed coverage for the dependency-release installer.

``test_installer`` pins the manifest shape, the mirror fallback and zip-slip.
What it leaves untested is exactly the machinery that decides whether a
downloaded or on-disk dependency tree is trustworthy:

* the download loop's server-honesty checks (HTTP status, Content-Length,
  over-size abort, short read) -- a mirror that lies about its payload must
  not produce a "successful" install;
* the archive bombs ``_safe_extract`` must refuse before ``extractall``
  (file count, expansion size, symlinks);
* the cached-archive and cached-bundle short-circuits, and the SHA gate that
  discards a stale or corrupt cache;
* the bundle validation in ``configure_dependency_bundle`` -- IDA-exclusion
  proof, path containment, missing headless runtime.

None of these touch the network or the real pinned manifest: the release is
substituted and every payload is built in ``tmp_path``.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.installer as installer


# --------------------------------------------------------------------------- #
# _download_one: the server must not be able to lie about the payload size    #
# --------------------------------------------------------------------------- #
class _FakeHeaders:
    def __init__(self, content_length: str | None) -> None:
        self._content_length = content_length

    def get(self, key: str, default: Any = None) -> Any:
        if key == "Content-Length":
            return self._content_length
        return default


class _FakeResponse:
    def __init__(
        self, *, status: int = 200, content_length: str | None = None, chunks: list[bytes]
    ) -> None:
        self.status = status
        self.headers = _FakeHeaders(content_length)
        self._chunks = list(chunks)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        del size
        return self._chunks.pop(0) if self._chunks else b""


def _patch_urlopen(monkeypatch: pytest.MonkeyPatch, response: _FakeResponse) -> None:
    def _fake(
        request: object, timeout: float | None = None, context: object = None
    ) -> _FakeResponse:
        del request, timeout, context
        return response

    monkeypatch.setattr(urllib.request, "urlopen", _fake)


def test_download_rejects_non_200_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_urlopen(monkeypatch, _FakeResponse(status=404, chunks=[b"ignored"]))
    with pytest.raises(installer.InstallError, match="HTTP 404"):
        installer._download_one(
            "https://mirror.invalid/a.zip", tmp_path / "out.bin", expected_size=7
        )


def test_download_rejects_content_length_header_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_urlopen(monkeypatch, _FakeResponse(content_length="999", chunks=[b"AAAA"]))
    with pytest.raises(installer.InstallError, match="size header mismatch"):
        installer._download_one(
            "https://mirror.invalid/a.zip", tmp_path / "out.bin", expected_size=4
        )


def test_download_aborts_when_body_exceeds_pinned_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mirror handing back more than the pinned size is stopped mid-stream."""
    _patch_urlopen(monkeypatch, _FakeResponse(chunks=[b"AAAAAAAA"]))
    with pytest.raises(installer.InstallError, match="exceeded the pinned release size"):
        installer._download_one(
            "https://mirror.invalid/a.zip", tmp_path / "out.bin", expected_size=4
        )


def test_download_rejects_a_short_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_urlopen(monkeypatch, _FakeResponse(chunks=[b"AA"]))
    with pytest.raises(installer.InstallError, match="incomplete"):
        installer._download_one(
            "https://mirror.invalid/a.zip", tmp_path / "out.bin", expected_size=4
        )


def test_download_writes_exactly_the_pinned_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_urlopen(monkeypatch, _FakeResponse(chunks=[b"AB", b"CD"]))
    out = tmp_path / "out.bin"
    installer._download_one("https://mirror.invalid/a.zip", out, expected_size=4)
    assert out.read_bytes() == b"ABCD"


# --------------------------------------------------------------------------- #
# _safe_extract: refuse archive bombs before extractall                       #
# --------------------------------------------------------------------------- #
def test_safe_extract_refuses_too_many_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(installer, "_MAX_ARCHIVE_FILES", 1)
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("a.txt", b"x")
        bundle.writestr("b.txt", b"y")
    dest = tmp_path / "dest"
    with pytest.raises(installer.InstallError, match="too many files"):
        installer._safe_extract(archive, dest)
    assert not dest.exists()


def test_safe_extract_refuses_expansion_bomb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(installer, "_MAX_EXTRACTED_BYTES", 4)
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("big.bin", b"A" * 16)
    with pytest.raises(installer.InstallError, match="expands beyond"):
        installer._safe_extract(archive, tmp_path / "dest")


def test_safe_extract_refuses_symlink_members(tmp_path: Path) -> None:
    archive = tmp_path / "link.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        info = zipfile.ZipInfo("evil.link")
        info.external_attr = 0o120777 << 16
        bundle.writestr(info, b"/etc/passwd")
    with pytest.raises(installer.InstallError, match="symlink"):
        installer._safe_extract(archive, tmp_path / "dest")


# --------------------------------------------------------------------------- #
# download_dependency_release: cache honesty                                  #
# --------------------------------------------------------------------------- #
def _release_for(archive: Path, *, urls: list[str] | None = None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "tag": "test-release",
        "asset": archive.name,
        "size": archive.stat().st_size,
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "never_bundles_ida": True,
        "download_urls": urls or ["https://a.invalid/x.zip", "https://b.invalid/x.zip"],
    }


def test_download_returns_a_matching_cache_without_touching_the_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "deps"
    root.mkdir()
    archive = root / "deps.zip"
    archive.write_bytes(b"CACHED-PAYLOAD")
    monkeypatch.setattr(installer, "load_dependency_release", lambda: _release_for(archive))

    def _boom(*a: object, **k: object) -> None:
        raise AssertionError("cached archive must not be re-downloaded")

    monkeypatch.setattr(installer, "_download_one", _boom)
    result = installer.download_dependency_release(root)
    assert result["cached"] is True
    assert Path(result["archive"]) == archive


def test_download_discards_a_same_size_but_corrupt_cache_then_refetches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "deps"
    root.mkdir()
    archive = root / "deps.zip"
    good = b"G" * 32
    # The stale file matches the pinned size but not the hash: it must be
    # discarded rather than trusted, then replaced by a fresh download.
    archive.write_bytes(b"B" * 32)
    release = {
        "schema_version": 1,
        "tag": "test-release",
        "asset": "deps.zip",
        "size": 32,
        "sha256": hashlib.sha256(good).hexdigest(),
        "never_bundles_ida": True,
        "download_urls": ["https://a.invalid/x.zip"],
    }
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)

    def _fake_download(url: str, destination: Path, *, expected_size: int) -> None:
        del url, expected_size
        destination.write_bytes(good)

    monkeypatch.setattr(installer, "_download_one", _fake_download)
    result = installer.download_dependency_release(root)
    assert result["cached"] is False
    assert archive.read_bytes() == good


def test_download_raises_when_every_source_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "src.zip"
    archive.write_bytes(b"payload")
    release = _release_for(archive, urls=["https://a.invalid/x.zip", "https://b.invalid/x.zip"])
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)

    def _always_fail(url: str, destination: Path, *, expected_size: int) -> None:
        del destination, expected_size
        raise OSError(f"unreachable {url}")

    monkeypatch.setattr(installer, "_download_one", _always_fail)
    with pytest.raises(installer.InstallError, match="all dependency release sources failed"):
        installer.download_dependency_release(tmp_path / "deps")


# --------------------------------------------------------------------------- #
# extract_dependency_release: archive gate + cache short-circuit              #
# --------------------------------------------------------------------------- #
def _valid_bundle_zip(path: Path, *, never_bundles_ida: bool = True) -> None:
    manifest = {
        "schema_version": 1,
        "never_bundles_ida": never_bundles_ida,
        "included": [{"id": "upx", "path": "upx.exe"}],
        "missing": [],
    }
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("bundle/MANIFEST.json", json.dumps(manifest))
        bundle.writestr("bundle/upx.exe", b"MZ")


def test_extract_refuses_a_missing_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "nope.zip"
    archive.write_bytes(b"x")
    monkeypatch.setattr(installer, "load_dependency_release", lambda: _release_for(archive))
    with pytest.raises(installer.InstallError, match="not found"):
        installer.extract_dependency_release(tmp_path / "absent.zip", tmp_path / "out")


def test_extract_refuses_a_sha_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "real.zip"
    _valid_bundle_zip(archive)
    release = _release_for(archive)
    release["sha256"] = "0" * 64
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)
    with pytest.raises(installer.InstallError, match="SHA-256 mismatch"):
        installer.extract_dependency_release(archive, tmp_path / "out")


def test_extract_returns_the_existing_bundle_as_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "real.zip"
    _valid_bundle_zip(archive)
    monkeypatch.setattr(installer, "load_dependency_release", lambda: _release_for(archive))
    parent = tmp_path / "installed"
    already = parent / "test-release"
    already.mkdir(parents=True)
    (already / "MANIFEST.json").write_text(json.dumps({"never_bundles_ida": True}))
    result = installer.extract_dependency_release(archive, parent)
    assert result["cached"] is True
    assert Path(result["root"]) == already.resolve()


def test_extract_refuses_a_bundle_that_does_not_exclude_ida(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "real.zip"
    _valid_bundle_zip(archive, never_bundles_ida=False)
    monkeypatch.setattr(installer, "load_dependency_release", lambda: _release_for(archive))
    with pytest.raises(installer.InstallError, match="IDA is excluded"):
        installer.extract_dependency_release(archive, tmp_path / "out")


# --------------------------------------------------------------------------- #
# configure_dependency_bundle: manifest / path / runtime validation           #
# --------------------------------------------------------------------------- #
def _write_bundle(
    root: Path,
    *,
    included: Any,
    never_bundles_ida: bool = True,
    files: tuple[str, ...] = (),
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "never_bundles_ida": never_bundles_ida,
        "included": included,
        "missing": [],
    }
    (root / "MANIFEST.json").write_text(json.dumps(manifest))
    for rel in files:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"MZ")


def test_configure_refuses_a_missing_manifest(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(installer.InstallError, match="MANIFEST.json not found"):
        installer.configure_dependency_bundle(empty)


def test_configure_refuses_a_bundle_that_may_contain_ida(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, included=[], never_bundles_ida=False)
    with pytest.raises(installer.InstallError, match="may contain IDA"):
        installer.configure_dependency_bundle(root)


def test_configure_refuses_a_non_list_included(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, included="not-a-list")
    with pytest.raises(installer.InstallError, match="included list is invalid"):
        installer.configure_dependency_bundle(root)


def test_configure_rejects_a_path_that_escapes_the_bundle(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, included=[{"id": "upx", "path": "../escape.exe"}])
    with pytest.raises(installer.InstallError, match="invalid executable paths"):
        installer.configure_dependency_bundle(root)


def test_configure_rejects_a_declared_path_with_no_file(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, included=[{"id": "upx", "path": "ghost.exe"}])
    with pytest.raises(installer.InstallError, match="invalid executable paths"):
        installer.configure_dependency_bundle(root)


def test_configure_requires_both_headless_runtimes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unknown ids and non-dict entries are skipped, but a bundle without the
    x86 and x64 headless runtimes cannot be activated."""
    root = tmp_path / "bundle"
    _write_bundle(
        root,
        included=[
            "junk-entry",
            {"id": "mystery", "path": "whatever"},
            {"id": "upx", "path": "upx.exe"},
        ],
        files=("upx.exe",),
    )
    monkeypatch.setattr(installer, "update_config_values", lambda values: tmp_path / "config.json")
    with pytest.raises(installer.InstallError, match="missing an x86 or x64 headless runtime"):
        installer.configure_dependency_bundle(root)


# --------------------------------------------------------------------------- #
# load_dependency_release: remaining manifest validations                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("update", "error"),
    [
        ({"schema_version": 2}, "unsupported dependency release manifest"),
        ({"sha256": "abc"}, "invalid SHA-256"),
        ({"sha256": "z" * 64}, "invalid SHA-256"),
        ({"never_bundles_ida": False}, "must explicitly exclude IDA"),
        ({"download_urls": []}, "has no download URLs"),
        ({"download_urls": "https://a.invalid/x.zip"}, "has no download URLs"),
    ],
)
def test_load_release_rejects_unsafe_schema_hash_and_urls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    update: dict[str, object],
    error: str,
) -> None:
    manifest: dict[str, object] = {
        "schema_version": 1,
        "tag": "release",
        "asset": "deps.zip",
        "size": 1,
        "sha256": "0" * 64,
        "never_bundles_ida": True,
        "download_urls": ["https://mirror.invalid/deps.zip"],
    }
    manifest.update(update)
    path = tmp_path / "dependency_release.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(installer, "_RELEASE_MANIFEST", path)
    with pytest.raises(installer.InstallError, match=error):
        installer.load_dependency_release()
