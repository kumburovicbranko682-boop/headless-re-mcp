from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.installer as installer


def _bundle_zip(path: Path, *, traversal: bool = False) -> tuple[Path, dict[str, Any]]:
    included = [
        {"id": "x64dbg-x64", "path": "runtime/x64dbg-x64/headless.exe"},
        {"id": "x64dbg-x86", "path": "runtime/x64dbg-x86/headless.exe"},
        {"id": "upx", "path": "tools/upx/upx.exe"},
    ]
    manifest = {
        "schema_version": 1,
        "never_bundles_ida": True,
        "included": included,
        "missing": ["die"],
    }
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("bundle/MANIFEST.json", json.dumps(manifest))
        for item in included:
            bundle.writestr(f"bundle/{item['path']}", b"MZ-test")
        if traversal:
            bundle.writestr("../escaped.txt", b"no")
    release = {
        "schema_version": 1,
        "tag": "test-release",
        "asset": path.name,
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "never_bundles_ida": True,
        "download_urls": ["https://primary.invalid/a.zip", "https://mirror.invalid/a.zip"],
    }
    return path, release


def test_release_manifest_is_pinned_and_has_tested_mirror() -> None:
    release = installer.load_dependency_release()
    assert release["tag"] == "v0.1.0-deps"
    assert release["asset"] == "headless-re-mcp-deps-win.x64.zip"
    assert release["sha256"] == "b0172b140f2f9e8d49ad02890188afb2f5032073f1bca6b36b4d09523cce9263"
    assert any(str(url).startswith("https://ghproxy.net/") for url in release["download_urls"])
    assert release["never_bundles_ida"] is True


def test_download_uses_mirror_then_sha_verifies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, release = _bundle_zip(tmp_path / "source.zip")
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)
    calls: list[str] = []

    def fake_download(url: str, destination: Path, *, expected_size: int) -> None:
        calls.append(url)
        assert expected_size == source.stat().st_size
        if len(calls) == 1:
            raise OSError("primary unavailable")
        destination.write_bytes(source.read_bytes())

    monkeypatch.setattr(installer, "_download_one", fake_download)
    target = tmp_path / "downloads"
    result = installer.download_dependency_release(target)
    assert result["ok"] is True
    assert result["source"] == release["download_urls"][1]
    assert len(result["attempts"]) == 1
    assert Path(result["archive"]).read_bytes() == source.read_bytes()


def test_extract_and_configure_validated_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, release = _bundle_zip(tmp_path / "bundle.zip")
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)
    extracted = installer.extract_dependency_release(archive, tmp_path / "installed")
    captured: dict[str, Path] = {}

    def fake_update(values: dict[str, Path]) -> Path:
        captured.update(values)
        return tmp_path / "config.json"

    monkeypatch.setattr(installer, "update_config_values", fake_update)
    configured = installer.configure_dependency_bundle(Path(extracted["root"]))
    assert configured["ok"] is True
    assert set(captured) == {"x64dbg_headless_x64", "x64dbg_headless_x86", "upx"}
    assert all(path.is_file() for path in captured.values())
    assert configured["missing_optional"] == ["die"]


def test_extract_rejects_zip_slip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, release = _bundle_zip(tmp_path / "bad.zip", traversal=True)
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)
    with pytest.raises(installer.InstallError, match="escapes root"):
        installer.extract_dependency_release(archive, tmp_path / "installed")
    assert not (tmp_path / "escaped.txt").exists()

