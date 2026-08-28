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
    partials: list[Path] = []

    def fake_download(url: str, destination: Path, *, expected_size: int) -> None:
        calls.append(url)
        partials.append(destination)
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
    assert len(set(partials)) == 2
    assert all(path.parent == target.resolve() for path in partials)
    assert not list(target.glob(f".{source.name}.part-*"))


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


@pytest.mark.parametrize(
    ("update", "error"),
    [
        ({"tag": "../escape"}, "invalid tag"),
        ({"asset": r"..\escape.zip"}, "invalid asset"),
        ({"size": 0}, "invalid size"),
        ({"size": True}, "invalid size"),
        ({"download_urls": ["http://mirror.invalid/deps.zip"]}, "invalid download URL"),
        (
            {"download_urls": ["https://token@mirror.invalid/deps.zip"]},
            "invalid download URL",
        ),
    ],
)
def test_release_manifest_rejects_unsafe_paths_sizes_and_urls(
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


def test_release_manifest_requires_an_object_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "dependency_release.json"
    path.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(installer, "_RELEASE_MANIFEST", path)

    with pytest.raises(installer.InstallError, match="root must be an object"):
        installer.load_dependency_release()


def test_release_manifest_is_rejected_before_an_unbounded_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(installer, "_MAX_MANIFEST_BYTES", 64)
    path = tmp_path / "dependency_release.json"
    path.write_bytes(b"{" + b" " * 64 + b"}")
    monkeypatch.setattr(installer, "_RELEASE_MANIFEST", path)

    with pytest.raises(installer.InstallError, match="manifest exceeds 64 bytes"):
        installer.load_dependency_release()


def test_download_rejects_an_insecure_override_before_network_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_network(*args: object, **kwargs: object) -> None:
        raise AssertionError((args, kwargs))

    monkeypatch.setattr(installer.urllib.request, "urlopen", fail_network)

    with pytest.raises(installer.InstallError, match="credential-free HTTPS"):
        installer._download_one(
            "http://mirror.invalid/deps.zip",
            tmp_path / "deps.zip",
            expected_size=1,
        )


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (b"[]", "root must be an object"),
        (b"\xff", "manifest is unreadable"),
    ],
)
def test_configure_normalizes_corrupt_bundle_manifest_errors(
    tmp_path: Path,
    payload: bytes,
    error: str,
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "MANIFEST.json").write_bytes(payload)

    with pytest.raises(installer.InstallError, match=error):
        installer.configure_dependency_bundle(bundle)


def test_bundle_manifest_is_rejected_before_an_unbounded_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(installer, "_MAX_MANIFEST_BYTES", 64)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "MANIFEST.json").write_bytes(b"{" + b" " * 64 + b"}")

    with pytest.raises(installer.InstallError, match="manifest exceeds 64 bytes"):
        installer.configure_dependency_bundle(bundle)

def test_an_unreadable_manifest_path_names_its_label(tmp_path: Path) -> None:
    with pytest.raises(installer.InstallError, match="probe file is unreadable"):
        installer._read_manifest(tmp_path, label="probe file")


def test_a_release_manifest_that_is_not_json_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        installer, "_read_manifest", lambda path, *, label: b"\xff\xfe not json"
    )
    with pytest.raises(installer.InstallError, match="manifest is unreadable"):
        installer.load_dependency_release()


def test_a_url_that_cannot_even_be_split_is_unsafe() -> None:
    assert installer._is_safe_download_url("http://[bad") is False


def test_every_source_failing_sha_verification_fails_the_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, release = _bundle_zip(tmp_path / "source.zip")
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)

    def poisoned(url: str, destination: Path, *, expected_size: int) -> None:
        destination.write_bytes(b"X" * expected_size)

    monkeypatch.setattr(installer, "_download_one", poisoned)
    with pytest.raises(installer.InstallError, match="all dependency release sources failed"):
        installer.download_dependency_release(tmp_path / "downloads")
    assert not list((tmp_path / "downloads").glob(".*.part-*"))


def test_extract_refuses_a_bundle_without_a_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "no-manifest.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bundle/readme.txt", b"nothing here")
    release = {
        "schema_version": 1,
        "tag": "test-release",
        "asset": archive.name,
        "size": archive.stat().st_size,
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "never_bundles_ida": True,
        "download_urls": ["https://primary.invalid/a.zip"],
    }
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)
    with pytest.raises(installer.InstallError, match="MANIFEST.json missing"):
        installer.extract_dependency_release(archive, tmp_path / "installed")


def test_extract_refuses_a_bundle_that_does_not_disclaim_ida(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "with-ida.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "bundle/MANIFEST.json",
            json.dumps({"schema_version": 1, "never_bundles_ida": False, "included": []}),
        )
    release = {
        "schema_version": 1,
        "tag": "test-release",
        "asset": archive.name,
        "size": archive.stat().st_size,
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "never_bundles_ida": True,
        "download_urls": ["https://primary.invalid/a.zip"],
    }
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)
    with pytest.raises(installer.InstallError, match="does not prove that IDA is excluded"):
        installer.extract_dependency_release(archive, tmp_path / "installed")


def test_extract_notices_a_bundle_that_vanishes_after_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, release = _bundle_zip(tmp_path / "bundle.zip")
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)
    real_find = installer._find_bundle_root
    final = (tmp_path / "installed" / str(release["tag"])).resolve()

    def flaky(root: Path) -> Path | None:
        if root.resolve() == final:
            return None
        return real_find(root)

    monkeypatch.setattr(installer, "_find_bundle_root", flaky)
    with pytest.raises(installer.InstallError, match="disappeared after activation"):
        installer.extract_dependency_release(archive, tmp_path / "installed")


def test_extract_replaces_a_stale_install_directory_without_a_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, release = _bundle_zip(tmp_path / "bundle.zip")
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)
    stale = tmp_path / "installed" / str(release["tag"])
    stale.mkdir(parents=True)
    (stale / "leftover.txt").write_text("junk", encoding="utf-8")
    extracted = installer.extract_dependency_release(archive, tmp_path / "installed")
    assert extracted["ok"] is True
    assert extracted["cached"] is False
    assert not (stale / "leftover.txt").exists()


def test_the_interactive_ida_prompt_takes_skip_or_a_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import builtins

    monkeypatch.setattr(builtins, "input", lambda prompt="": " - ")
    assert installer._prompt_ida_path() is None
    monkeypatch.setattr(builtins, "input", lambda prompt="": f'"{tmp_path}"')
    assert installer._prompt_ida_path() == tmp_path.resolve()


def test_the_setup_summary_prints_steps_and_the_missing_ida_hint(
    capsys: pytest.CaptureFixture[str],
) -> None:
    installer.print_setup_summary(
        {
            "config_path": "/tmp/config.json",
            "steps": [
                {"ok": True, "step": "deps"},
                "not-a-dict",
                {"ok": False, "step": "doctor"},
            ],
            "doctor_ready": False,
            "ida_configured": False,
            "platform": "windows",
        }
    )
    out = capsys.readouterr().out
    assert "[OK] deps" in out
    assert "[WARN] doctor" in out
    assert "IDA 尚未配置" in out
    assert "Windows 必需" in out
