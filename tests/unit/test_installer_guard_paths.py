"""Guard and edge-branch coverage for the one-click installer.

``test_installer.py`` / ``test_installer_setup.py`` cover manifest validation,
the download transport, safe extraction, bundle configuration and the main
orchestration happy paths. These drive the remaining fail-closed and edge
branches: an unreadable release manifest, an undecodable manifest body, a URL
``urlsplit`` cannot parse, the download SHA-256 mismatch, the three
extraction guards (missing manifest, stale destination, vanished bundle), the
interactive IDA prompt, and the non-dict step skipped by the summary printer.
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.installer as installer
from tests.unit.test_installer_setup import _install_common_stubs, _set_platform

InstallError = installer.InstallError


def _make_zip(path: Path, entries: dict[str, bytes]) -> dict[str, Any]:
    """Write a zip and return a release manifest whose SHA/size match it."""

    with zipfile.ZipFile(path, "w") as bundle:
        for name, data in entries.items():
            bundle.writestr(name, data)
    return {
        "schema_version": 1,
        "tag": "t",
        "asset": path.name,
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "never_bundles_ida": True,
        "download_urls": ["https://mirror.test/deps.zip"],
    }


def _valid_bundle_zip(path: Path) -> dict[str, Any]:
    manifest = {
        "schema_version": 1,
        "never_bundles_ida": True,
        "included": [],
        "missing": [],
    }
    return _make_zip(path, {"bundle/MANIFEST.json": json.dumps(manifest).encode("utf-8")})


# --------------------------------------------------------------------------
# _read_manifest / load_dependency_release fail-closed reads.
# --------------------------------------------------------------------------


def test_read_manifest_reports_an_unreadable_file(tmp_path: Path) -> None:
    with pytest.raises(InstallError, match="widget is unreadable"):
        installer._read_manifest(tmp_path / "missing.json", label="widget")


def test_load_release_manifest_rejects_undecodable_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "dependency_release.json"
    path.write_bytes(b"\xff\xfe not valid utf-8")
    monkeypatch.setattr(installer, "_RELEASE_MANIFEST", path)

    with pytest.raises(InstallError, match="release manifest is unreadable"):
        installer.load_dependency_release()


# --------------------------------------------------------------------------
# _is_safe_download_url urlsplit failure.
# --------------------------------------------------------------------------


def test_is_safe_download_url_rejects_a_url_urlsplit_cannot_parse() -> None:
    # An unbalanced IPv6 bracket makes urlsplit raise ValueError before any of
    # the scheme/host checks run.
    assert installer._is_safe_download_url("https://[::1") is False


# --------------------------------------------------------------------------
# download_dependency_release SHA-256 mismatch.
# --------------------------------------------------------------------------


def test_download_release_reports_a_sha_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = {
        "schema_version": 1,
        "tag": "t",
        "asset": "deps.zip",
        "size": 4,
        "sha256": "0" * 64,
        "never_bundles_ida": True,
        "download_urls": ["https://a.test/x.zip"],
    }
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)

    def wrong_bytes(url: str, destination: Path, *, expected_size: int) -> None:
        # Correct size so the size gate passes, but content whose hash cannot
        # match the pinned all-zero digest.
        destination.write_bytes(b"AAAA")

    monkeypatch.setattr(installer, "_download_one", wrong_bytes)

    with pytest.raises(InstallError, match="all dependency release sources failed") as caught:
        installer.download_dependency_release(tmp_path / "dl")
    assert "SHA-256 mismatch" in str(caught.value)


# --------------------------------------------------------------------------
# extract_dependency_release guards.
# --------------------------------------------------------------------------


def test_extract_rejects_a_bundle_without_a_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "a.zip"
    release = _make_zip(archive, {"payload/data.bin": b"x"})
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)

    with pytest.raises(InstallError, match="MANIFEST.json missing"):
        installer.extract_dependency_release(archive, tmp_path / "installed")


def test_extract_replaces_a_stale_final_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "a.zip"
    release = _valid_bundle_zip(archive)
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)

    parent = tmp_path / "installed"
    stale = parent / "t"  # matches release["tag"], but has no valid bundle root
    stale.mkdir(parents=True)
    (stale / "junk.txt").write_text("old", encoding="utf-8")

    result = installer.extract_dependency_release(archive, parent)

    assert result["ok"] is True
    assert result["cached"] is False
    # The stale tree was removed before activation, so its junk is gone.
    assert not (parent / "t" / "junk.txt").exists()
    assert Path(str(result["root"])).name == "bundle"


def test_extract_detects_a_bundle_that_vanishes_after_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "a.zip"
    release = _valid_bundle_zip(archive)
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)

    # No-op the activation move so the final directory never materialises; the
    # post-activation bundle-root check then fails closed. installer calls the
    # shared os.replace, so patching it here is what the helper observes.
    def _noop_replace(src: Any, dst: Any) -> None:
        return None

    monkeypatch.setattr(os, "replace", _noop_replace)

    with pytest.raises(InstallError, match="disappeared after activation"):
        installer.extract_dependency_release(archive, tmp_path / "installed")


# --------------------------------------------------------------------------
# _prompt_ida_path interactive input.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("answer", ["", "-", "skip"])
def test_prompt_ida_path_returns_none_for_skip_answers(
    answer: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: answer)
    assert installer._prompt_ida_path() is None


def test_prompt_ida_path_resolves_a_supplied_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: f'  "{tmp_path}"  ')
    assert installer._prompt_ida_path() == tmp_path.expanduser().resolve()


# --------------------------------------------------------------------------
# run_one_click_setup interactive prompt branch.
# --------------------------------------------------------------------------


def test_run_one_click_setup_prompts_for_ida_when_interactive_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_platform(monkeypatch, "nt")
    _install_common_stubs(monkeypatch, tmp_path)

    prompted = {"count": 0}

    def fake_prompt() -> Path | None:
        prompted["count"] += 1
        return None

    monkeypatch.setattr(installer, "_prompt_ida_path", fake_prompt)

    result = installer.run_one_click_setup(non_interactive=False, download_release=False)

    assert prompted["count"] == 1
    assert result["ida_configured"] is False


# --------------------------------------------------------------------------
# print_setup_summary non-dict step.
# --------------------------------------------------------------------------


def test_print_setup_summary_skips_non_dict_steps(capsys: pytest.CaptureFixture[str]) -> None:
    installer.print_setup_summary(
        {
            "config_path": "/tmp/config.json",
            "platform": "linux",
            "ida_configured": True,
            "doctor_ready": True,
            "steps": [{"step": "generate_mcp", "ok": True}, "not-a-dict", 123],
        }
    )
    out = capsys.readouterr().out
    assert "[OK] generate_mcp" in out
