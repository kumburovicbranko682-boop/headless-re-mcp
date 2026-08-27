"""Installer paths: manifest guards, extraction edges and the one-click flow.

Every network, config-write and doctor seam is patched in the installer (or
the module it imports from at call time), so the flow logic runs for real
while nothing downloads, persists, or probes the host.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.config_generate as config_generate
import headless_re_mcp.doctor as doctor_mod
import headless_re_mcp.installer as installer
import headless_re_mcp.web.setup as web_setup
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import Probe, ProbeStatus
from headless_re_mcp.installer import (
    InstallError,
    _is_safe_download_url,
    _prompt_ida_path,
    _read_manifest,
    _sha256,
    extract_dependency_release,
    print_setup_summary,
    run_one_click_setup,
)


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    from dataclasses import replace

    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides) if overrides else base


# --- manifest guards -----------------------------------------------------------


def test_an_unreadable_manifest_is_an_install_error(tmp_path: Path) -> None:
    with pytest.raises(InstallError, match="unreadable"):
        _read_manifest(tmp_path / "gone.json", label="test manifest")


def test_a_corrupt_release_manifest_is_an_install_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "dependency_release.json"
    bad.write_bytes(b"{not json")
    monkeypatch.setattr(installer, "_RELEASE_MANIFEST", bad)

    with pytest.raises(InstallError, match="unreadable"):
        installer.load_dependency_release()


def test_download_urls_with_broken_syntax_are_unsafe() -> None:
    assert _is_safe_download_url("https://[broken") is False
    assert _is_safe_download_url("http://example.com/x.zip") is False
    assert _is_safe_download_url("https://user:pw@example.com/x.zip") is False
    assert _is_safe_download_url("https://example.com/x.zip") is True


# --- download loop ----------------------------------------------------------------


def test_a_sha_mismatch_burns_the_mirror_and_reports_all_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = {
        "asset": "deps.zip",
        "sha256": "0" * 64,
        "size": 4,
        "tag": "v1",
        "download_urls": ["https://a.example/x.zip", "https://b.example/x.zip"],
    }
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)

    def fake_download(url: str, destination: Path, *, expected_size: int) -> None:
        destination.write_bytes(b"junk")

    monkeypatch.setattr(installer, "_download_one", fake_download)

    with pytest.raises(InstallError, match="all dependency release sources failed") as caught:
        installer.download_dependency_release(tmp_path)

    assert str(caught.value).count("SHA-256 mismatch") == 2


# --- extraction ------------------------------------------------------------------


def _zip_with(tmp_path: Path, files: dict[str, str]) -> Path:
    archive = tmp_path / "deps.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, content in files.items():
            bundle.writestr(name, content)
    archive.write_bytes(buffer.getvalue())
    return archive


def _pin_release(
    monkeypatch: pytest.MonkeyPatch, archive: Path, *, tag: str = "bundle-v1"
) -> None:
    release = {"sha256": _sha256(archive), "tag": tag, "asset": archive.name}
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)


def test_a_bundle_without_a_manifest_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = _zip_with(tmp_path, {"tools/readme.txt": "no manifest here"})
    _pin_release(monkeypatch, archive)

    with pytest.raises(InstallError, match="MANIFEST.json missing"):
        extract_dependency_release(archive, tmp_path / "out")


def test_extraction_replaces_a_broken_previous_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = json.dumps({"never_bundles_ida": True})
    archive = _zip_with(tmp_path, {"bundle/MANIFEST.json": manifest})
    _pin_release(monkeypatch, archive)
    out = tmp_path / "out"
    broken_final = out / "bundle-v1"
    broken_final.mkdir(parents=True)  # exists, but has no MANIFEST -> not cached

    result = extract_dependency_release(archive, out)

    assert result["ok"] is True
    assert result["cached"] is False
    assert Path(result["root"]).name == "bundle"
    assert (Path(result["root"]) / "MANIFEST.json").is_file()


def test_a_bundle_that_vanishes_after_activation_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = json.dumps({"never_bundles_ida": True})
    archive = _zip_with(tmp_path, {"bundle/MANIFEST.json": manifest})
    _pin_release(monkeypatch, archive)
    out = tmp_path / "out"
    real_find = installer._find_bundle_root

    def vanishing_find(root: Path) -> Path | None:
        if root == out / "bundle-v1":
            return None  # neither cached before nor visible after activation
        return real_find(root)

    monkeypatch.setattr(installer, "_find_bundle_root", vanishing_find)

    with pytest.raises(InstallError, match="disappeared after activation"):
        extract_dependency_release(archive, out)


# --- IDA prompt --------------------------------------------------------------------


def test_the_ida_prompt_accepts_skip_and_a_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("builtins.input", lambda prompt="": " - ")
    assert _prompt_ida_path() is None

    monkeypatch.setattr("builtins.input", lambda prompt="": '"/opt/ida" ')
    assert _prompt_ida_path() == Path("/opt/ida").resolve()


# --- one-click setup ----------------------------------------------------------------


def _patch_finishers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    ready: bool = True,
) -> dict[str, Any]:
    seen: dict[str, Any] = {"config_updates": []}
    monkeypatch.setattr(
        installer,
        "update_config_values",
        lambda updates, **kwargs: (
            seen["config_updates"].append(updates),
            tmp_path / "config.json",
        )[1],
    )
    monkeypatch.setattr(
        config_generate,
        "export_mcp_environment",
        lambda settings, **kwargs: {"ok": True, "written": {"bundle": "mcp.json"}},
    )
    report = SimpleNamespace(
        ready=ready,
        probes=[Probe("python", ProbeStatus.READY, "Python 3.12")],
    )
    monkeypatch.setattr(doctor_mod, "run_doctor", lambda settings: report)
    return seen


def test_one_click_setup_on_windows_runs_the_bundle_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(installer, "os", SimpleNamespace(name="nt"))
    empty = _settings(tmp_path)
    monkeypatch.setattr(
        installer.Settings, "load", staticmethod(lambda config_path=None: empty)
    )
    monkeypatch.setattr(
        installer,
        "download_dependency_release",
        lambda dest: {"ok": True, "archive": str(tmp_path / "deps.zip")},
    )
    monkeypatch.setattr(
        installer,
        "extract_dependency_release",
        lambda archive, dest: {"ok": True, "root": str(tmp_path / "bundle")},
    )
    monkeypatch.setattr(
        installer,
        "configure_dependency_bundle",
        lambda root: {"ok": True, "configured": {}},
    )
    from headless_re_mcp.config import ida_library_names

    ida = tmp_path / "ida"
    ida.mkdir()
    (ida / ida_library_names()[0]).write_bytes(b"MZ")
    monkeypatch.setattr(
        web_setup, "configure_ida", lambda **kwargs: {"ok": True, "saved": True}
    )
    _patch_finishers(monkeypatch, tmp_path)

    result = run_one_click_setup(ida_home=ida, non_interactive=True)

    step_names = [step["step"] for step in result["steps"]]
    assert step_names == [
        "download_release",
        "extract_release",
        "configure_release",
        "configure_ida",
        "generate_mcp",
        "doctor",
    ]
    assert result["ok"] is True
    assert result["platform"] == "windows"
    assert result["ida_configured"] is True


def test_one_click_setup_on_linux_skips_the_windows_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = _settings(tmp_path)
    monkeypatch.setattr(
        installer.Settings, "load", staticmethod(lambda config_path=None: empty)
    )
    monkeypatch.setattr(installer, "discover_ida_home", lambda: None)
    _patch_finishers(monkeypatch, tmp_path, ready=False)

    result = run_one_click_setup(non_interactive=True)

    step_names = [step["step"] for step in result["steps"]]
    assert step_names == ["windows_dependency_release", "configure_ida", "generate_mcp", "doctor"]
    assert result["steps"][0]["status"] == "unsupported_on_platform"
    assert result["steps"][1]["status"] == "optional"
    assert result["steps"][1]["ok"] is True  # optional on Linux
    assert result["ok"] is False  # doctor not ready
    assert result["ida_configured"] is False


def test_one_click_setup_prompts_for_ida_on_interactive_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(installer, "os", SimpleNamespace(name="nt"))
    empty = _settings(tmp_path)
    monkeypatch.setattr(
        installer.Settings, "load", staticmethod(lambda config_path=None: empty)
    )
    monkeypatch.setattr(installer, "discover_ida_home", lambda: None)
    prompted: list[bool] = []

    def fake_prompt() -> None:
        prompted.append(True)
        return None

    monkeypatch.setattr(installer, "_prompt_ida_path", fake_prompt)
    _patch_finishers(monkeypatch, tmp_path)

    result = run_one_click_setup(download_release=False, non_interactive=False)

    assert prompted == [True]
    ida_step = next(s for s in result["steps"] if s["step"] == "configure_ida")
    assert ida_step["ok"] is False  # required on Windows, still unconfigured
    assert ida_step["status"] == "required"


def test_one_click_setup_refuses_an_invalid_ida_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = _settings(tmp_path)
    monkeypatch.setattr(
        installer.Settings, "load", staticmethod(lambda config_path=None: empty)
    )

    with pytest.raises(InstallError, match="not a directory"):
        run_one_click_setup(
            download_release=False,
            non_interactive=True,
            ida_home=tmp_path / "not-an-ida",
        )


def test_one_click_setup_fails_when_ida_configuration_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = _settings(tmp_path)
    monkeypatch.setattr(
        installer.Settings, "load", staticmethod(lambda config_path=None: empty)
    )
    from headless_re_mcp.config import ida_library_names

    ida = tmp_path / "ida"
    ida.mkdir()
    (ida / ida_library_names()[0]).write_bytes(b"MZ")
    monkeypatch.setattr(
        web_setup, "configure_ida", lambda **kwargs: {"ok": False, "saved": True}
    )

    with pytest.raises(InstallError, match="IDA configuration failed"):
        run_one_click_setup(
            download_release=False, non_interactive=True, ida_home=ida
        )


# --- summary printing ----------------------------------------------------------------


def test_setup_summary_flags_unconfigured_ida_per_platform(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print_setup_summary(
        {
            "config_path": "/tmp/config.json",
            "steps": [{"step": "doctor", "ok": True}, "not-a-dict"],
            "doctor_ready": True,
            "ida_configured": False,
            "platform": "windows",
        }
    )

    out = capsys.readouterr().out
    assert "[OK] doctor" in out
    assert "Windows 必需" in out
    assert "python start_web.py" in out


def test_setup_summary_stays_quiet_when_ida_is_configured(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print_setup_summary(
        {
            "config_path": "/tmp/config.json",
            "steps": [{"step": "configure_ida", "ok": False}],
            "doctor_ready": False,
            "ida_configured": True,
            "platform": "linux",
        }
    )

    out = capsys.readouterr().out
    assert "[WARN] configure_ida" in out
    assert "IDA 尚未配置" not in out
