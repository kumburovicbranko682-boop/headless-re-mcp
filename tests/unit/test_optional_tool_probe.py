"""A configured-but-broken optional tool path must read as BLOCKED, not missing.

probe_optional_tool backs adb/jadx/apktool/apksigner/webcrack/wabt. It used to
try the configured path and, when that was not a file, silently fall back to
PATH -- so a typo'd or moved HEADLESS_RE_<TOOL> read as "detected" (if the tool
happened to be on PATH) or "not installed" (if not). Both mislead: the clients
(JadxClient/JsClient/WasmClient/ApktoolClient) take the configured path as-is
with no PATH fallback, so a broken path makes the tool unavailable even when the
binary is on PATH. probe_die/probe_upx/probe_exeinfope already BLOCK on a broken
configured path; these pin that probe_optional_tool now matches them.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.doctor as doctor_module
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import ProbeStatus, probe_optional_tool, run_doctor

_JADX = ("jadx", "jadx.bat")


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides)


def test_configured_missing_path_is_blocked_not_missing(tmp_path: Path) -> None:
    probe = probe_optional_tool(
        "jadx", _settings(tmp_path, jadx=tmp_path / "nope" / "jadx"), "jadx", _JADX
    )

    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["path"].endswith("jadx")
    assert "unset" in (probe.remediation or "")


def test_configured_directory_is_blocked(tmp_path: Path) -> None:
    """A directory is not an executable; is_file() is False, so it must block."""
    a_dir = tmp_path / "apktool-dir"
    a_dir.mkdir()

    probe = probe_optional_tool(
        "apktool", _settings(tmp_path, apktool=a_dir), "apktool", ("apktool",)
    )

    assert probe.status == ProbeStatus.BLOCKED


def test_broken_config_blocks_even_when_the_tool_is_on_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The load-bearing case: config wins over PATH, matching the clients.

    Old behaviour fell through to PATH and reported the PATH hit as detected, but
    JadxClient(settings.jadx) would use the broken configured path and answer
    capability_unavailable. Blocking keeps the doctor honest about that.
    """
    monkeypatch.setattr(
        doctor_module.shutil, "which", lambda cmd: "/usr/bin/jadx" if cmd == "jadx" else None
    )

    probe = probe_optional_tool(
        "jadx", _settings(tmp_path, jadx=tmp_path / "moved" / "jadx"), "jadx", _JADX
    )

    assert probe.status == ProbeStatus.BLOCKED


def test_configured_valid_file_is_detected(tmp_path: Path) -> None:
    real = tmp_path / "jadx"
    real.write_bytes(b"")

    probe = probe_optional_tool("jadx", _settings(tmp_path, jadx=real), "jadx", _JADX)

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["path"] == str(real)


def test_unconfigured_falls_back_to_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        doctor_module.shutil, "which", lambda cmd: "/usr/bin/jadx" if cmd == "jadx" else None
    )

    probe = probe_optional_tool("jadx", _settings(tmp_path), "jadx", _JADX)

    assert probe.status == ProbeStatus.DETECTED
    assert "command detected" in probe.summary


def test_unconfigured_and_absent_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: None)

    probe = probe_optional_tool("jadx", _settings(tmp_path), "jadx", _JADX)

    assert probe.status == ProbeStatus.MISSING


def test_run_doctor_blocks_a_broken_configured_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end, and it does not drag the required core out of ready."""
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: None)

    report = run_doctor(_settings(tmp_path, apktool=tmp_path / "gone" / "apktool"))
    by_name = {probe.name: probe for probe in report.probes}

    assert by_name["apktool"].status == ProbeStatus.BLOCKED
    # apktool is optional; a blocked optional backend never blocks core readiness.
    assert "apktool" not in report.required_probes
