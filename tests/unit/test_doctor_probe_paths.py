"""Coverage for ``doctor`` optional-tool probes and formatting helpers.

The optional CLI probes share a three-arm shape: unset settings report MISSING,
a configured path that is not a file reports BLOCKED, and a present path is
validated through a per-tool ``probe_*`` seam (or the ``_probe_run`` version
seam). These drive each arm with a temp executable and a stubbed seam so the
tests stay about what a probe makes of a result, not about real tools.
"""

from __future__ import annotations

import shutil
import types
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.doctor as doctor
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import (
    DoctorReport,
    Probe,
    ProbeStatus,
    format_report,
    probe_command,
    probe_de4dot,
    probe_die,
    probe_exeinfope,
    probe_ghidra,
    probe_ida,
    probe_native_toolchain,
    probe_net_reactor_slayer,
    probe_optional_tool,
    probe_python_module,
    probe_scylla,
    probe_upx,
    probe_vmp_dumper,
    probe_xvlkc,
)


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides)


def _executable(tmp_path: Path, name: str = "tool") -> Path:
    path = tmp_path / name
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


# ---------------------------------------------------------------------------
# probe_die (two _probe_run calls: --version and --help)
# ---------------------------------------------------------------------------


def test_probe_die_missing_when_unconfigured(tmp_path: Path) -> None:
    assert probe_die(_settings(tmp_path)).status is ProbeStatus.MISSING


def test_probe_die_blocked_when_configured_path_is_absent(tmp_path: Path) -> None:
    probe = probe_die(_settings(tmp_path, diec=tmp_path / "missing-diec"))
    assert probe.status is ProbeStatus.BLOCKED


def test_probe_die_ready_with_version_and_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def run(command: list[str], *, timeout: float, env: object = None) -> doctor._ProbeOutput:
        if "--help" in command:
            return doctor._ProbeOutput(0, "usage: diec --json <file>", "")
        return doctor._ProbeOutput(0, "Detect It Easy v3.07", "")

    monkeypatch.setattr(doctor, "_probe_run", run)
    probe = probe_die(_settings(tmp_path, diec=_executable(tmp_path, "diec")))
    assert probe.status is ProbeStatus.READY
    assert probe.details["version"] == "3.07"
    assert probe.details["json_capable"] is True


def test_probe_die_blocked_without_a_usable_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        doctor,
        "_probe_run",
        lambda command, *, timeout, env=None: doctor._ProbeOutput(0, "no version here", ""),
    )
    probe = probe_die(_settings(tmp_path, diec=_executable(tmp_path, "diec")))
    assert probe.status is ProbeStatus.BLOCKED


def test_probe_die_blocked_when_the_run_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(command: list[str], *, timeout: float, env: object = None) -> doctor._ProbeOutput:
        raise OSError("cannot exec")

    monkeypatch.setattr(doctor, "_probe_run", boom)
    probe = probe_die(_settings(tmp_path, diec=_executable(tmp_path, "diec")))
    assert probe.status is ProbeStatus.BLOCKED
    assert "error" in probe.details


# ---------------------------------------------------------------------------
# probe_upx
# ---------------------------------------------------------------------------


def test_probe_upx_missing_when_unconfigured(tmp_path: Path) -> None:
    assert probe_upx(_settings(tmp_path)).status is ProbeStatus.MISSING


def test_probe_upx_blocked_when_configured_path_is_absent(tmp_path: Path) -> None:
    assert probe_upx(_settings(tmp_path, upx=tmp_path / "nope")).status is ProbeStatus.BLOCKED


def test_probe_upx_ready_with_a_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        doctor,
        "_probe_run",
        lambda command, *, timeout, env=None: doctor._ProbeOutput(0, "upx 4.2.1", ""),
    )
    probe = probe_upx(_settings(tmp_path, upx=_executable(tmp_path, "upx")))
    assert probe.status is ProbeStatus.READY
    assert probe.details["version"] == "4.2.1"


def test_probe_upx_blocked_without_a_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        doctor,
        "_probe_run",
        lambda command, *, timeout, env=None: doctor._ProbeOutput(1, "", "boom"),
    )
    assert probe_upx(_settings(tmp_path, upx=_executable(tmp_path, "upx"))).status is (
        ProbeStatus.BLOCKED
    )


def test_probe_upx_blocked_when_the_run_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(command: list[str], *, timeout: float, env: object = None) -> doctor._ProbeOutput:
        raise OSError("no exec")

    monkeypatch.setattr(doctor, "_probe_run", boom)
    assert probe_upx(_settings(tmp_path, upx=_executable(tmp_path, "upx"))).status is (
        ProbeStatus.BLOCKED
    )


# ---------------------------------------------------------------------------
# probe_exeinfope (silent-scan seam)
# ---------------------------------------------------------------------------


def _patch_exeinfope(monkeypatch: pytest.MonkeyPatch, fake: object) -> None:
    monkeypatch.setattr("headless_re_mcp.detection.exeinfope.scan_with_exeinfope", fake)


def test_probe_exeinfope_missing_and_blocked_guards(tmp_path: Path) -> None:
    assert probe_exeinfope(_settings(tmp_path)).status is ProbeStatus.MISSING
    stale = probe_exeinfope(_settings(tmp_path, exeinfope=tmp_path / "gone"))
    assert stale.status is ProbeStatus.BLOCKED


def test_probe_exeinfope_blocked_on_a_visible_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.detection.exeinfope import ExeinfopeGuiWindowError

    def raise_gui(*args: object, **kwargs: object) -> object:
        raise ExeinfopeGuiWindowError(["Exeinfo PE Analyzer"])

    _patch_exeinfope(monkeypatch, raise_gui)
    probe = probe_exeinfope(_settings(tmp_path, exeinfope=_executable(tmp_path, "exe")))
    assert probe.status is ProbeStatus.BLOCKED
    assert probe.details["analyzer_windows"] == ["Exeinfo PE Analyzer"]


def test_probe_exeinfope_blocked_on_a_scan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.detection.exeinfope import ExeinfopeScanError

    def raise_scan(*args: object, **kwargs: object) -> object:
        raise ExeinfopeScanError("process_error", "exeinfope crashed")

    _patch_exeinfope(monkeypatch, raise_scan)
    probe = probe_exeinfope(_settings(tmp_path, exeinfope=_executable(tmp_path, "exe")))
    assert probe.status is ProbeStatus.BLOCKED
    assert probe.details["code"] == "process_error"


def test_probe_exeinfope_blocked_when_start_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_os(*args: object, **kwargs: object) -> object:
        raise OSError("permission denied")

    _patch_exeinfope(monkeypatch, raise_os)
    assert (
        probe_exeinfope(_settings(tmp_path, exeinfope=_executable(tmp_path, "exe"))).status
        is ProbeStatus.BLOCKED
    )


def _fake_scan_result(findings: list[object]) -> object:
    return types.SimpleNamespace(
        findings=findings,
        source=types.SimpleNamespace(duration_ms=12.5),
        returncode=0,
        raw_log="log-bytes",
    )


def test_probe_exeinfope_blocked_on_empty_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_exeinfope(monkeypatch, lambda *a, **k: _fake_scan_result([]))
    assert (
        probe_exeinfope(_settings(tmp_path, exeinfope=_executable(tmp_path, "exe"))).status
        is ProbeStatus.BLOCKED
    )


def test_probe_exeinfope_ready_with_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_exeinfope(monkeypatch, lambda *a, **k: _fake_scan_result([object()]))
    probe = probe_exeinfope(_settings(tmp_path, exeinfope=_executable(tmp_path, "exe")))
    assert probe.status is ProbeStatus.READY
    assert probe.details["findings"] == 1


# ---------------------------------------------------------------------------
# probe_de4dot / net_reactor_slayer / xvlkc / vmp_dumper / scylla
# ---------------------------------------------------------------------------


def _probe_cli_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    probe: object,
    setting: str,
    seam: str,
) -> None:
    assert probe(_settings(tmp_path)).status is ProbeStatus.MISSING  # type: ignore[operator]

    absent = _settings(tmp_path, **{setting: tmp_path / "not-there"})
    assert probe(absent).status is ProbeStatus.BLOCKED  # type: ignore[operator]

    present = _settings(tmp_path, **{setting: _executable(tmp_path, setting)})
    monkeypatch.setattr(seam, lambda executable, **kw: (True, "version 1.0"))
    assert probe(present).status is ProbeStatus.READY  # type: ignore[operator]

    monkeypatch.setattr(seam, lambda executable, **kw: (False, "nope"))
    assert probe(present).status is ProbeStatus.BLOCKED  # type: ignore[operator]


def test_probe_de4dot_arms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _probe_cli_case(
        tmp_path,
        monkeypatch,
        probe=probe_de4dot,
        setting="de4dot",
        seam="headless_re_mcp.dotnet.de4dot.probe_de4dot_version",
    )


def test_probe_net_reactor_slayer_arms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _probe_cli_case(
        tmp_path,
        monkeypatch,
        probe=probe_net_reactor_slayer,
        setting="net_reactor_slayer",
        seam="headless_re_mcp.dotnet.net_reactor_slayer.probe_net_reactor_slayer",
    )


def test_probe_xvlkc_arms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _probe_cli_case(
        tmp_path,
        monkeypatch,
        probe=probe_xvlkc,
        setting="xvlkc",
        seam="headless_re_mcp.unpack.xvlkc.probe_xvlkc",
    )


def test_probe_vmp_dumper_arms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _probe_cli_case(
        tmp_path,
        monkeypatch,
        probe=probe_vmp_dumper,
        setting="vmp_dumper",
        seam="headless_re_mcp.unpack.vmp_dumper.probe_vmp_dumper",
    )


def test_probe_scylla_arms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _probe_cli_case(
        tmp_path,
        monkeypatch,
        probe=probe_scylla,
        setting="scylla",
        seam="headless_re_mcp.unpack.scylla.probe_scylla",
    )


# ---------------------------------------------------------------------------
# probe_ghidra
# ---------------------------------------------------------------------------


def test_probe_ghidra_missing_without_a_home(tmp_path: Path) -> None:
    assert probe_ghidra(_settings(tmp_path)).status is ProbeStatus.MISSING


def test_probe_ghidra_missing_without_analyze_headless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda home: None,
    )
    probe = probe_ghidra(_settings(tmp_path, ghidra_home=tmp_path))
    assert probe.status is ProbeStatus.MISSING


def test_probe_ghidra_detected_without_java(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    analyze = _executable(tmp_path, "analyzeHeadless")
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda home: analyze,
    )
    monkeypatch.setattr(shutil, "which", lambda name: None)
    probe = probe_ghidra(_settings(tmp_path, ghidra_home=tmp_path))
    assert probe.status is ProbeStatus.DETECTED


def test_probe_ghidra_ready_with_java(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    analyze = _executable(tmp_path, "analyzeHeadless")
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda home: analyze,
    )
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/java")
    probe = probe_ghidra(_settings(tmp_path, ghidra_home=tmp_path))
    assert probe.status is ProbeStatus.READY


# ---------------------------------------------------------------------------
# probe_native_toolchain / probe_command / probe_optional_tool / python_module
# ---------------------------------------------------------------------------


def test_probe_native_toolchain_ready_and_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    assert probe_native_toolchain().status is ProbeStatus.READY

    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert probe_native_toolchain().status is ProbeStatus.BLOCKED


def test_probe_command_detected_and_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        shutil, "which", lambda name: "/usr/bin/tool" if name == "wanted" else None
    )
    assert probe_command("thing", ("wanted",)).status is ProbeStatus.DETECTED
    assert probe_command("thing", ("absent",)).status is ProbeStatus.MISSING


def test_probe_optional_tool_from_configured_path(tmp_path: Path) -> None:
    settings = _settings(tmp_path, jadx=_executable(tmp_path, "jadx"))
    probe = probe_optional_tool("jadx", settings, "jadx", ("jadx",))
    assert probe.status is ProbeStatus.DETECTED
    assert probe.details["path"].endswith("jadx")


def test_probe_optional_tool_from_path_and_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/jadx")
    assert probe_optional_tool("jadx", settings, "jadx", ("jadx",)).status is (ProbeStatus.DETECTED)

    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert probe_optional_tool("jadx", settings, "jadx", ("jadx",)).status is (ProbeStatus.MISSING)


def test_probe_python_module_detected_for_a_real_module() -> None:
    probe = probe_python_module("json_module", "json")
    assert probe.status is ProbeStatus.DETECTED
    assert probe.details["origin"]


# ---------------------------------------------------------------------------
# probe_ida arms via the discovery seams
# ---------------------------------------------------------------------------


def test_probe_ida_missing_without_a_home(tmp_path: Path) -> None:
    assert probe_ida(_settings(tmp_path)).status is ProbeStatus.MISSING


def test_probe_ida_blocked_without_the_native_library(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "ida"
    home.mkdir()
    monkeypatch.setattr(doctor, "find_idalib_library", lambda h: None)
    monkeypatch.setattr(doctor, "find_ida_executable", lambda h: home / "ida")
    probe = probe_ida(_settings(tmp_path, ida_home=home))
    assert probe.status is ProbeStatus.BLOCKED
    assert "idalib library is missing" in probe.summary


def test_probe_ida_blocked_without_the_python_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "ida"
    home.mkdir()
    monkeypatch.setattr(doctor, "find_idalib_library", lambda h: home / "libidalib.so")
    monkeypatch.setattr(doctor, "find_ida_executable", lambda h: home / "ida")
    # idapro is not installed here, so the module spec lookup returns None.
    probe = probe_ida(_settings(tmp_path, ida_home=home))
    assert probe.status is ProbeStatus.BLOCKED
    assert "idapro Python package is unavailable" in probe.summary


# ---------------------------------------------------------------------------
# format_report
# ---------------------------------------------------------------------------


def test_format_report_lists_blocking_required_backends_with_fixes() -> None:
    ready = Probe("platform", ProbeStatus.READY, "ok")
    blocked = Probe(
        "ida_idalib",
        ProbeStatus.BLOCKED,
        "IDA missing",
        {},
        "Install IDA.",
    )
    optional = Probe("upx", ProbeStatus.MISSING, "no upx")
    report = DoctorReport(
        probes=(ready, blocked, optional),
        required_probes=frozenset({"platform", "ida_idalib"}),
    )

    text = format_report(report)

    assert "Overall: NOT READY" in text
    assert "Blocking required backends" in text
    assert "fix: Install IDA." in text
    assert "Optional backends:" in text
