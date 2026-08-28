"""Guard and error branches of the doctor probes.

test_doctor.py covers the happy paths; these tests hit the refusal, failure,
and platform-specific branches that only fire when a configured tool is
broken, mis-pointed, or probed from the wrong operating system.
"""

from __future__ import annotations

import ctypes
import importlib.util
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.doctor as doctor_module
from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.config import Settings, ida_library_names
from headless_re_mcp.detection.exeinfope import (
    ExeinfopeGuiWindowError,
    ExeinfopeScanError,
)
from headless_re_mcp.doctor import (
    WINDOWS_REQUIRED_PROBES,
    DoctorReport,
    Probe,
    ProbeStatus,
    format_report,
    probe_de4dot,
    probe_die,
    probe_exeinfope,
    probe_ghidra,
    probe_ida,
    probe_native_toolchain,
    probe_net_reactor_slayer,
    probe_platform,
    probe_python_module,
    probe_scylla,
    probe_upx,
    probe_vmp_dumper,
    probe_windows_feature,
    probe_x64dbg_binaries,
    probe_x64dbg_scyllahide,
    probe_x64dbg_source,
    probe_xvlkc,
    required_probe_names,
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


def test_probe_to_dict_omits_required_when_not_asked() -> None:
    payload = Probe("python", ProbeStatus.READY, "ok").to_dict()
    assert "required" not in payload
    assert payload["status"] == "ready"


def test_required_probe_names_for_windows() -> None:
    assert required_probe_names("windows") == WINDOWS_REQUIRED_PROBES


def test_probe_platform_blocks_unsupported_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor_module,
        "runtime_platform_report",
        lambda: {
            "name": "sunos",
            "system": "SunOS",
            "machine": "sparc64",
            "architecture": "sparc64",
            "core_supported": False,
            "support_level": "none",
        },
    )
    probe = probe_platform()
    assert probe.status == ProbeStatus.BLOCKED
    assert "SunOS sparc64" in probe.summary


def test_probe_windows_feature_is_ready_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_module, "runtime_platform_report", lambda: {"name": "windows"})
    probe = probe_windows_feature("win32_ui", "Win32 UI")
    assert probe.status == ProbeStatus.READY
    assert probe.details == {"supported_platforms": ["windows"]}


def test_is_elevated_reads_the_windows_shell_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(
        ctypes,
        "windll",
        SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: 1)),
        raising=False,
    )
    assert doctor_module._is_elevated() is True


def test_is_elevated_returns_none_when_the_shell_api_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(), raising=False)
    assert doctor_module._is_elevated() is None


def _ida_home_with_idalib(tmp_path: Path) -> Path:
    home = tmp_path / "ida"
    home.mkdir()
    (home / ida_library_names()[0]).write_bytes(b"\x7fELF")
    return home


def test_probe_ida_blocks_when_idalib_is_missing(tmp_path: Path) -> None:
    home = tmp_path / "ida"
    home.mkdir()
    probe = probe_ida(_settings(tmp_path, ida_home=home))
    assert probe.status == ProbeStatus.BLOCKED
    assert "idalib library is missing" in probe.summary


def test_probe_ida_points_at_the_activation_script_without_idapro(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _ida_home_with_idalib(tmp_path)
    real = importlib.util.find_spec

    def fake(name: str, package: str | None = None) -> Any:
        return None if name == "idapro" else real(name, package)

    monkeypatch.setattr(importlib.util, "find_spec", fake)
    probe = probe_ida(_settings(tmp_path, ida_home=home))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.summary == "idalib exists but the idapro Python package is unavailable"
    assert "py-activate-idalib.py" in str(probe.details["activation_script"])


def _patch_idapro_spec(monkeypatch: pytest.MonkeyPatch) -> None:
    real = importlib.util.find_spec

    def fake(name: str, package: str | None = None) -> Any:
        if name == "idapro":
            return SimpleNamespace(origin="fake/idapro/__init__.py")
        return real(name, package)

    monkeypatch.setattr(importlib.util, "find_spec", fake)


def test_probe_ida_runs_the_runtime_probe_to_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _ida_home_with_idalib(tmp_path)
    _patch_idapro_spec(monkeypatch)
    seen: dict[str, Any] = {}

    def fake_probe_run(
        command: list[str], *, timeout: float, env: Any = None
    ) -> doctor_module._ProbeOutput:
        seen["command"] = command
        seen["path"] = env["PATH"]
        assert timeout == 15
        return doctor_module._ProbeOutput(0, "fake/idapro/__init__.py\nTrue\n", "")

    monkeypatch.setattr(doctor_module, "_probe_run", fake_probe_run)
    probe = probe_ida(_settings(tmp_path, ida_home=home))
    assert probe.status == ProbeStatus.READY
    assert str(home) in seen["path"]
    assert "import idapro" in seen["command"][-1]


def test_probe_ida_blocks_when_the_runtime_probe_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _ida_home_with_idalib(tmp_path)
    _patch_idapro_spec(monkeypatch)
    monkeypatch.setattr(
        doctor_module,
        "_probe_run",
        lambda command, *, timeout, env=None: doctor_module._ProbeOutput(
            1, "", "license check failed"
        ),
    )
    probe = probe_ida(_settings(tmp_path, ida_home=home))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["probe_exit_code"] == 1
    assert probe.details["probe_stderr"] == "license check failed"


def test_probe_ida_blocks_when_the_runtime_probe_cannot_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _ida_home_with_idalib(tmp_path)
    _patch_idapro_spec(monkeypatch)

    def raise_timeout(command: list[str], *, timeout: float, env: Any = None) -> Any:
        raise TimedOut(15.0, [123])

    monkeypatch.setattr(doctor_module, "_probe_run", raise_timeout)
    probe = probe_ida(_settings(tmp_path, ida_home=home))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.summary == "idapro runtime probe failed to start"
    assert "timed out" in probe.details["error"]


def test_probe_x64dbg_source_is_missing_when_unconfigured(tmp_path: Path) -> None:
    probe = probe_x64dbg_source(_settings(tmp_path))
    assert probe.status == ProbeStatus.MISSING
    assert "HEADLESS_RE_X64DBG_SOURCE" in (probe.remediation or "")


def test_probe_x64dbg_source_blocks_without_the_headless_target(
    tmp_path: Path,
) -> None:
    source = tmp_path / "x64dbg"
    source.mkdir()
    probe = probe_x64dbg_source(_settings(tmp_path, x64dbg_source=source))
    assert probe.status == ProbeStatus.BLOCKED
    assert "headless target is absent" in probe.summary


def test_probe_x64dbg_source_blocks_when_cmake_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "x64dbg"
    (source / "src" / "headless").mkdir(parents=True)
    (source / "src" / "headless" / "headless.cpp").write_text("int main(){}", encoding="utf-8")
    cmake = source / "CMakeLists.txt"
    cmake.write_text("add_executable(headless)", encoding="utf-8")
    real_open = Path.open

    def fail_on_cmake(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == "CMakeLists.txt":
            raise PermissionError("read denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_on_cmake)
    probe = probe_x64dbg_source(_settings(tmp_path, x64dbg_source=source))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.summary == "x64dbg CMake project could not be read"
    assert "read denied" in probe.details["error"]


def test_probe_x64dbg_binaries_is_missing_without_both_architectures(
    tmp_path: Path,
) -> None:
    x64 = tmp_path / "headless-x64.exe"
    x64.touch()
    probe = probe_x64dbg_binaries(_settings(tmp_path, x64dbg_headless_x64=x64))
    assert probe.status == ProbeStatus.MISSING
    assert "not both configured" in probe.summary


def test_probe_x64dbg_binaries_records_a_gate_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    x86 = tmp_path / "headless-x86.exe"
    x64 = tmp_path / "headless-x64.exe"
    x86.touch()
    x64.touch()

    def crash(executable: Path, architecture: Any, *, timeout: float) -> Any:
        raise ValueError("gate refused the executable")

    monkeypatch.setattr(doctor_module, "run_command_loop_gate", crash)
    probe = probe_x64dbg_binaries(
        _settings(tmp_path, x64dbg_headless_x86=x86, x64dbg_headless_x64=x64)
    )
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["x64"]["error"] == "ValueError: gate refused the executable"


def test_probe_scyllahide_reports_missing_plugin_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    x86 = tmp_path / "headless-x86.exe"
    x64 = tmp_path / "headless-x64.exe"
    x86.touch()
    x64.touch()
    monkeypatch.setattr(
        "headless_re_mcp.backends.x64dbg.stealth.inspect_layout",
        lambda layout: {"configured": True, "plugin_present": False},
    )
    probe = probe_x64dbg_scyllahide(
        _settings(tmp_path, x64dbg_headless_x86=x86, x64dbg_headless_x64=x64)
    )
    assert probe.status == ProbeStatus.MISSING
    assert "plugin files are missing" in probe.summary
    assert "x86" in (probe.remediation or "")
    assert "x64" in (probe.remediation or "")


def test_probe_scyllahide_is_missing_when_headless_is_unconfigured(
    tmp_path: Path,
) -> None:
    probe = probe_x64dbg_scyllahide(_settings(tmp_path))
    assert probe.status == ProbeStatus.MISSING
    assert "plugin path is unknown" in probe.summary


def test_probe_scyllahide_is_ready_when_plugins_sit_beside_headless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    x64 = tmp_path / "headless-x64.exe"
    x64.touch()
    monkeypatch.setattr(
        "headless_re_mcp.backends.x64dbg.stealth.inspect_layout",
        lambda layout: {
            "configured": layout is not None,
            "plugin_present": layout is not None,
        },
    )
    probe = probe_x64dbg_scyllahide(_settings(tmp_path, x64dbg_headless_x64=x64))
    assert probe.status == ProbeStatus.READY


def test_probe_native_toolchain_detects_a_complete_kit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"C:/tools/{name}.exe")
    probe = probe_native_toolchain()
    assert probe.status == ProbeStatus.READY
    assert probe.details["cmake"] == "C:/tools/cmake.exe"


def test_probe_native_toolchain_blocks_an_incomplete_kit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    probe = probe_native_toolchain()
    assert probe.status == ProbeStatus.BLOCKED
    assert "Visual Studio 2022" in (probe.remediation or "")


def test_probe_die_blocks_a_stale_configured_path(tmp_path: Path) -> None:
    probe = probe_die(_settings(tmp_path, diec=tmp_path / "gone" / "diec"))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.summary == "Configured Detect It Easy CLI does not exist"


def test_probe_die_blocks_when_the_cli_probe_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "diec"
    executable.touch()

    def raise_timeout(command: list[str], *, timeout: float, env: Any = None) -> Any:
        raise TimedOut(5.0, [42])

    monkeypatch.setattr(doctor_module, "_probe_run", raise_timeout)
    probe = probe_die(_settings(tmp_path, diec=executable))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["error"].startswith("TimedOut:")


def _exeinfope_settings(tmp_path: Path) -> Settings:
    executable = tmp_path / "Exeinfope.exe"
    executable.touch()
    return _settings(tmp_path, exeinfope=executable)


def test_probe_exeinfope_blocks_on_a_visible_analyzer_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_gui(*args: Any, **kwargs: Any) -> Any:
        raise ExeinfopeGuiWindowError(["Exeinfo PE - main"])

    monkeypatch.setattr("headless_re_mcp.detection.exeinfope.scan_with_exeinfope", raise_gui)
    probe = probe_exeinfope(_exeinfope_settings(tmp_path))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.summary == "Exeinfo PE probe showed a visible analyzer window"
    assert probe.details["analyzer_windows"] == ["Exeinfo PE - main"]


def test_probe_exeinfope_blocks_on_a_scan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_scan(*args: Any, **kwargs: Any) -> Any:
        raise ExeinfopeScanError("scan_timeout", "log never appeared")

    monkeypatch.setattr("headless_re_mcp.detection.exeinfope.scan_with_exeinfope", raise_scan)
    probe = probe_exeinfope(_exeinfope_settings(tmp_path))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["code"] == "scan_timeout"


def test_probe_exeinfope_blocks_when_the_probe_cannot_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_os(*args: Any, **kwargs: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr("headless_re_mcp.detection.exeinfope.scan_with_exeinfope", raise_os)
    probe = probe_exeinfope(_exeinfope_settings(tmp_path))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.summary == "Exeinfo PE probe failed to start"
    assert probe.details["error"] == "OSError: exec format error"


def test_probe_exeinfope_blocks_an_empty_finding_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = SimpleNamespace(
        findings=(),
        source=SimpleNamespace(duration_ms=8),
        returncode=0,
        raw_log="",
    )
    monkeypatch.setattr(
        "headless_re_mcp.detection.exeinfope.scan_with_exeinfope",
        lambda *args, **kwargs: result,
    )
    probe = probe_exeinfope(_exeinfope_settings(tmp_path))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.summary == "Exeinfo PE probe produced an empty finding set"
    assert probe.details["findings"] == 0


def test_probe_upx_blocks_a_stale_configured_path(tmp_path: Path) -> None:
    probe = probe_upx(_settings(tmp_path, upx=tmp_path / "gone" / "upx"))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.summary == "Configured UPX CLI does not exist"


def test_probe_upx_blocks_when_the_cli_probe_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "upx"
    executable.touch()

    def raise_os(command: list[str], *, timeout: float, env: Any = None) -> Any:
        raise OSError("not executable")

    monkeypatch.setattr(doctor_module, "_probe_run", raise_os)
    probe = probe_upx(_settings(tmp_path, upx=executable))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["error"] == "OSError: not executable"


_EXTERNAL_CLI_CASES: list[tuple[Any, str, str]] = [
    (probe_de4dot, "de4dot", "headless_re_mcp.dotnet.de4dot.probe_de4dot_version"),
    (
        probe_net_reactor_slayer,
        "net_reactor_slayer",
        "headless_re_mcp.dotnet.net_reactor_slayer.probe_net_reactor_slayer",
    ),
    (probe_xvlkc, "xvlkc", "headless_re_mcp.unpack.xvlkc.probe_xvlkc"),
    (
        probe_vmp_dumper,
        "vmp_dumper",
        "headless_re_mcp.unpack.vmp_dumper.probe_vmp_dumper",
    ),
    (probe_scylla, "scylla", "headless_re_mcp.unpack.scylla.probe_scylla"),
]


@pytest.mark.parametrize(
    ("probe_fn", "attr", "cli_probe_target"),
    _EXTERNAL_CLI_CASES,
    ids=[attr for _, attr, _ in _EXTERNAL_CLI_CASES],
)
def test_external_cli_probes_cover_every_configuration_state(
    probe_fn: Any,
    attr: str,
    cli_probe_target: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The five external-CLI probes share one shape: MISSING when unset,
    BLOCKED for a stale path, then READY/BLOCKED from the CLI probe answer."""
    unconfigured = probe_fn(_settings(tmp_path, **{attr: None}))
    assert unconfigured.status == ProbeStatus.MISSING
    assert unconfigured.remediation is not None

    stale = probe_fn(_settings(tmp_path, **{attr: tmp_path / "gone" / attr}))
    assert stale.status == ProbeStatus.BLOCKED
    assert "does not exist" in stale.summary

    executable = tmp_path / f"{attr}.exe"
    executable.touch()
    settings = _settings(tmp_path, **{attr: executable})

    monkeypatch.setattr(cli_probe_target, lambda path: (True, "version 1.2.3"))
    ready = probe_fn(settings)
    assert ready.status == ProbeStatus.READY
    assert ready.details["probe_output"] == "version 1.2.3"

    monkeypatch.setattr(cli_probe_target, lambda path: (False, None))
    blocked = probe_fn(settings)
    assert blocked.status == ProbeStatus.BLOCKED
    assert blocked.details["probe_output"] is None


def test_probe_python_module_reports_a_missing_module() -> None:
    probe = probe_python_module("nope", "headless_re_mcp_definitely_absent")
    assert probe.status == ProbeStatus.MISSING


def test_report_to_json_round_trips() -> None:
    import json

    report = DoctorReport(
        (Probe("platform", ProbeStatus.READY, "ok"), Probe("python", ProbeStatus.READY, "ok")),
        required_probes=frozenset({"platform", "python"}),
    )
    payload = json.loads(report.to_json())
    assert payload["ready"] is True
    assert payload["required_probes"] == ["platform", "python"]


def test_format_report_lists_blocking_probes_without_remediation() -> None:
    report = DoctorReport(
        (
            Probe("platform", ProbeStatus.READY, "ok"),
            Probe("python", ProbeStatus.BLOCKED, "too old"),
        ),
        required_probes=frozenset({"platform", "python"}),
    )
    text = format_report(report)
    assert "- python (blocked)" in text
    # No remediation was offered, so no fix line follows the bullet.
    assert "fix:" not in text.split("Blocking required backends")[1]


def test_no_window_flags_on_both_platforms(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert doctor_module._no_window_flags() == 0
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    assert doctor_module._no_window_flags() == 0x08000000


def test_probe_run_decodes_bounded_output(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run_bounded(
        command: list[str], *, timeout: float, creationflags: int, env: Any
    ) -> Any:
        seen.update(command=command, timeout=timeout, creationflags=creationflags)
        return SimpleNamespace(returncode=3, stdout=b"out\xff", stderr=b"err")

    monkeypatch.setattr(doctor_module, "run_bounded", fake_run_bounded)
    output = doctor_module._probe_run(["tool", "--version"], timeout=7)
    assert seen == {"command": ["tool", "--version"], "timeout": 7, "creationflags": 0}
    assert output.returncode == 3
    assert output.stdout == "out\ufffd"
    assert output.stderr == "err"


def test_bounded_text_truncates_oversized_output() -> None:
    text = doctor_module._bounded_text("a" * 50, "b" * 50, limit=10)
    assert text.endswith("\n...[truncated]")
    assert len(text) == 10 + len("\n...[truncated]")


def test_probe_ghidra_missing_analyze_headless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda home: None,
    )
    probe = probe_ghidra(_settings(tmp_path, ghidra_home=tmp_path / "ghidra"))
    assert probe.status == ProbeStatus.MISSING
    assert probe.summary == "analyzeHeadless not found under ghidra_home"


def test_probe_ghidra_detected_without_java(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    analyze = tmp_path / "ghidra" / "support" / "analyzeHeadless"
    analyze.parent.mkdir(parents=True)
    analyze.touch()
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda home: analyze,
    )
    monkeypatch.setattr(shutil, "which", lambda name: None)
    probe = probe_ghidra(_settings(tmp_path, ghidra_home=tmp_path / "ghidra"))
    assert probe.status == ProbeStatus.DETECTED
    assert "java is not on PATH" in probe.summary


def test_probe_ghidra_ready_with_java(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    analyze = tmp_path / "ghidra" / "support" / "analyzeHeadless"
    analyze.parent.mkdir(parents=True)
    analyze.touch()
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda home: analyze,
    )
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/java")
    probe = probe_ghidra(_settings(tmp_path, ghidra_home=tmp_path / "ghidra"))
    assert probe.status == ProbeStatus.READY
    assert probe.details["java"] == "/usr/bin/java"
