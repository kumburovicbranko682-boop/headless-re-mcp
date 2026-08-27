"""Doctor probe outcomes that need a configured-but-broken tool or a fake host.

Each probe's MISSING / BLOCKED / READY legs run against tmp paths and patched
runners; nothing external is launched and no real host state is consulted.
"""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.x64dbg.stealth as stealth_mod
import headless_re_mcp.detection.exeinfope as exeinfope_mod
import headless_re_mcp.doctor as doctor
import headless_re_mcp.dotnet.de4dot as de4dot_mod
import headless_re_mcp.dotnet.net_reactor_slayer as nrs_mod
import headless_re_mcp.unpack.scylla as scylla_mod
import headless_re_mcp.unpack.vmp_dumper as vmp_mod
import headless_re_mcp.unpack.xvlkc as xvlkc_mod
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
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
    _bounded_text,
    _is_elevated,
    _no_window_flags,
    _probe_run,
    format_report,
    probe_python_module,
    required_probe_names,
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


# --- platform / small helpers -------------------------------------------------


def test_windows_hosts_require_the_debugger_probes() -> None:
    assert required_probe_names("windows") == WINDOWS_REQUIRED_PROBES
    assert "x64dbg_headless_binaries" in required_probe_names("windows")


def test_probe_serialization_omits_required_when_not_asked() -> None:
    probe = Probe("x", ProbeStatus.READY, "fine")

    assert "required" not in probe.to_dict()
    assert probe.to_dict(required=True)["required"] is True


def test_an_unsupported_host_blocks_the_platform_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor,
        "runtime_platform_report",
        lambda: {
            "core_supported": False,
            "system": "OS/2",
            "machine": "powerpc",
            "architecture": "ppc",
            "support_level": "none",
            "name": "os2",
        },
    )

    probe = doctor.probe_platform()

    assert probe.status is ProbeStatus.BLOCKED
    assert "outside the supported host matrix" in probe.summary


def test_windows_features_read_as_supported_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor, "runtime_platform_report", lambda: {"name": "windows"}
    )

    probe = doctor.probe_windows_feature("win32_ui", "Win32 UI")

    assert probe.status is ProbeStatus.READY
    assert probe.details == {"supported_platforms": ["windows"]}


def test_elevation_is_read_from_the_shell_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor.os, "name", "nt")
    shell32 = SimpleNamespace(IsUserAnAdmin=lambda: 1)
    monkeypatch.setattr(
        doctor.ctypes, "windll", SimpleNamespace(shell32=shell32), raising=False
    )
    assert _is_elevated() is True

    monkeypatch.setattr(doctor.ctypes, "windll", SimpleNamespace(), raising=False)
    assert _is_elevated() is None


def test_no_window_flags_follow_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.os, "name", "posix")
    assert _no_window_flags() == 0

    monkeypatch.setattr(doctor.os, "name", "nt")
    monkeypatch.setattr(
        doctor.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False
    )
    assert _no_window_flags() == 0x08000000


def test_probe_run_decodes_the_bounded_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor, "run_bounded", lambda cmd, **kwargs: Completed(3, b"out", b"err")
    )

    output = _probe_run(["tool", "--version"], timeout=5)

    assert (output.returncode, output.stdout, output.stderr) == (3, "out", "err")


def test_bounded_text_is_truncated() -> None:
    assert _bounded_text("x" * 5000, limit=100).endswith("...[truncated]")


# --- IDA ------------------------------------------------------------------------


def _ida_home(tmp_path: Path, *, with_lib: bool) -> Path:
    home = tmp_path / "ida"
    home.mkdir(exist_ok=True)
    if with_lib:
        (home / ida_library_names()[0]).write_bytes(b"MZ")
    return home


def test_ida_without_idalib_is_blocked(tmp_path: Path) -> None:
    settings = _settings(tmp_path, ida_home=_ida_home(tmp_path, with_lib=False))

    probe = doctor.probe_ida(settings)

    assert probe.status is ProbeStatus.BLOCKED
    assert "idalib library is missing" in probe.summary


def _idapro_present(monkeypatch: pytest.MonkeyPatch) -> None:
    real_find_spec = importlib.util.find_spec

    def fake_find_spec(name: str, *args: Any) -> Any:
        if name == "idapro":
            return SimpleNamespace(origin="/site-packages/idapro/__init__.py")
        return real_find_spec(name, *args)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)


def test_ida_runtime_probe_that_cannot_start_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _idapro_present(monkeypatch)

    def unlaunchable(command: list[str], **kwargs: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(doctor, "_probe_run", unlaunchable)
    settings = _settings(tmp_path, ida_home=_ida_home(tmp_path, with_lib=True))

    probe = doctor.probe_ida(settings)

    assert probe.status is ProbeStatus.BLOCKED
    assert "failed to start" in probe.summary


def test_ida_runtime_probe_success_is_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _idapro_present(monkeypatch)
    monkeypatch.setattr(
        doctor,
        "_probe_run",
        lambda command, **kwargs: doctor._ProbeOutput(0, "/idapro.py\nTrue\n", ""),
    )
    settings = _settings(tmp_path, ida_home=_ida_home(tmp_path, with_lib=True))

    probe = doctor.probe_ida(settings)

    assert probe.status is ProbeStatus.READY
    assert probe.details["probe_exit_code"] == 0


def test_ida_runtime_probe_failure_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _idapro_present(monkeypatch)
    monkeypatch.setattr(
        doctor,
        "_probe_run",
        lambda command, **kwargs: doctor._ProbeOutput(1, "", "license error"),
    )
    settings = _settings(tmp_path, ida_home=_ida_home(tmp_path, with_lib=True))

    probe = doctor.probe_ida(settings)

    assert probe.status is ProbeStatus.BLOCKED
    assert "initialization failed" in probe.summary


# --- x64dbg source / binaries / stealth ----------------------------------------


def test_missing_x64dbg_source_is_missing(tmp_path: Path) -> None:
    probe = doctor.probe_x64dbg_source(_settings(tmp_path))

    assert probe.status is ProbeStatus.MISSING


def test_x64dbg_source_without_the_headless_target_is_blocked(
    tmp_path: Path,
) -> None:
    source = tmp_path / "x64dbg"
    source.mkdir()

    probe = doctor.probe_x64dbg_source(_settings(tmp_path, x64dbg_source=source))

    assert probe.status is ProbeStatus.BLOCKED
    assert "headless target is absent" in probe.summary


def test_an_unreadable_cmake_project_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "x64dbg"
    (source / "src" / "headless").mkdir(parents=True)
    (source / "src" / "headless" / "headless.cpp").write_text("int main(){}\n")
    (source / "CMakeLists.txt").write_text("add_executable(headless)\n")
    real_open = Path.open

    def unreadable_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == "CMakeLists.txt":
            raise OSError("permission denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", unreadable_open)

    probe = doctor.probe_x64dbg_source(_settings(tmp_path, x64dbg_source=source))

    assert probe.status is ProbeStatus.BLOCKED
    assert "could not be read" in probe.summary


def test_x64dbg_binaries_missing_one_arch_is_missing(tmp_path: Path) -> None:
    x64 = tmp_path / "x64.exe"
    x64.write_bytes(b"MZ")

    probe = doctor.probe_x64dbg_binaries(
        _settings(tmp_path, x64dbg_headless_x64=x64)
    )

    assert probe.status is ProbeStatus.MISSING


def test_a_gate_that_cannot_launch_blocks_the_binaries_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    x64 = tmp_path / "x64.exe"
    x86 = tmp_path / "x86.exe"
    x64.write_bytes(b"MZ")
    x86.write_bytes(b"MZ")

    def broken_gate(path: Path, architecture: Any, *, timeout: float) -> Any:
        raise ValueError("not a runnable gate")

    monkeypatch.setattr(doctor, "run_command_loop_gate", broken_gate)

    probe = doctor.probe_x64dbg_binaries(
        _settings(tmp_path, x64dbg_headless_x64=x64, x64dbg_headless_x86=x86)
    )

    assert probe.status is ProbeStatus.BLOCKED
    assert "ValueError" in probe.details["x64"]["error"]


def test_report_json_round_trips() -> None:
    import json

    report = DoctorReport(
        probes=(Probe("python", ProbeStatus.READY, "Python 3.12"),),
        required_probes=frozenset({"python"}),
    )

    decoded = json.loads(report.to_json())

    assert decoded["ready"] is True
    assert decoded["probes"][0]["name"] == "python"


def test_ida_without_the_idapro_package_names_the_activation_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_find_spec = importlib.util.find_spec

    def absent_find_spec(name: str, *args: Any) -> Any:
        if name == "idapro":
            return None
        return real_find_spec(name, *args)

    monkeypatch.setattr(importlib.util, "find_spec", absent_find_spec)
    settings = _settings(tmp_path, ida_home=_ida_home(tmp_path, with_lib=True))

    probe = doctor.probe_ida(settings)

    assert probe.status is ProbeStatus.BLOCKED
    assert "idapro Python package is unavailable" in probe.summary
    assert "py-activate-idalib.py" in probe.details["activation_script"]


def test_scyllahide_with_nothing_configured_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        stealth_mod, "layout_for_headless", lambda path, architecture: None
    )
    monkeypatch.setattr(
        stealth_mod, "inspect_layout", lambda layout: {"configured": False}
    )

    probe = doctor.probe_x64dbg_scyllahide(_settings(tmp_path))

    assert probe.status is ProbeStatus.MISSING
    assert "plugin path is unknown" in probe.summary


def test_scyllahide_present_everywhere_is_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        stealth_mod, "layout_for_headless", lambda path, architecture: object()
    )
    monkeypatch.setattr(
        stealth_mod,
        "inspect_layout",
        lambda layout: {"configured": True, "plugin_present": True},
    )

    probe = doctor.probe_x64dbg_scyllahide(_settings(tmp_path))

    assert probe.status is ProbeStatus.READY


def test_scyllahide_missing_next_to_a_configured_headless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        stealth_mod, "layout_for_headless", lambda path, architecture: object()
    )
    monkeypatch.setattr(
        stealth_mod,
        "inspect_layout",
        lambda layout: {"configured": True, "plugin_present": False},
    )

    probe = doctor.probe_x64dbg_scyllahide(_settings(tmp_path))

    assert probe.status is ProbeStatus.MISSING
    assert "plugin files are missing" in probe.summary


# --- native toolchain -------------------------------------------------------------


def test_a_complete_msvc_toolchain_is_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = {"cmake": "/usr/bin/cmake", "ninja": "/usr/bin/ninja", "cl": "/opt/cl"}
    monkeypatch.setattr(shutil, "which", lambda name: tools.get(name))

    probe = doctor.probe_native_toolchain()

    assert probe.status is ProbeStatus.READY


def test_an_incomplete_toolchain_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path))

    probe = doctor.probe_native_toolchain()

    assert probe.status is ProbeStatus.BLOCKED
    assert probe.details["vswhere"] is None


# --- configured-CLI probes ----------------------------------------------------------


def test_a_stale_diec_path_is_blocked(tmp_path: Path) -> None:
    probe = doctor.probe_die(_settings(tmp_path, diec=tmp_path / "gone"))

    assert probe.status is ProbeStatus.BLOCKED
    assert "does not exist" in probe.summary


def test_a_diec_that_times_out_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    diec = tmp_path / "diec"
    diec.write_bytes(b"")

    def timing_out(command: list[str], **kwargs: Any) -> Any:
        raise TimedOut(timeout=5.0, killed=[7])

    monkeypatch.setattr(doctor, "_probe_run", timing_out)

    probe = doctor.probe_die(_settings(tmp_path, diec=diec))

    assert probe.status is ProbeStatus.BLOCKED
    assert "TimedOut" in probe.details["error"]


def test_a_stale_upx_path_is_blocked(tmp_path: Path) -> None:
    probe = doctor.probe_upx(_settings(tmp_path, upx=tmp_path / "gone"))

    assert probe.status is ProbeStatus.BLOCKED


def test_an_unlaunchable_upx_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upx = tmp_path / "upx"
    upx.write_bytes(b"")

    def unlaunchable(command: list[str], **kwargs: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(doctor, "_probe_run", unlaunchable)

    probe = doctor.probe_upx(_settings(tmp_path, upx=upx))

    assert probe.status is ProbeStatus.BLOCKED
    assert "OSError" in probe.details["error"]


# --- exeinfope ---------------------------------------------------------------------


def _exeinfope_settings(tmp_path: Path) -> Settings:
    executable = tmp_path / "exeinfope.exe"
    executable.write_bytes(b"MZ")
    return _settings(tmp_path, exeinfope=executable)


def test_exeinfope_showing_a_window_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def windowed(*args: Any, **kwargs: Any) -> Any:
        raise ExeinfopeGuiWindowError(["Exeinfo PE - main"])

    monkeypatch.setattr(exeinfope_mod, "scan_with_exeinfope", windowed)

    probe = doctor.probe_exeinfope(_exeinfope_settings(tmp_path))

    assert probe.status is ProbeStatus.BLOCKED
    assert probe.details["analyzer_windows"] == ["Exeinfo PE - main"]


def test_exeinfope_scan_failure_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(*args: Any, **kwargs: Any) -> Any:
        raise ExeinfopeScanError("timeout", "scan hung")

    monkeypatch.setattr(exeinfope_mod, "scan_with_exeinfope", failing)

    probe = doctor.probe_exeinfope(_exeinfope_settings(tmp_path))

    assert probe.status is ProbeStatus.BLOCKED
    assert probe.details["code"] == "timeout"


def test_exeinfope_that_cannot_start_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unlaunchable(*args: Any, **kwargs: Any) -> Any:
        raise OSError("not runnable")

    monkeypatch.setattr(exeinfope_mod, "scan_with_exeinfope", unlaunchable)

    probe = doctor.probe_exeinfope(_exeinfope_settings(tmp_path))

    assert probe.status is ProbeStatus.BLOCKED
    assert "failed to start" in probe.summary


def test_exeinfope_with_an_empty_finding_set_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = SimpleNamespace(
        findings=[],
        source=SimpleNamespace(duration_ms=12),
        returncode=0,
        raw_log="",
    )
    monkeypatch.setattr(
        exeinfope_mod, "scan_with_exeinfope", lambda *args, **kwargs: result
    )

    probe = doctor.probe_exeinfope(_exeinfope_settings(tmp_path))

    assert probe.status is ProbeStatus.BLOCKED
    assert "empty finding set" in probe.summary


# --- external unpacker CLIs -----------------------------------------------------


@pytest.mark.parametrize(
    ("probe_fn", "attr", "module", "patch_name"),
    [
        (doctor.probe_de4dot, "de4dot", de4dot_mod, "probe_de4dot_version"),
        (
            doctor.probe_net_reactor_slayer,
            "net_reactor_slayer",
            nrs_mod,
            "probe_net_reactor_slayer",
        ),
        (doctor.probe_xvlkc, "xvlkc", xvlkc_mod, "probe_xvlkc"),
        (doctor.probe_vmp_dumper, "vmp_dumper", vmp_mod, "probe_vmp_dumper"),
        (doctor.probe_scylla, "scylla", scylla_mod, "probe_scylla"),
    ],
)
def test_external_cli_probes_report_all_three_outcomes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_fn: Any,
    attr: str,
    module: Any,
    patch_name: str,
) -> None:
    unconfigured = probe_fn(_settings(tmp_path))
    assert unconfigured.status is ProbeStatus.MISSING
    assert unconfigured.remediation is not None

    stale = probe_fn(_settings(tmp_path, **{attr: tmp_path / "gone"}))
    assert stale.status is ProbeStatus.BLOCKED
    assert "does not exist" in stale.summary

    executable = tmp_path / f"{attr}.exe"
    executable.write_bytes(b"MZ")
    live = _settings(tmp_path, **{attr: executable})

    monkeypatch.setattr(module, patch_name, lambda path: (True, "v1.2.3"))
    ready = probe_fn(live)
    assert ready.status is ProbeStatus.READY
    assert ready.details["probe_output"] == "v1.2.3"

    monkeypatch.setattr(module, patch_name, lambda path: (False, None))
    blocked = probe_fn(live)
    assert blocked.status is ProbeStatus.BLOCKED
    assert blocked.details["probe_output"] is None


# --- optional modules / ghidra / report --------------------------------------------


def test_an_installed_python_module_is_detected() -> None:
    probe = probe_python_module("jsonmod", "json")

    assert probe.status is ProbeStatus.DETECTED
    assert "origin" in probe.details


def test_ghidra_home_without_analyze_headless_is_missing(tmp_path: Path) -> None:
    home = tmp_path / "ghidra"
    home.mkdir()

    probe = doctor.probe_ghidra(_settings(tmp_path, ghidra_home=home))

    assert probe.status is ProbeStatus.MISSING
    assert "analyzeHeadless not found" in probe.summary


def _ghidra_home(tmp_path: Path) -> Path:
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True, exist_ok=True)
    (home / "support" / "analyzeHeadless").write_text("#!/bin/sh\n")
    return home


def test_ghidra_without_java_is_only_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)

    probe = doctor.probe_ghidra(
        _settings(tmp_path, ghidra_home=_ghidra_home(tmp_path))
    )

    assert probe.status is ProbeStatus.DETECTED
    assert "java is not on PATH" in probe.summary


def test_ghidra_with_java_is_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/java")

    probe = doctor.probe_ghidra(
        _settings(tmp_path, ghidra_home=_ghidra_home(tmp_path))
    )

    assert probe.status is ProbeStatus.READY
    assert probe.details["java"] == "/usr/bin/java"


def test_format_report_lists_blockers_without_remediation(
) -> None:
    report = DoctorReport(
        probes=(Probe("python", ProbeStatus.BLOCKED, "Python 3.8"),),
        required_probes=frozenset({"python"}),
    )

    text = format_report(report)

    assert "NOT READY" in text
    assert "Blocking required backends" in text
    assert "- python (blocked)" in text
    assert "fix:" not in text
