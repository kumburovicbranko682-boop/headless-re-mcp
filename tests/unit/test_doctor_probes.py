"""Doctor probes for optional foreign tools must classify without side effects.

Each ``probe_*`` reads an operator-configured path and reports MISSING (not
set), BLOCKED (set but unusable), DETECTED or READY. The tools themselves are
absent here, so the CLI seams (``_probe_run`` and the per-tool ``probe_*``
adapters) are faked to drive every classification branch: an unconfigured tool
never blocks readiness, a stale path is reported clearly, and a probe failure
degrades to BLOCKED rather than raising.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.doctor as doctor_module
from headless_re_mcp.config import Settings
from headless_re_mcp.detection.exeinfope import (
    ExeinfopeGuiWindowError,
    ExeinfopeScanError,
)
from headless_re_mcp.doctor import (
    ProbeStatus,
    _bounded_text,
    _no_window_flags,
    _probe_run,
    probe_de4dot,
    probe_die,
    probe_exeinfope,
    probe_ghidra,
    probe_native_toolchain,
    probe_net_reactor_slayer,
    probe_scylla,
    probe_upx,
    probe_vmp_dumper,
    probe_x64dbg_binaries,
    probe_x64dbg_scyllahide,
    probe_xvlkc,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def _executable(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Delegated optional-CLI probes: (settings attr, probe, patch target)
# --------------------------------------------------------------------------

_DELEGATED: list[tuple[str, Callable[[Settings], Any], str]] = [
    ("de4dot", probe_de4dot, "headless_re_mcp.dotnet.de4dot.probe_de4dot_version"),
    (
        "net_reactor_slayer",
        probe_net_reactor_slayer,
        "headless_re_mcp.dotnet.net_reactor_slayer.probe_net_reactor_slayer",
    ),
    ("xvlkc", probe_xvlkc, "headless_re_mcp.unpack.xvlkc.probe_xvlkc"),
    ("vmp_dumper", probe_vmp_dumper, "headless_re_mcp.unpack.vmp_dumper.probe_vmp_dumper"),
    ("scylla", probe_scylla, "headless_re_mcp.unpack.scylla.probe_scylla"),
]


@pytest.mark.parametrize("attr,probe_fn,_target", _DELEGATED, ids=[a for a, *_ in _DELEGATED])
def test_delegated_probe_is_missing_when_unconfigured(
    tmp_path: Path, attr: str, probe_fn: Callable[[Settings], Any], _target: str
) -> None:
    probe = probe_fn(_settings(tmp_path))
    assert probe.status == ProbeStatus.MISSING


@pytest.mark.parametrize("attr,probe_fn,_target", _DELEGATED, ids=[a for a, *_ in _DELEGATED])
def test_delegated_probe_is_blocked_when_path_is_stale(
    tmp_path: Path, attr: str, probe_fn: Callable[[Settings], Any], _target: str
) -> None:
    settings = replace(_settings(tmp_path), **{attr: tmp_path / "not-here"})  # type: ignore[arg-type]
    probe = probe_fn(settings)
    assert probe.status == ProbeStatus.BLOCKED


@pytest.mark.parametrize("attr,probe_fn,target", _DELEGATED, ids=[a for a, *_ in _DELEGATED])
def test_delegated_probe_is_ready_when_the_cli_answers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attr: str,
    probe_fn: Callable[[Settings], Any],
    target: str,
) -> None:
    executable = _executable(tmp_path, attr)
    settings = replace(_settings(tmp_path), **{attr: executable})  # type: ignore[arg-type]
    monkeypatch.setattr(target, lambda _exe: (True, "version 1.2.3"))
    probe = probe_fn(settings)
    assert probe.status == ProbeStatus.READY
    assert probe.details["executable"] == str(executable)


@pytest.mark.parametrize("attr,probe_fn,target", _DELEGATED, ids=[a for a, *_ in _DELEGATED])
def test_delegated_probe_is_blocked_when_the_cli_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attr: str,
    probe_fn: Callable[[Settings], Any],
    target: str,
) -> None:
    executable = _executable(tmp_path, attr)
    settings = replace(_settings(tmp_path), **{attr: executable})  # type: ignore[arg-type]
    monkeypatch.setattr(target, lambda _exe: (False, "unusable build"))
    probe = probe_fn(settings)
    assert probe.status == ProbeStatus.BLOCKED


# --------------------------------------------------------------------------
# _probe_run-backed probes: diec and upx
# --------------------------------------------------------------------------


def test_probe_die_is_blocked_when_path_is_stale(tmp_path: Path) -> None:
    settings = replace(_settings(tmp_path), diec=tmp_path / "not-here")
    assert probe_die(settings).status == ProbeStatus.BLOCKED


def test_probe_die_is_blocked_when_the_probe_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(_settings(tmp_path), diec=_executable(tmp_path, "diec"))

    def boom(command: list[str], *, timeout: float, env: Any = None) -> Any:
        raise OSError("cannot execute")

    monkeypatch.setattr(doctor_module, "_probe_run", boom)
    probe = probe_die(settings)
    assert probe.status == ProbeStatus.BLOCKED
    assert "OSError" in probe.details["error"]


def test_probe_die_is_ready_for_a_json_capable_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(_settings(tmp_path), diec=_executable(tmp_path, "diec"))

    def fake(command: list[str], *, timeout: float, env: Any = None) -> Any:
        if command[-1] == "--version":
            return doctor_module._ProbeOutput(0, "Detect It Easy v3.09", "")
        return doctor_module._ProbeOutput(0, "usage: diec --json <file>", "")

    monkeypatch.setattr(doctor_module, "_probe_run", fake)
    probe = probe_die(settings)
    assert probe.status == ProbeStatus.READY
    assert probe.details["version"] == "3.09"


def test_probe_upx_is_blocked_when_path_is_stale(tmp_path: Path) -> None:
    settings = replace(_settings(tmp_path), upx=tmp_path / "not-here")
    assert probe_upx(settings).status == ProbeStatus.BLOCKED


def test_probe_upx_is_blocked_when_the_probe_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(_settings(tmp_path), upx=_executable(tmp_path, "upx"))

    def boom(command: list[str], *, timeout: float, env: Any = None) -> Any:
        raise OSError("cannot execute")

    monkeypatch.setattr(doctor_module, "_probe_run", boom)
    assert probe_upx(settings).status == ProbeStatus.BLOCKED


# --------------------------------------------------------------------------
# exeinfope: silent-scan probe with a synthetic PE
# --------------------------------------------------------------------------


def _fake_exeinfope_result(findings: list[Any]) -> Any:
    return SimpleNamespace(
        findings=findings,
        source=SimpleNamespace(duration_ms=12),
        returncode=0,
        raw_log="log-body",
    )


def test_probe_exeinfope_is_ready_with_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(_settings(tmp_path), exeinfope=_executable(tmp_path, "exeinfope"))
    monkeypatch.setattr(
        "headless_re_mcp.detection.exeinfope.scan_with_exeinfope",
        lambda *a, **k: _fake_exeinfope_result([object()]),
    )
    probe = probe_exeinfope(settings)
    assert probe.status == ProbeStatus.READY
    assert probe.details["findings"] == 1


def test_probe_exeinfope_is_blocked_on_empty_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(_settings(tmp_path), exeinfope=_executable(tmp_path, "exeinfope"))
    monkeypatch.setattr(
        "headless_re_mcp.detection.exeinfope.scan_with_exeinfope",
        lambda *a, **k: _fake_exeinfope_result([]),
    )
    assert probe_exeinfope(settings).status == ProbeStatus.BLOCKED


def test_probe_exeinfope_is_blocked_on_a_visible_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(_settings(tmp_path), exeinfope=_executable(tmp_path, "exeinfope"))

    def raise_gui(*a: Any, **k: Any) -> Any:
        raise ExeinfopeGuiWindowError(["Exeinfo PE"])

    monkeypatch.setattr(
        "headless_re_mcp.detection.exeinfope.scan_with_exeinfope", raise_gui
    )
    probe = probe_exeinfope(settings)
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["analyzer_windows"] == ["Exeinfo PE"]


def test_probe_exeinfope_is_blocked_on_a_scan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(_settings(tmp_path), exeinfope=_executable(tmp_path, "exeinfope"))

    def raise_scan(*a: Any, **k: Any) -> Any:
        raise ExeinfopeScanError("probe_failed", "scan did not run")

    monkeypatch.setattr(
        "headless_re_mcp.detection.exeinfope.scan_with_exeinfope", raise_scan
    )
    probe = probe_exeinfope(settings)
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["code"] == "probe_failed"


def test_probe_exeinfope_is_blocked_when_it_cannot_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(_settings(tmp_path), exeinfope=_executable(tmp_path, "exeinfope"))

    def raise_os(*a: Any, **k: Any) -> Any:
        raise OSError("permission denied")

    monkeypatch.setattr(
        "headless_re_mcp.detection.exeinfope.scan_with_exeinfope", raise_os
    )
    assert probe_exeinfope(settings).status == ProbeStatus.BLOCKED


# --------------------------------------------------------------------------
# ghidra: analyzeHeadless + java discovery
# --------------------------------------------------------------------------


def test_probe_ghidra_is_missing_without_a_home(tmp_path: Path) -> None:
    assert probe_ghidra(_settings(tmp_path)).status == ProbeStatus.MISSING


def test_probe_ghidra_is_missing_without_analyze_headless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(_settings(tmp_path), ghidra_home=tmp_path)
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda _home: None,
    )
    assert probe_ghidra(settings).status == ProbeStatus.MISSING


def test_probe_ghidra_is_detected_without_java(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    analyze = _executable(tmp_path, "analyzeHeadless")
    settings = replace(_settings(tmp_path), ghidra_home=tmp_path)
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda _home: analyze,
    )
    monkeypatch.setattr("headless_re_mcp.doctor.shutil.which", lambda _cmd: None)
    assert probe_ghidra(settings).status == ProbeStatus.DETECTED


def test_probe_ghidra_is_ready_with_java(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    analyze = _executable(tmp_path, "analyzeHeadless")
    settings = replace(_settings(tmp_path), ghidra_home=tmp_path)
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda _home: analyze,
    )
    monkeypatch.setattr(
        "headless_re_mcp.doctor.shutil.which",
        lambda cmd: "/usr/bin/java" if cmd == "java" else None,
    )
    probe = probe_ghidra(settings)
    assert probe.status == ProbeStatus.READY
    assert probe.details["java"] == "/usr/bin/java"


# --------------------------------------------------------------------------
# native toolchain + x64dbg binary/plugin probes
# --------------------------------------------------------------------------


def test_probe_native_toolchain_is_ready_when_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.doctor.shutil.which",
        lambda cmd: f"/usr/bin/{cmd}" if cmd in {"cmake", "ninja", "cl"} else None,
    )
    assert probe_native_toolchain().status == ProbeStatus.READY


def test_probe_native_toolchain_is_blocked_when_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("headless_re_mcp.doctor.shutil.which", lambda _cmd: None)
    assert probe_native_toolchain().status == ProbeStatus.BLOCKED


def test_probe_x64dbg_binaries_missing_when_not_both_present(tmp_path: Path) -> None:
    settings = replace(
        _settings(tmp_path), x64dbg_headless_x64=_executable(tmp_path, "x64")
    )
    assert probe_x64dbg_binaries(settings).status == ProbeStatus.MISSING


def test_probe_x64dbg_binaries_blocked_when_gate_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(
        _settings(tmp_path),
        x64dbg_headless_x64=_executable(tmp_path, "x64"),
        x64dbg_headless_x86=_executable(tmp_path, "x86"),
    )

    def boom(path: Path, architecture: Any, *, timeout: float) -> Any:
        raise OSError("not a valid executable")

    monkeypatch.setattr(doctor_module, "run_command_loop_gate", boom)
    probe = probe_x64dbg_binaries(settings)
    assert probe.status == ProbeStatus.BLOCKED


def test_probe_x64dbg_scyllahide_missing_plugins(tmp_path: Path) -> None:
    # A configured headless with no ScyllaHide files beside it reports missing.
    headless = _executable(tmp_path, "x64dbg.exe")
    settings = replace(_settings(tmp_path), x64dbg_headless_x64=headless)
    probe = probe_x64dbg_scyllahide(settings)
    assert probe.status == ProbeStatus.MISSING


# --------------------------------------------------------------------------
# probe run helpers
# --------------------------------------------------------------------------


def test_no_window_flags_is_zero_off_windows() -> None:
    assert _no_window_flags() == 0


def test_no_window_flags_consults_subprocess_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("headless_re_mcp.doctor.os.name", "nt")
    assert isinstance(_no_window_flags(), int)


def test_probe_run_decodes_bounded_output(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command: list[str], *, timeout: float, creationflags: int, env: Any) -> Any:
        return SimpleNamespace(returncode=0, stdout=b"out\xff", stderr=b"err")

    monkeypatch.setattr(doctor_module, "run_bounded", fake_run)
    output = _probe_run(["tool", "--version"], timeout=1.0)
    assert output.returncode == 0
    assert output.stdout.startswith("out")
    assert output.stderr == "err"


def test_bounded_text_truncates_beyond_limit() -> None:
    result = _bounded_text("a" * 6000)
    assert result.endswith("[truncated]")
    assert len(result) <= 4096 + len("\n...[truncated]")
