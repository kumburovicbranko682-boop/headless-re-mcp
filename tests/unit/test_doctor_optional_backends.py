"""Readiness probes for the optional non-PE backends (Android, Web, .NET, portable).

`test_doctor.py` exercises the required PE/Windows core (IDA, x64dbg, Exeinfo
PE, UPX). The optional-backend probes that report whether the .NET, portable
and Android/Web toolchains are usable were left uncovered; this suite drives
each of them by faking the underlying CLI/version probes so the doctor's
ready/blocked/missing verdicts are pinned without any real tool on the host.
"""

from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.doctor as doctor_module
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import (
    DoctorReport,
    Probe,
    ProbeStatus,
    probe_de4dot,
    probe_die,
    probe_ghidra,
    probe_net_reactor_slayer,
    probe_python_module,
)


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides) if overrides else base


# --------------------------------------------------------------------------
# probe_de4dot (.NET deobfuscator CLI)
# --------------------------------------------------------------------------


def test_de4dot_probe_blocks_when_configured_path_is_missing(tmp_path: Path) -> None:
    settings = _settings(tmp_path, de4dot=tmp_path / "nope" / "de4dot.exe")
    probe = probe_de4dot(settings)
    assert probe.status == ProbeStatus.BLOCKED
    assert "does not exist" in probe.summary


def test_de4dot_probe_ready_when_cli_identifies_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "de4dot.exe"
    executable.touch()
    monkeypatch.setattr(
        "headless_re_mcp.dotnet.de4dot.probe_de4dot_version",
        lambda _exe: (True, "de4dot v3.1.41592"),
    )
    probe = probe_de4dot(_settings(tmp_path, de4dot=executable))
    assert probe.status == ProbeStatus.READY
    assert probe.details["probe_output"] == "de4dot v3.1.41592"
    assert "GPL" in probe.details["license_note"]


def test_de4dot_probe_blocks_when_cli_probe_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "de4dot.exe"
    executable.touch()
    monkeypatch.setattr(
        "headless_re_mcp.dotnet.de4dot.probe_de4dot_version",
        lambda _exe: (False, ""),
    )
    probe = probe_de4dot(_settings(tmp_path, de4dot=executable))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["probe_output"] is None


# --------------------------------------------------------------------------
# probe_net_reactor_slayer (.NET Reactor unpacker CLI)
# --------------------------------------------------------------------------


def test_net_reactor_slayer_probe_blocks_missing_file(tmp_path: Path) -> None:
    settings = _settings(tmp_path, net_reactor_slayer=tmp_path / "gone" / "slayer.exe")
    probe = probe_net_reactor_slayer(settings)
    assert probe.status == ProbeStatus.BLOCKED


def test_net_reactor_slayer_probe_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "slayer.exe"
    executable.touch()
    monkeypatch.setattr(
        "headless_re_mcp.dotnet.net_reactor_slayer.probe_net_reactor_slayer",
        lambda _exe: (True, "NETReactorSlayer 1.0"),
    )
    probe = probe_net_reactor_slayer(_settings(tmp_path, net_reactor_slayer=executable))
    assert probe.status == ProbeStatus.READY
    assert probe.details["license"] == "GPL-3.0"


def test_net_reactor_slayer_probe_blocks_on_failed_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "slayer.exe"
    executable.touch()
    monkeypatch.setattr(
        "headless_re_mcp.dotnet.net_reactor_slayer.probe_net_reactor_slayer",
        lambda _exe: (False, "boom"),
    )
    probe = probe_net_reactor_slayer(_settings(tmp_path, net_reactor_slayer=executable))
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["scope"] == "authorized_reactor_samples_only"


# --------------------------------------------------------------------------
# probe_ghidra (portable analysis backend)
# --------------------------------------------------------------------------


def test_ghidra_probe_missing_when_launcher_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "ghidra"
    home.mkdir()
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda _home: None,
    )
    probe = probe_ghidra(_settings(tmp_path, ghidra_home=home))
    assert probe.status == ProbeStatus.MISSING
    assert "analyzeHeadless" in probe.summary


def test_ghidra_probe_detected_when_java_is_off_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "ghidra"
    home.mkdir()
    analyze = home / "support" / "analyzeHeadless"
    analyze.parent.mkdir(parents=True)
    analyze.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda _home: analyze,
    )
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: None)
    probe = probe_ghidra(_settings(tmp_path, ghidra_home=home))
    assert probe.status == ProbeStatus.DETECTED
    assert "java is not on PATH" in probe.summary


def test_ghidra_probe_ready_with_java(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "ghidra"
    home.mkdir()
    analyze = home / "support" / "analyzeHeadless"
    analyze.parent.mkdir(parents=True)
    analyze.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        "headless_re_mcp.backends.ghidra.client._find_analyze_headless",
        lambda _home: analyze,
    )
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: "/usr/bin/java")
    probe = probe_ghidra(_settings(tmp_path, ghidra_home=home))
    assert probe.status == ProbeStatus.READY
    assert probe.details["java"] == "/usr/bin/java"


# --------------------------------------------------------------------------
# probe_python_module (Android/Web importable-module detection)
# --------------------------------------------------------------------------


def test_python_module_probe_detects_installed_module() -> None:
    # A module guaranteed importable stands in for frida/androguard/playwright.
    probe = probe_python_module("frida", "json")
    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["origin"]


def test_python_module_probe_reports_absent_module() -> None:
    probe = probe_python_module("frida", "definitely_not_a_real_module_xyz")
    assert probe.status == ProbeStatus.MISSING


# --------------------------------------------------------------------------
# Detect It Easy CLI error arms + shared probe helpers.
# --------------------------------------------------------------------------


def test_die_probe_blocks_missing_configured_file(tmp_path: Path) -> None:
    settings = _settings(tmp_path, diec=tmp_path / "absent" / "diec.exe")
    probe = probe_die(settings)
    assert probe.status == ProbeStatus.BLOCKED
    assert "does not exist" in probe.summary


def test_die_probe_blocks_when_launch_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "diec.exe"
    executable.touch()

    def _boom(command: list[str], *, timeout: float, env: object = None) -> object:
        del command, timeout, env
        raise TimedOut(5.0, [])

    monkeypatch.setattr(doctor_module, "_probe_run", _boom)
    probe = probe_die(_settings(tmp_path, diec=executable))
    assert probe.status == ProbeStatus.BLOCKED
    assert "TimedOut" in probe.details["error"]


def test_probe_run_decodes_bounded_output(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_bounded(command: list[str], **kwargs: object) -> Completed:
        assert kwargs["timeout"] == 5
        return Completed(0, b"out\n", b"err\n")

    monkeypatch.setattr(doctor_module, "run_bounded", fake_bounded)
    result = doctor_module._probe_run(["tool", "--version"], timeout=5)
    assert result.returncode == 0
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"


def test_bounded_text_truncates_oversized_output() -> None:
    text = doctor_module._bounded_text("x" * 5000, limit=4096)
    assert text.endswith("...[truncated]")
    assert len(text) <= 4096 + len("\n...[truncated]")


def test_no_window_flags_is_zero_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor_module.os, "name", "posix")
    assert doctor_module._no_window_flags() == 0
    monkeypatch.setattr(doctor_module.os, "name", "nt")
    # subprocess.CREATE_NO_WINDOW is absent off Windows, so the getattr default holds.
    assert doctor_module._no_window_flags() == getattr(subprocess, "CREATE_NO_WINDOW", 0)


def test_report_serialises_to_json_and_probe_dict_omits_required() -> None:
    probe = Probe("ghidra", ProbeStatus.DETECTED, "found", {"home": "/x"})
    assert "required" not in probe.to_dict()  # default: no required flag

    report = DoctorReport(
        (Probe("platform", ProbeStatus.READY, "ok"), probe),
        required_probes=frozenset({"platform"}),
    )
    import json as _json

    payload = _json.loads(report.to_json())
    assert payload["ready"] is True
    names = {entry["name"]: entry for entry in payload["probes"]}
    assert names["platform"]["required"] is True
    assert names["ghidra"]["required"] is False
