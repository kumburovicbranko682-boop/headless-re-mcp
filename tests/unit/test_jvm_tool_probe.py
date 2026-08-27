"""The doctor must not call a JVM-backed tool ready when java cannot run it.

jadx, apktool and apksigner are launcher scripts that start a JVM, the same
shape as Ghidra's analyzeHeadless. The old probe found the launcher and reported
a plain "detected"; on a host with the launcher but no ``java`` on PATH every
call then failed when the launcher could not start the JVM, with nothing in the
doctor to have warned. ``probe_ghidra`` already reports "present but java is not
on PATH"; these pin that jadx/apktool/apksigner now share that honesty.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.doctor as doctor_module
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import ProbeStatus, probe_jvm_backed_tool, run_doctor

_EXE = ".bat" if os.name == "nt" else ""


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides)


def _no_which(monkeypatch: pytest.MonkeyPatch, resolver) -> None:
    monkeypatch.setattr(doctor_module.shutil, "which", resolver)


def test_configured_tool_without_java_stays_detected_but_flags_the_jre(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apktool present, java absent: detected (not ready) with a JRE remediation."""
    _no_which(monkeypatch, lambda _cmd: None)
    apktool = tmp_path / f"apktool{_EXE}"
    apktool.write_bytes(b"")

    probe = probe_jvm_backed_tool(
        "apktool", _settings(tmp_path, apktool=apktool), "apktool", ("apktool", "apktool.bat")
    )

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["java"] is None
    assert "java is not on PATH" in probe.summary
    assert "JRE" in (probe.remediation or "")


def test_configured_tool_with_java_reports_the_jre_and_no_remediation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    java = "/opt/jdk/bin/java"
    _no_which(monkeypatch, lambda cmd: java if cmd == "java" else None)
    jadx = tmp_path / f"jadx{_EXE}"
    jadx.write_bytes(b"")

    probe = probe_jvm_backed_tool(
        "jadx", _settings(tmp_path, jadx=jadx), "jadx", ("jadx", "jadx.bat")
    )

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["java"] == java
    assert "java is not on PATH" not in probe.summary
    assert probe.remediation is None


def test_missing_tool_is_left_untouched_and_never_mentions_java(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No launcher at all is a plain MISSING; the JRE is moot until it resolves."""
    _no_which(monkeypatch, lambda _cmd: None)

    probe = probe_jvm_backed_tool(
        "apksigner", _settings(tmp_path), "apksigner", ("apksigner", "apksigner.bat")
    )

    assert probe.status == ProbeStatus.MISSING
    assert "java" not in probe.details


def test_launcher_found_on_path_still_checks_for_java(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reachable case: jadx is on PATH from a package, but the box has no JRE.

    The launcher resolves through PATH rather than a configured path, so the java
    check has to run on that branch too -- not only for configured tools.
    """
    _no_which(
        monkeypatch,
        lambda cmd: "/usr/bin/jadx" if cmd in ("jadx", "jadx.bat") else None,
    )

    probe = probe_jvm_backed_tool(
        "jadx", _settings(tmp_path), "jadx", ("jadx", "jadx.bat")
    )

    assert probe.status == ProbeStatus.DETECTED
    assert "command detected" in probe.summary
    assert "java is not on PATH" in probe.summary
    assert probe.details["java"] is None


def test_run_doctor_routes_apktool_through_the_jvm_aware_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: a configured apktool with no java reads as detected-not-ready."""
    _no_which(monkeypatch, lambda _cmd: None)
    apktool = tmp_path / f"apktool{_EXE}"
    apktool.write_bytes(b"")

    report = run_doctor(_settings(tmp_path, apktool=apktool))
    by_name = {probe.name: probe for probe in report.probes}

    assert by_name["apktool"].status == ProbeStatus.DETECTED
    assert by_name["apktool"].details["java"] is None
    assert "java is not on PATH" in by_name["apktool"].summary
