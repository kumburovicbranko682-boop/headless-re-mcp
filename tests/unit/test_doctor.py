from __future__ import annotations

import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.doctor as doctor_module
from headless_re_mcp.backends.x64dbg.gate import XdbgHeadlessGateResult
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.doctor import (
    WINDOWS_REQUIRED_PROBES,
    DoctorReport,
    Probe,
    ProbeStatus,
    format_report,
    probe_die,
    probe_exeinfope,
    probe_optional_tool,
    probe_upx,
    probe_x64dbg_binaries,
    probe_x64dbg_source,
    run_doctor,
)


def _as_probe_run(fake_run: object) -> object:
    """Adapt a CompletedProcess-shaped fake to the probe seam.

    The probes no longer call subprocess.run directly: a configured tool path is
    often a launcher, and subprocess.run kills only the launcher on timeout and
    then drains with no deadline, which hangs the doctor. Patching the seam
    keeps these tests about what a probe makes of the output.
    """

    def run(command: list[str], *, timeout: float, env: object = None) -> object:
        del env
        completed = fake_run(command, timeout=timeout, capture_output=True)  # type: ignore[operator]
        return doctor_module._ProbeOutput(
            completed.returncode, completed.stdout or "", completed.stderr or ""
        )

    return run


def _settings(
    source: Path | None,
    artifacts: Path,
    *,
    x86: Path | None = None,
    x64: Path | None = None,
) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=source,
        x64dbg_headless_x64=x64,
        x64dbg_headless_x86=x86,
        artifact_root=artifacts,
    )


def test_radare2_probe_honors_a_configured_off_path_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """doctor must not report radare2 MISSING when r2 is configured off PATH.

    r2.* runs ``R2Client(settings.r2)``, which uses the configured path directly,
    so a probe that consulted only PATH (``shutil.which``) reported the backend
    missing while the tools worked -- the same doctor/tool split the webcrack
    resolver fixed. Configured-first with a PATH fallback matches every other
    optional-CLI probe (adb, jadx, apktool, webcrack, wabt).
    """
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: None)
    r2 = tmp_path / "vendor" / "r2"
    r2.parent.mkdir(parents=True)
    r2.write_text("#!/bin/sh\n", encoding="utf-8")
    settings = replace(_settings(None, tmp_path / "artifacts"), r2=r2)

    report = run_doctor(settings)

    probe = next(p for p in report.probes if p.name == "radare2")
    assert probe.status == ProbeStatus.DETECTED
    assert probe.details.get("path") == str(r2)


def test_radare2_probe_falls_back_to_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    on_path = tmp_path / "r2"
    on_path.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        doctor_module.shutil, "which", lambda cmd: str(on_path) if cmd == "r2" else None
    )
    settings = replace(_settings(None, tmp_path / "artifacts"), r2=None)

    probe = probe_optional_tool("radare2", settings, "r2", ("r2", "rizin"))

    assert probe.status == ProbeStatus.DETECTED


def test_radare2_probe_missing_when_neither_configured_nor_on_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: None)
    settings = replace(_settings(None, tmp_path / "artifacts"), r2=None)

    probe = probe_optional_tool("radare2", settings, "r2", ("r2", "rizin"))

    assert probe.status == ProbeStatus.MISSING


def test_x64dbg_source_probe_requires_official_target(tmp_path: Path) -> None:
    source = tmp_path / "x64dbg"
    (source / "src" / "headless").mkdir(parents=True)
    (source / "src" / "headless" / "headless.cpp").write_text("int main(){}", encoding="utf-8")
    (source / "CMakeLists.txt").write_text("project(x64dbg)", encoding="utf-8")
    probe = probe_x64dbg_source(_settings(source, tmp_path / "artifacts"))
    assert probe.status == ProbeStatus.BLOCKED


def test_x64dbg_source_probe_accepts_official_target_shape(tmp_path: Path) -> None:
    source = tmp_path / "x64dbg"
    (source / "src" / "headless").mkdir(parents=True)
    (source / "src" / "headless" / "headless.cpp").write_text("int main(){}", encoding="utf-8")
    (source / "CMakeLists.txt").write_text("add_executable(headless)", encoding="utf-8")
    probe = probe_x64dbg_source(_settings(source, tmp_path / "artifacts"))
    assert probe.status == ProbeStatus.READY


def test_x64dbg_source_probe_bounds_cmake_project_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "x64dbg"
    (source / "src" / "headless").mkdir(parents=True)
    (source / "src" / "headless" / "headless.cpp").write_text(
        "int main(){}", encoding="utf-8"
    )
    (source / "CMakeLists.txt").write_bytes(b"x" * 1024)
    monkeypatch.setattr(doctor_module, "_MAX_CMAKE_FILE_BYTES", 64)

    probe = probe_x64dbg_source(_settings(source, tmp_path / "artifacts"))

    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["max_bytes"] == 64
    assert probe.details["size_at_least"] == 65


def _gate_result(
    executable: Path,
    architecture: Architecture,
    *,
    ok: bool = True,
) -> XdbgHeadlessGateResult:
    return XdbgHeadlessGateResult(
        ok=ok,
        architecture=architecture,
        executable=str(executable),
        exit_code=0 if ok else 1,
        stdout="[headless] entering command loop..." if ok else "",
        stderr="" if ok else "startup failed",
        analyzer_windows=(),
        command_loop_seen=ok,
    )


def test_x64dbg_binary_probe_runtime_gates_both_architectures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    x86 = tmp_path / "headless-x86.exe"
    x64 = tmp_path / "headless-x64.exe"
    x86.touch()
    x64.touch()
    calls: list[Architecture] = []

    def fake_gate(
        executable: Path,
        architecture: Architecture,
        *,
        timeout: float,
    ) -> XdbgHeadlessGateResult:
        assert timeout == 15.0
        calls.append(architecture)
        return _gate_result(executable, architecture)

    monkeypatch.setattr(doctor_module, "run_command_loop_gate", fake_gate)
    probe = probe_x64dbg_binaries(
        _settings(None, tmp_path / "artifacts", x86=x86, x64=x64)
    )

    assert probe.status == ProbeStatus.READY
    assert set(calls) == {Architecture.X86, Architecture.X64}


def test_x64dbg_binary_probe_blocks_on_failed_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    x86 = tmp_path / "headless-x86.exe"
    x64 = tmp_path / "headless-x64.exe"
    x86.touch()
    x64.touch()

    def fake_gate(
        executable: Path,
        architecture: Architecture,
        *,
        timeout: float,
    ) -> XdbgHeadlessGateResult:
        assert timeout == 15.0
        return _gate_result(
            executable,
            architecture,
            ok=architecture == Architecture.X64,
        )

    monkeypatch.setattr(doctor_module, "run_command_loop_gate", fake_gate)
    probe = probe_x64dbg_binaries(
        _settings(None, tmp_path / "artifacts", x86=x86, x64=x64)
    )

    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["x86"]["exit_code"] == 1


def test_doctor_requires_runtime_gated_x64dbg_binaries() -> None:
    required = (
        Probe("platform", ProbeStatus.READY, "ready"),
        Probe("python", ProbeStatus.READY, "ready"),
        Probe("ida_idalib", ProbeStatus.READY, "ready"),
        Probe("x64dbg_source", ProbeStatus.READY, "ready"),
        Probe("native_toolchain", ProbeStatus.READY, "ready"),
    )
    assert not DoctorReport(required, required_probes=WINDOWS_REQUIRED_PROBES).ready
    assert DoctorReport(
        (*required, Probe("x64dbg_headless_binaries", ProbeStatus.READY, "ready")),
        required_probes=WINDOWS_REQUIRED_PROBES,
    ).ready


def test_doctor_ready_does_not_require_source_tree_or_msvc() -> None:
    assert DoctorReport(
        (
            Probe("platform", ProbeStatus.READY, "ready"),
            Probe("python", ProbeStatus.READY, "ready"),
            Probe("ida_idalib", ProbeStatus.READY, "ready"),
            Probe("x64dbg_headless_binaries", ProbeStatus.READY, "ready"),
            Probe("x64dbg_source", ProbeStatus.MISSING, "optional"),
            Probe("native_toolchain", ProbeStatus.MISSING, "optional"),
        ),
        required_probes=WINDOWS_REQUIRED_PROBES,
    ).ready


def test_die_probe_is_optional_when_unconfigured(tmp_path: Path) -> None:
    probe = probe_die(_settings(None, tmp_path / "artifacts"))

    assert probe.status == ProbeStatus.MISSING
    assert "HEADLESS_RE_DIEC" in (probe.remediation or "")


def test_die_probe_verifies_version_and_json_interface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "diec.exe"
    executable.touch()
    settings = _settings(None, tmp_path / "artifacts")
    settings = replace(settings, diec=executable)
    commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        assert kwargs["timeout"] == 5
        assert kwargs["capture_output"] is True
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, stdout="die 3.21\n", stderr="")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="--json  Result as JSON\n",
            stderr="",
        )

    monkeypatch.setattr(doctor_module, "_probe_run", _as_probe_run(fake_run))
    probe = probe_die(settings)

    assert probe.status == ProbeStatus.READY
    assert probe.details["version"] == "3.21"
    assert probe.details["json_capable"] is True
    assert [command[-1] for command in commands] == ["--version", "--help"]


def test_die_probe_blocks_cli_without_json_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "diec.exe"
    executable.touch()
    settings = _settings(None, tmp_path / "artifacts")
    settings = replace(settings, diec=executable)

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        output = "die 3.21" if command[-1] == "--version" else "plain output only"
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr(doctor_module, "_probe_run", _as_probe_run(fake_run))

    assert probe_die(settings).status == ProbeStatus.BLOCKED


def test_die_probe_accepts_short_json_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "diec.exe"
    executable.touch()
    settings = replace(_settings(None, tmp_path / "artifacts"), diec=executable)

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, stdout="die 3.21\n", stderr="")
        # Official help may list only the short -j form.
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="Usage: diec [options] file\n -j  Result as JSON\n",
            stderr="",
        )

    monkeypatch.setattr(doctor_module, "_probe_run", _as_probe_run(fake_run))
    probe = probe_die(settings)

    assert probe.status == ProbeStatus.READY
    assert probe.details["json_capable"] is True


def test_exeinfope_probe_is_optional_when_unconfigured(tmp_path: Path) -> None:
    probe = probe_exeinfope(_settings(None, tmp_path / "artifacts"))

    assert probe.status == ProbeStatus.MISSING
    assert "HEADLESS_RE_EXEINFOPE" in (probe.remediation or "")


def test_exeinfope_probe_blocks_missing_file(tmp_path: Path) -> None:
    settings = replace(
        _settings(None, tmp_path / "artifacts"),
        exeinfope=tmp_path / "missing-exeinfope.exe",
    )
    probe = probe_exeinfope(settings)
    assert probe.status == ProbeStatus.BLOCKED


def test_exeinfope_probe_ready_when_silent_scan_works(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime

    from headless_re_mcp.detection.exeinfope import ExeinfopeScanResult
    from headless_re_mcp.detection.models import (
        DetectionEvidence,
        DetectionFinding,
        DetectionSource,
        FindingCategory,
        ScanMode,
    )

    executable = tmp_path / "Exeinfope.exe"
    executable.touch()
    settings = replace(_settings(None, tmp_path / "artifacts"), exeinfope=executable)

    def fake_scan(executable_path, path, *, log_path, timeout=30.0, **kwargs):
        del executable_path, timeout, kwargs
        log_path.write_text("doctor-sample.exe -  x64 Microsoft Visual C++\n", encoding="utf-8")
        finding = DetectionFinding(
            id="exeinfope:0",
            category=FindingCategory.COMPILER,
            name="Microsoft",
            summary="x64 Microsoft Visual C++",
            confidence=0.55,
            source="exeinfope",
            evidence=(
                DetectionEvidence(
                    kind="exeinfope_log_line",
                    description="x64 Microsoft Visual C++",
                    details={"raw_line": "x", "parser": "best_effort"},
                ),
            ),
        )
        return ExeinfopeScanResult(
            path=path,
            size=path.stat().st_size,
            mode=ScanMode.NORMAL,
            findings=(finding,),
            source=DetectionSource(
                name="exeinfope",
                status="completed",
                duration_ms=12,
                summary="probe",
            ),
            raw_log="doctor-sample.exe -  x64 Microsoft Visual C++\n",
            log_path=log_path,
            stdout="",
            stderr="",
            returncode=0,
            scanned_at=datetime.now(UTC),
        )

    monkeypatch.setattr(
        "headless_re_mcp.detection.exeinfope.scan_with_exeinfope",
        fake_scan,
    )
    probe = probe_exeinfope(settings)
    assert probe.status == ProbeStatus.READY
    assert probe.details["claims_universal_unpack"] is False


def test_upx_probe_is_optional_when_unconfigured(tmp_path: Path) -> None:
    probe = probe_upx(_settings(None, tmp_path / "artifacts"))

    assert probe.status == ProbeStatus.MISSING
    assert "HEADLESS_RE_UPX" in (probe.remediation or "")


def test_upx_probe_verifies_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "upx.exe"
    executable.touch()
    settings = replace(_settings(None, tmp_path / "artifacts"), upx=executable)

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[-1] == "--version"
        assert kwargs["timeout"] == 5
        assert kwargs["capture_output"] is True
        return subprocess.CompletedProcess(command, 0, stdout="upx 5.2.0\n", stderr="")

    monkeypatch.setattr(doctor_module, "_probe_run", _as_probe_run(fake_run))
    probe = probe_upx(settings)

    assert probe.status == ProbeStatus.READY
    assert probe.details["version"] == "5.2.0"


def test_upx_probe_blocks_without_usable_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "upx.exe"
    executable.touch()
    settings = replace(_settings(None, tmp_path / "artifacts"), upx=executable)

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(command, 0, stdout="not-upx-tool\n", stderr="")

    monkeypatch.setattr(doctor_module, "_probe_run", _as_probe_run(fake_run))
    assert probe_upx(settings).status == ProbeStatus.BLOCKED


def test_isolation_probe_blocks_on_elevated_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_module, "_is_elevated", lambda: True)
    monkeypatch.setattr(doctor_module, "_VM_DRIVER_HINTS", ())

    probe = doctor_module.probe_isolation(_settings(None, tmp_path / "artifacts"))

    assert probe.status == ProbeStatus.BLOCKED
    assert "low-privilege" in (probe.remediation or "")


def test_isolation_probe_accepts_hidden_desktop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_module, "_is_elevated", lambda: False)
    monkeypatch.setattr(doctor_module, "_VM_DRIVER_HINTS", ())
    monkeypatch.setattr(
        doctor_module,
        "runtime_platform_report",
        lambda: {"name": "windows"},
    )
    settings = replace(_settings(None, tmp_path / "artifacts"), hidden_desktop=True)

    probe = doctor_module.probe_isolation(settings)

    assert probe.status == ProbeStatus.READY
    assert probe.details["hidden_desktop"] is True


def test_isolation_probe_is_advisory_and_never_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_module, "_is_elevated", lambda: False)
    monkeypatch.setattr(doctor_module, "_VM_DRIVER_HINTS", ())

    probe = doctor_module.probe_isolation(_settings(None, tmp_path / "artifacts"))

    assert probe.status == ProbeStatus.MISSING
    assert probe.details["advisory"] is True
    assert "isolation" not in doctor_module.REQUIRED_PROBES


def _all_required_ready() -> tuple[Probe, ...]:
    return tuple(
        Probe(name, ProbeStatus.READY, f"{name} ready")
        for name in (
            "platform",
            "python",
            "ida_idalib",
            "x64dbg_headless_binaries",
        )
    )


def test_format_report_ready_lists_required_count() -> None:
    text = format_report(
        DoctorReport(_all_required_ready(), required_probes=WINDOWS_REQUIRED_PROBES)
    )
    assert text.splitlines()[0] == "Overall: READY (required 4/4 ready)"
    assert "Required core components:" in text
    assert "Blocking required backends" not in text


def test_format_report_flags_blocking_required_and_groups_optional() -> None:
    required = (
        Probe("platform", ProbeStatus.READY, "supported"),
        Probe("python", ProbeStatus.READY, "Python 3.12"),
        Probe(
            "ida_idalib",
            ProbeStatus.MISSING,
            "IDA not found",
            remediation="Set HEADLESS_RE_IDA_HOME.",
        ),
        Probe("x64dbg_headless_binaries", ProbeStatus.READY, "ok"),
    )
    optional = (
        Probe("diec", ProbeStatus.MISSING, "optional DIE not set"),
        Probe("windbg", ProbeStatus.UNSUPPORTED, "Windows only"),
    )
    text = format_report(
        DoctorReport((*required, *optional), required_probes=WINDOWS_REQUIRED_PROBES)
    )

    assert text.splitlines()[0] == "Overall: NOT READY (required 3/4 ready)"
    assert "Optional backends:" in text
    assert "Unsupported on this platform (optional):" in text
    assert "Blocking required backends (resolve these first):" in text
    assert "- ida_idalib (missing)" in text
    assert "Set HEADLESS_RE_IDA_HOME." in text


@pytest.mark.skipif(os.name == "nt", reason="Linux platform policy")
def test_linux_doctor_requires_only_portable_core(tmp_path: Path) -> None:
    report = run_doctor(_settings(None, tmp_path / "artifacts"))
    statuses = {probe.name: probe.status for probe in report.probes}

    assert report.ready is True
    assert report.required_probes == frozenset({"platform", "python"})
    assert statuses["platform"] == ProbeStatus.READY
    for name in (
        "x64dbg_headless_binaries",
        "windbg",
        "win32_ui",
        "hidden_desktop",
    ):
        assert statuses[name] == ProbeStatus.UNSUPPORTED

    payload = report.to_dict()
    assert payload["platform"]["name"] == "linux"
    assert payload["platform"]["support_level"] == "core"
    required = {
        probe["name"]
        for probe in payload["probes"]
        if probe["required"] is True
    }
    assert required == {"platform", "python"}


@pytest.mark.skipif(os.name == "nt", reason="Linux platform policy")
def test_linux_hidden_desktop_setting_is_not_an_isolation_signal(tmp_path: Path) -> None:
    settings = replace(
        _settings(None, tmp_path / "artifacts"),
        hidden_desktop=True,
    )
    probe = doctor_module.probe_isolation(settings)

    assert probe.status == ProbeStatus.MISSING
    assert probe.details["hidden_desktop"] is True
    assert probe.details["hidden_desktop_supported"] is False


def test_python_module_probe_reports_installed_and_missing_modules() -> None:
    """frida/androguard/playwright/mitmproxy probes rely on this helper."""
    detected = doctor_module.probe_python_module("json-probe", "json")
    missing = doctor_module.probe_python_module(
        "ghost", "headless_re_mcp_definitely_not_a_module"
    )

    assert detected.status == ProbeStatus.DETECTED
    assert "origin" in detected.details
    assert missing.status == ProbeStatus.MISSING
    assert "not installed" in missing.summary


def test_command_probe_detects_java_on_path_and_reports_it_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor_module.shutil,
        "which",
        lambda cmd: "/usr/bin/java" if cmd == "java" else None,
    )
    assert doctor_module.probe_command("java", ("java",)).status == ProbeStatus.DETECTED

    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: None)
    missing = doctor_module.probe_command("java", ("java",))
    assert missing.status == ProbeStatus.MISSING


def test_ghidra_probe_is_optional_when_home_is_not_configured(tmp_path: Path) -> None:
    probe = doctor_module.probe_ghidra(_settings(None, tmp_path / "artifacts"))

    assert probe.status == ProbeStatus.MISSING
    assert "HEADLESS_RE_GHIDRA_HOME" in (probe.remediation or "")


def test_ghidra_probe_flags_a_home_without_analyze_headless(tmp_path: Path) -> None:
    home = tmp_path / "ghidra"
    home.mkdir()
    settings = replace(_settings(None, tmp_path / "artifacts"), ghidra_home=home)

    probe = doctor_module.probe_ghidra(settings)

    assert probe.status == ProbeStatus.MISSING
    assert "analyzeHeadless not found" in probe.summary
    assert probe.details["home"] == str(home)


def _ghidra_home_with_launcher(tmp_path: Path) -> Path:
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    (home / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    return home


def test_ghidra_probe_detects_launcher_but_warns_when_java_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _ghidra_home_with_launcher(tmp_path)
    settings = replace(_settings(None, tmp_path / "artifacts"), ghidra_home=home)
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: None)

    probe = doctor_module.probe_ghidra(settings)

    assert probe.status == ProbeStatus.DETECTED
    assert "java is not on PATH" in probe.summary
    assert "Install a JRE" in (probe.remediation or "")


def test_ghidra_probe_is_ready_with_launcher_and_java(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _ghidra_home_with_launcher(tmp_path)
    settings = replace(_settings(None, tmp_path / "artifacts"), ghidra_home=home)
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: "/usr/bin/java")

    probe = doctor_module.probe_ghidra(settings)

    assert probe.status == ProbeStatus.READY
    assert probe.details["java"] == "/usr/bin/java"
    assert probe.details["analyze_headless"].endswith("analyzeHeadless")


@pytest.mark.skipif(os.name == "nt", reason="POSIX probe runner")
def test_probe_run_executes_a_real_command_under_a_deadline() -> None:
    """The unpatched seam must actually run tools; probes read decoded text."""
    import sys

    output = doctor_module._probe_run(
        [sys.executable, "-c", "print('probe-ok')"], timeout=30.0
    )

    assert output.returncode == 0
    assert "probe-ok" in output.stdout
    assert output.stderr == ""


def test_bounded_text_truncates_oversized_probe_output() -> None:
    text = doctor_module._bounded_text("x" * 100, limit=10)

    assert text.startswith("x" * 10)
    assert text.endswith("...[truncated]")


def test_probe_to_dict_omits_the_required_flag_when_not_asked() -> None:
    payload = Probe("x", ProbeStatus.READY, "ok").to_dict()

    assert "required" not in payload
    assert payload["status"] == "ready"


def test_required_probe_names_selects_the_windows_and_linux_sets() -> None:
    assert doctor_module.required_probe_names("windows") == WINDOWS_REQUIRED_PROBES
    assert (
        doctor_module.required_probe_names("linux")
        == doctor_module.LINUX_REQUIRED_PROBES
    )


def test_report_to_json_falls_back_to_the_live_host_without_a_platform_probe() -> None:
    import json

    report = DoctorReport(
        (Probe("python", ProbeStatus.READY, "ok"),),
        required_probes=frozenset({"python"}),
    )
    payload = json.loads(report.to_json())

    assert payload["ready"] is True
    assert payload["platform"]["name"]


def test_platform_probe_blocks_an_unsupported_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor_module,
        "runtime_platform_report",
        lambda: {
            "name": "unsupported",
            "core_supported": False,
            "support_level": "none",
            "system": "Haiku",
            "architecture": "sparc",
            "machine": "sparc64",
        },
    )

    probe = doctor_module.probe_platform()

    assert probe.status == ProbeStatus.BLOCKED
    assert "outside the supported host matrix" in probe.summary


def test_format_report_lists_a_blocking_probe_without_remediation() -> None:
    required = (
        Probe("platform", ProbeStatus.READY, "supported"),
        Probe("python", ProbeStatus.BLOCKED, "interpreter too old"),
    )
    text = format_report(
        DoctorReport(required, required_probes=frozenset({"platform", "python"}))
    )

    assert "- python (blocked)" in text
    assert "fix:" not in text.split("Blocking required backends")[1]
