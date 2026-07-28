from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.doctor as doctor_module
from headless_re_mcp.backends.x64dbg.gate import XdbgHeadlessGateResult
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.doctor import (
    DoctorReport,
    Probe,
    ProbeStatus,
    probe_die,
    probe_exeinfope,
    probe_upx,
    probe_x64dbg_binaries,
    probe_x64dbg_source,
)


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
        Probe("python", ProbeStatus.READY, "ready"),
        Probe("ida_idalib", ProbeStatus.READY, "ready"),
        Probe("x64dbg_source", ProbeStatus.READY, "ready"),
        Probe("native_toolchain", ProbeStatus.READY, "ready"),
    )
    assert not DoctorReport(required).ready
    assert DoctorReport(
        (*required, Probe("x64dbg_headless_binaries", ProbeStatus.READY, "ready"))
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

    monkeypatch.setattr(doctor_module.subprocess, "run", fake_run)
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

    monkeypatch.setattr(doctor_module.subprocess, "run", fake_run)

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

    monkeypatch.setattr(doctor_module.subprocess, "run", fake_run)
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

    monkeypatch.setattr(doctor_module.subprocess, "run", fake_run)
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

    monkeypatch.setattr(doctor_module.subprocess, "run", fake_run)
    assert probe_upx(settings).status == ProbeStatus.BLOCKED
