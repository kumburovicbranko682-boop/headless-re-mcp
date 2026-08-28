from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

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
    probe_ghidra,
    probe_optional_tool,
    probe_playwright,
    probe_upx,
    probe_x64dbg_binaries,
    probe_x64dbg_source,
    required_probe_names,
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


def test_jvm_tool_probe_flags_missing_java_on_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # jadx/apktool/apksigner are only JVM launchers: finding the wrapper on PATH
    # does not mean it can run, so a missing java must show up as a hint rather
    # than a bare "detected" that misleads the operator (same as probe_ghidra).
    on_path = tmp_path / "jadx"
    on_path.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        doctor_module.shutil, "which", lambda cmd: str(on_path) if cmd == "jadx" else None
    )
    settings = replace(_settings(None, tmp_path / "artifacts"), jadx=None)

    probe = probe_optional_tool(
        "jadx", settings, "jadx", ("jadx", "jadx.bat"), needs_runtime=("java", "a JRE")
    )

    assert probe.status == ProbeStatus.DETECTED
    assert probe.remediation is not None
    assert "java" in probe.remediation.lower()
    assert "java is not on PATH" in probe.summary


def test_jvm_tool_probe_is_clean_when_java_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    on_path = tmp_path / "apktool"
    on_path.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        doctor_module.shutil,
        "which",
        lambda cmd: str(on_path)
        if cmd == "apktool"
        else ("/usr/bin/java" if cmd == "java" else None),
    )
    settings = replace(_settings(None, tmp_path / "artifacts"), apktool=None)

    probe = probe_optional_tool(
        "apktool",
        settings,
        "apktool",
        ("apktool", "apktool.bat"),
        needs_runtime=("java", "a JRE"),
    )

    assert probe.status == ProbeStatus.DETECTED
    assert probe.remediation is None
    assert "java is not on PATH" not in probe.summary


def test_jvm_tool_probe_flags_missing_java_for_configured_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = tmp_path / "apksigner"
    configured.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: None)
    settings = replace(_settings(None, tmp_path / "artifacts"), apksigner=configured)

    probe = probe_optional_tool(
        "apksigner", settings, "apksigner", ("apksigner",), needs_runtime=("java", "a JRE")
    )

    assert probe.status == ProbeStatus.DETECTED
    assert probe.remediation is not None
    assert probe.details["path"] == str(configured)


def test_non_jvm_tool_probe_needs_no_java_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A native tool (radare2) must not grow a runtime hint just because java or
    # node is absent: needs_runtime stays unset and the probe is a clean detection.
    on_path = tmp_path / "r2"
    on_path.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        doctor_module.shutil, "which", lambda cmd: str(on_path) if cmd == "r2" else None
    )
    settings = replace(_settings(None, tmp_path / "artifacts"), r2=None)

    probe = probe_optional_tool("radare2", settings, "r2", ("r2", "rizin"))

    assert probe.status == ProbeStatus.DETECTED
    assert probe.remediation is None


def test_webcrack_probe_flags_missing_node_on_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """webcrack is a Node launcher exactly as jadx is a JVM launcher.

    npm installs a `webcrack` shim that execs node, so the shim being on PATH
    says nothing about whether it can run; the JVM tools got this hint but
    webcrack shipped without it, and a Node-less machine read as "detected".
    """
    on_path = tmp_path / "webcrack"
    on_path.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        doctor_module.shutil, "which", lambda cmd: str(on_path) if cmd == "webcrack" else None
    )
    settings = replace(_settings(None, tmp_path / "artifacts"), webcrack=None)

    probe = probe_optional_tool(
        "webcrack", settings, "webcrack", ("webcrack",), needs_runtime=("node", "Node.js")
    )

    assert probe.status == ProbeStatus.DETECTED
    assert probe.remediation is not None
    assert "node" in probe.remediation.lower()
    assert "node is not on PATH" in probe.summary


def test_run_doctor_wires_runtime_hints_for_all_launcher_backends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real probe list must pass the hints, not merely support them.

    The unit tests above call probe_optional_tool directly, so they cannot catch
    a call site that forgets needs_runtime. With the four launchers on PATH but
    java and node absent, each probe run_doctor emits must carry the remediation.
    """
    launchers = {"jadx", "apktool", "apksigner", "webcrack"}

    def which(cmd: str) -> str | None:
        return f"/usr/bin/{cmd}" if cmd in launchers else None  # java, node absent

    monkeypatch.setattr(doctor_module.shutil, "which", which)

    report = run_doctor(_settings(None, tmp_path / "artifacts"))
    by_name = {probe.name: probe for probe in report.probes}

    for name, runtime in (
        ("jadx", "java"),
        ("apktool", "java"),
        ("apksigner", "java"),
        ("webcrack", "node"),
    ):
        probe = by_name[name]
        assert probe.status == ProbeStatus.DETECTED, name
        assert probe.remediation is not None, name
        assert f"{runtime} is not on PATH" in probe.summary, name


def test_run_doctor_emits_a_probe_for_every_nonpe_backend(tmp_path: Path) -> None:
    """Every non-PE backend must stay visible in the doctor report.

    doctor is how an operator learns which optional backend to install; a
    refactor of run_doctor that dropped a probe -- or platform-gated one that
    should not be -- would silently blind them to that backend, and only the
    few launchers with a dedicated probe test (radare2, jadx/apktool/apksigner,
    webcrack) would notice. These backends are all cross-platform and emitted
    unconditionally, so pin the whole non-PE set by name; a new non-PE backend
    should be added here when it is added to run_doctor.
    """
    report = run_doctor(_settings(None, tmp_path / "artifacts"))
    names = {probe.name for probe in report.probes}
    nonpe_backends = {
        # portable binary backends
        "radare2",
        "ghidra",
        "frida",
        "java",
        # android
        "androguard",
        "adbutils",
        "adb",
        "jadx",
        "apktool",
        "apksigner",
        # web
        "playwright",
        "mitmproxy",
        "webcrack",
        "wabt",
    }
    missing = nonpe_backends - names
    assert not missing, f"doctor stopped reporting these non-PE backends: {sorted(missing)}"


def test_missing_nonpe_backends_carry_install_remediation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A MISSING optional non-PE backend must tell the operator how to install it.

    doctor is documented as printing each missing item with its fix command, and
    the PE probes (IDA, x64dbg) all carry one -- but the optional non-PE backends
    used to report a bare 'not installed' with remediation=None, leaving a Linux
    operator bringing up the Android/Web lines with no next step. Force every
    optional backend absent (nothing on PATH, no importable module, no configured
    path) and assert each names an install route. These run cross-platform, so the
    hints stay package-manager-agnostic ('e.g. apt ...') or use pip/npm, which are
    correct everywhere; the assertion is only that a hint exists and points at the
    backend, not its exact wording.
    """
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: None)
    monkeypatch.setattr(doctor_module.importlib.util, "find_spec", lambda _name: None)

    report = run_doctor(_settings(None, tmp_path / "artifacts"))
    probes = {probe.name: probe for probe in report.probes}

    # ghidra/java/frida are covered by their own probes with dedicated
    # remediation tests; this pins the optional launchers and importable
    # backends whose MISSING path previously carried nothing.
    expected_backends = {
        "radare2",
        "adb",
        "wabt",
        "apktool",
        "apksigner",
        "jadx",
        "webcrack",
        "androguard",
        "adbutils",
        "mitmproxy",
        "playwright",
    }
    for name in expected_backends:
        probe = probes[name]
        assert probe.status is ProbeStatus.MISSING, f"{name}: {probe.status}"
        assert probe.remediation, f"{name} is MISSING with no install remediation"


def test_linux_required_set_contains_no_backend() -> None:
    """On Linux only the platform and interpreter are required; no RE backend is.

    This is the maturity contract for the non-PE lines (and for PE-on-Linux): a
    backend is optional, so a host that installed none of them still passes
    ``doctor --strict`` -- the CI 'Doctor and core service smoke' step runs
    exactly that. Windows deliberately keeps IDA/x64dbg required because that is
    where the PE chain runs, so the two sets differ on purpose; pin the Linux one
    by value rather than trusting run_doctor's ambient platform choice. If a
    backend is ever promoted into the Linux required set, that is a deliberate
    change to this contract and must update this test, not slip past it.
    """
    linux_required = required_probe_names("linux")
    assert linux_required == frozenset({"platform", "python"})
    # Every backend doctor probes -- PE and non-PE alike -- must stay out of the
    # Linux required set; that exclusion is what keeps a missing one non-blocking.
    backends = {
        "ida_idalib",
        "x64dbg_headless_binaries",
        "x64dbg_source",
        "native_toolchain",
        "windbg",
        "radare2",
        "ghidra",
        "frida",
        "java",
        "androguard",
        "adbutils",
        "adb",
        "jadx",
        "apktool",
        "apksigner",
        "playwright",
        "mitmproxy",
        "webcrack",
        "wabt",
    }
    assert linux_required.isdisjoint(backends)


def test_doctor_ready_on_linux_with_every_backend_missing() -> None:
    """The Linux counterpart to the Windows optional-backend readiness test.

    A report carrying only platform+python READY with every backend MISSING is
    still ready under the Linux required set -- the state a freshly provisioned
    Linux host is in before any FOSS backend (or IDA/x64dbg) is installed. Built
    with the Linux set passed explicitly so the assertion holds even when the
    unit suite runs on the Windows CI job, whose ambient required set differs.
    """
    report = DoctorReport(
        probes=(
            Probe("platform", ProbeStatus.READY, "ok"),
            Probe("python", ProbeStatus.READY, "ok"),
            Probe("ida_idalib", ProbeStatus.MISSING, "missing"),
            Probe("x64dbg_headless_binaries", ProbeStatus.MISSING, "missing"),
            Probe("radare2", ProbeStatus.MISSING, "missing"),
            Probe("ghidra", ProbeStatus.MISSING, "missing"),
            Probe("frida", ProbeStatus.MISSING, "missing"),
            Probe("androguard", ProbeStatus.MISSING, "missing"),
            Probe("adb", ProbeStatus.MISSING, "missing"),
            Probe("jadx", ProbeStatus.MISSING, "missing"),
            Probe("apktool", ProbeStatus.MISSING, "missing"),
            Probe("apksigner", ProbeStatus.MISSING, "missing"),
            Probe("playwright", ProbeStatus.MISSING, "missing"),
            Probe("mitmproxy", ProbeStatus.MISSING, "missing"),
            Probe("webcrack", ProbeStatus.MISSING, "missing"),
            Probe("wabt", ProbeStatus.MISSING, "missing"),
        ),
        required_probes=required_probe_names("linux"),
    )
    assert report.ready is True


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="the Linux required set only applies when doctor runs on Linux (skip != pass)",
)
def test_run_doctor_strict_is_ready_on_a_bare_linux_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: the real run_doctor path is ready with no backend installed.

    The two tests above pin the pieces (the required set, and readiness given
    that set); this exercises the whole ``doctor --strict`` decision the CI smoke
    step depends on. Force every optional backend absent -- nothing on PATH, no
    importable module -- and the report is still ready, because only platform and
    the interpreter are required. A regression that promoted any backend into the
    Linux required set would flip report.ready to False and fail that CI step;
    this fails first, naming the required probe that is not ready.
    """
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _cmd: None)
    monkeypatch.setattr(doctor_module.importlib.util, "find_spec", lambda _name: None)

    report = run_doctor(_settings(None, tmp_path / "artifacts"))

    assert report.required_probes == frozenset({"platform", "python"})
    not_ready = [
        probe.name
        for probe in report.probes
        if probe.name in report.required_probes and probe.status is not ProbeStatus.READY
    ]
    assert not_ready == [], f"required probes not ready on a bare host: {not_ready}"
    assert report.ready is True


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


def _ghidra_home(tmp_path: Path, *, pyghidra: bool) -> Path:
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    (home / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    if pyghidra:
        (home / "Ghidra" / "Features" / "PyGhidra").mkdir(parents=True)
    else:
        (home / "Ghidra" / "Features" / "Jython").mkdir(parents=True)
    return home


def test_probe_ghidra_missing_when_home_unset(tmp_path: Path) -> None:
    settings = replace(_settings(None, tmp_path / "artifacts"), ghidra_home=None)
    probe = probe_ghidra(settings)
    assert probe.status == ProbeStatus.MISSING


def test_probe_ghidra_ready_for_a_jython_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(doctor_module.shutil, "which", lambda name: "/usr/bin/java")
    settings = replace(
        _settings(None, tmp_path / "artifacts"),
        ghidra_home=_ghidra_home(tmp_path, pyghidra=False),
    )
    probe = probe_ghidra(settings)
    assert probe.status == ProbeStatus.READY


def test_probe_ghidra_detected_when_pyghidra_package_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A modern (PyGhidra) install with analyzeHeadless present but no pyghidra
    package cannot run the export scripts, so the doctor must not claim READY."""
    monkeypatch.setattr(doctor_module.shutil, "which", lambda name: "/usr/bin/java")
    monkeypatch.setattr(
        doctor_module.importlib.util,
        "find_spec",
        lambda name: None if name == "pyghidra" else object(),
    )
    settings = replace(
        _settings(None, tmp_path / "artifacts"),
        ghidra_home=_ghidra_home(tmp_path, pyghidra=True),
    )
    probe = probe_ghidra(settings)
    assert probe.status == ProbeStatus.DETECTED
    assert probe.remediation is not None
    assert "pyghidra" in probe.remediation.lower()


def test_probe_ghidra_ready_when_pyghidra_package_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(doctor_module.shutil, "which", lambda name: "/usr/bin/java")
    monkeypatch.setattr(
        doctor_module.importlib.util, "find_spec", lambda name: object()
    )
    settings = replace(
        _settings(None, tmp_path / "artifacts"),
        ghidra_home=_ghidra_home(tmp_path, pyghidra=True),
    )
    probe = probe_ghidra(settings)
    assert probe.status == ProbeStatus.READY


def test_probe_ghidra_missing_when_analyze_headless_is_absent(tmp_path: Path) -> None:
    """A configured home with no analyzeHeadless is MISSING, not READY.

    HEADLESS_RE_GHIDRA_HOME pointing at a directory that is not a real Ghidra
    install (or the wrong subdirectory) must report MISSING with the home it
    looked under and a remediation, rather than being taken as a usable backend.
    """
    home = tmp_path / "not-really-ghidra"
    home.mkdir()
    settings = replace(_settings(None, tmp_path / "artifacts"), ghidra_home=home)

    probe = probe_ghidra(settings)

    assert probe.status == ProbeStatus.MISSING
    assert "analyzeHeadless not found" in probe.summary
    assert probe.details.get("home") == str(home)
    assert probe.remediation is not None


def test_probe_ghidra_detected_but_not_ready_when_java_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """analyzeHeadless present but no java is DETECTED, never READY.

    analyzeHeadless is a JVM launcher; without java on PATH it cannot run, so the
    doctor reports the launcher as present (DETECTED) with a remediation to
    install a JRE, rather than claiming the backend is ready to use.
    """
    monkeypatch.setattr(doctor_module.shutil, "which", lambda name: None)
    settings = replace(
        _settings(None, tmp_path / "artifacts"),
        ghidra_home=_ghidra_home(tmp_path, pyghidra=False),
    )

    probe = probe_ghidra(settings)

    assert probe.status == ProbeStatus.DETECTED
    assert "java is not on PATH" in probe.summary
    assert probe.remediation is not None
    assert "java" in probe.remediation.lower()


def test_playwright_probe_is_missing_when_the_module_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_module.importlib.util, "find_spec", lambda _name: None)

    probe = probe_playwright()

    assert probe.status == ProbeStatus.MISSING
    # A wholly absent module now names its install route, like the other non-PE
    # backends: the browser step alone is useless with no module to drive it.
    assert probe.remediation
    assert "pip install" in probe.remediation


def test_playwright_probe_flags_a_missing_browser_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The module imports but no browser is installed: DETECTED plus a hint.

    This is what a default install then a forgotten `playwright install` leaves,
    and web.* cannot open a page in it.
    """
    monkeypatch.setattr(
        doctor_module.importlib.util,
        "find_spec",
        lambda _name: SimpleNamespace(origin="/site-packages/playwright/__init__.py"),
    )
    monkeypatch.setattr(doctor_module, "_playwright_has_chromium", lambda: False)

    probe = probe_playwright()

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["browser_installed"] is False
    assert probe.remediation is not None
    assert "playwright install chromium" in probe.remediation


def test_playwright_probe_is_clean_when_a_browser_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor_module.importlib.util,
        "find_spec",
        lambda _name: SimpleNamespace(origin="/site-packages/playwright/__init__.py"),
    )
    monkeypatch.setattr(doctor_module, "_playwright_has_chromium", lambda: True)

    probe = probe_playwright()

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["browser_installed"] is True
    assert probe.remediation is None


def test_playwright_probe_makes_no_claim_when_the_registry_is_unresolvable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PLAYWRIGHT_BROWSERS_PATH=0 installs beside the package; do not guess."""
    monkeypatch.setattr(
        doctor_module.importlib.util,
        "find_spec",
        lambda _name: SimpleNamespace(origin="/site-packages/playwright/__init__.py"),
    )
    monkeypatch.setattr(doctor_module, "_playwright_has_chromium", lambda: None)

    probe = probe_playwright()

    assert probe.status == ProbeStatus.DETECTED
    assert "browser_installed" not in probe.details
    assert probe.remediation is None


def test_playwright_browser_detection_reads_the_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The detector finds a real chromium build and reports an empty one missing."""
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))

    assert doctor_module._playwright_has_chromium() is False

    chrome = tmp_path / "chromium-1234" / "chrome-linux" / "chrome"
    chrome.parent.mkdir(parents=True)
    chrome.write_bytes(b"")

    assert doctor_module._playwright_has_chromium() is True


def test_playwright_browser_detection_is_unknown_for_the_package_local_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "0")

    assert doctor_module._playwright_has_chromium() is None
