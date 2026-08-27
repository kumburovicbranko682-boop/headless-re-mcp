from __future__ import annotations

import ctypes
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.x64dbg.gate import run_command_loop_gate
from headless_re_mcp.config import (
    Settings,
    find_ida_executable,
    find_idalib_library,
    ida_library_names,
)
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.platform_support import (
    runtime_platform_report,
    unsupported_on_platform_details,
)


class ProbeStatus(StrEnum):
    READY = "ready"
    DETECTED = "detected"
    MISSING = "missing"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported_on_platform"


@dataclass(frozen=True, slots=True)
class Probe:
    name: str
    status: ProbeStatus
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None

    def to_dict(self, *, required: bool | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "status": self.status.value,
            "summary": self.summary,
            "details": self.details,
            "remediation": self.remediation,
        }
        if required is not None:
            payload["required"] = required
        return payload


WINDOWS_REQUIRED_PROBES: frozenset[str] = frozenset(
    {
        "platform",
        "python",
        "ida_idalib",
        "x64dbg_headless_binaries",
    }
)
LINUX_REQUIRED_PROBES: frozenset[str] = frozenset({"platform", "python"})


def required_probe_names(platform_name: str | None = None) -> frozenset[str]:
    current = platform_name or str(runtime_platform_report()["name"])
    if current == "windows":
        return WINDOWS_REQUIRED_PROBES
    return LINUX_REQUIRED_PROBES


# Backwards-compatible snapshot for callers that only inspect this constant.
REQUIRED_PROBES: frozenset[str] = required_probe_names()
_MAX_CMAKE_FILE_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class DoctorReport:
    probes: tuple[Probe, ...]
    required_probes: frozenset[str] = field(default_factory=required_probe_names)

    @property
    def ready(self) -> bool:
        required = self.required_probes
        return all(
            probe.status == ProbeStatus.READY
            for probe in self.probes
            if probe.name in required
        ) and required.issubset({probe.name for probe in self.probes})

    def to_dict(self) -> dict[str, Any]:
        platform_probe = next(
            (probe for probe in self.probes if probe.name == "platform"),
            None,
        )
        return {
            "ready": self.ready,
            "platform": (
                {
                    "status": platform_probe.status.value,
                    "summary": platform_probe.summary,
                    **platform_probe.details,
                }
                if platform_probe is not None
                else runtime_platform_report()
            ),
            "required_probes": sorted(self.required_probes),
            "probes": [
                probe.to_dict(required=probe.name in self.required_probes)
                for probe in self.probes
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


def run_doctor(settings: Settings | None = None) -> DoctorReport:
    current = settings or Settings.load()
    platform_info = runtime_platform_report()
    on_windows = platform_info["name"] == "windows"

    def windows_only(name: str, summary: str) -> Probe:
        return unsupported_windows_probe(name, summary)

    probes = [
        probe_platform(),
        probe_python(),
        probe_ida(current),
        (
            probe_x64dbg_source(current)
            if on_windows
            else windows_only("x64dbg_source", "x64dbg source/build path requires Windows")
        ),
        (
            probe_x64dbg_binaries(current)
            if on_windows
            else windows_only(
                "x64dbg_headless_binaries",
                "x64dbg headless RPC binaries require Windows",
            )
        ),
        (
            probe_x64dbg_scyllahide(current)
            if on_windows
            else windows_only("x64dbg_scyllahide", "ScyllaHide for x64dbg requires Windows")
        ),
        (
            probe_native_toolchain()
            if on_windows
            else windows_only("native_toolchain", "x64dbg native build toolchain requires Windows")
        ),
        probe_windows_feature(
            "win32_ui",
            "Win32 UI, UIA, SendInput, screenshot, and Windows OCR",
        ),
        probe_windows_feature("hidden_desktop", "hidden Win32 desktop"),
        probe_isolation(current),
        probe_die(current),
        (
            probe_exeinfope(current)
            if on_windows
            else windows_only("exeinfope", "Exeinfo PE silent GUI adapter requires Windows")
        ),
        probe_upx(current),
        probe_de4dot(current),
        probe_net_reactor_slayer(current),
        (
            probe_xvlkc(current)
            if on_windows
            else windows_only("xvlkc", "configured XVLKC adapter requires Windows")
        ),
        (
            probe_vmp_dumper(current)
            if on_windows
            else windows_only("vmp_dumper", "configured VMP dumper adapter requires Windows")
        ),
        (
            probe_scylla(current)
            if on_windows
            else windows_only("scylla", "Scylla dump/IAT adapter requires Windows")
        ),
        probe_command("radare2", ("r2", "rizin")),
        probe_ghidra(current),
        probe_python_module("frida", "frida"),
        probe_command("java", ("java",)),
        (
            probe_command("windbg", ("cdb", "windbg", "windbgx"))
            if on_windows
            else windows_only("windbg", "WinDbg/cdb requires Windows")
        ),
        # Android reverse-engineering (all optional; missing only degrades).
        probe_python_module("androguard", "androguard"),
        probe_python_module("adbutils", "adbutils"),
        probe_optional_tool("adb", current, "adb", ("adb",)),
        probe_optional_tool("jadx", current, "jadx", ("jadx", "jadx.bat")),
        probe_optional_tool("apktool", current, "apktool", ("apktool", "apktool.bat")),
        probe_optional_tool("apksigner", current, "apksigner", ("apksigner", "apksigner.bat")),
        # Web reverse-engineering (all optional).
        probe_python_module("playwright", "playwright"),
        probe_python_module("mitmproxy", "mitmproxy"),
        probe_webcrack(current),
        probe_optional_tool("wabt", current, "wabt", ("wasm2wat",)),
    ]
    return DoctorReport(
        probes=tuple(probes),
        required_probes=required_probe_names(str(platform_info["name"])),
    )


def probe_platform() -> Probe:
    details = runtime_platform_report()
    if details["core_supported"]:
        scope = "full Windows" if details["support_level"] == "full" else "portable Linux core"
        return Probe(
            "platform",
            ProbeStatus.READY,
            f"{details['system']} {details['architecture']} supports the {scope}",
            details,
        )
    return Probe(
        "platform",
        ProbeStatus.BLOCKED,
        f"{details['system']} {details['machine']} is outside the supported host matrix",
        details,
        "Use Windows x86_64 or Linux x86_64 with Python 3.11+.",
    )


def unsupported_windows_probe(name: str, summary: str) -> Probe:
    return Probe(
        name,
        ProbeStatus.UNSUPPORTED,
        summary,
        unsupported_on_platform_details(name),
        "Run this optional capability on a Windows host.",
    )


def probe_windows_feature(name: str, summary: str) -> Probe:
    if runtime_platform_report()["name"] != "windows":
        return unsupported_windows_probe(name, f"{summary} is unsupported on this platform")
    return Probe(
        name,
        ProbeStatus.READY,
        f"{summary} is supported by this Windows host",
        {"supported_platforms": ["windows"]},
    )


_VM_DRIVER_HINTS: tuple[tuple[str, str], ...] = (
    ("vmware", r"C:\Windows\System32\drivers\vmhgfs.sys"),
    ("vmware", r"C:\Windows\System32\drivers\vmmouse.sys"),
    ("virtualbox", r"C:\Windows\System32\drivers\VBoxGuest.sys"),
    ("hyperv", r"C:\Windows\System32\drivers\vmbus.sys"),
)


def _is_elevated() -> bool | None:
    """Return whether the process is elevated, or None when it cannot be told."""
    if os.name != "nt":
        return None
    try:
        shell32 = ctypes.windll.shell32  # type: ignore[attr-defined,unused-ignore]
        return bool(shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return None


def probe_isolation(settings: Settings) -> Probe:
    """Advisory: is this host disposable enough to execute unknown samples?

    Never part of the required set, so it cannot flip overall readiness. It exists
    because the debugger really executes the target, and an operator should see
    that fact before launching an untrusted binary.
    """
    on_windows = runtime_platform_report()["name"] == "windows"
    hints = (
        sorted({name for name, path in _VM_DRIVER_HINTS if Path(path).exists()})
        if on_windows
        else []
    )
    elevated = _is_elevated()
    hidden_desktop = bool(getattr(settings, "hidden_desktop", False))
    details: dict[str, Any] = {
        "virtualization_hints": hints,
        "elevated": elevated,
        "hidden_desktop": hidden_desktop,
        "hidden_desktop_supported": on_windows,
        "advisory": True,
    }
    if elevated:
        return Probe(
            "isolation",
            ProbeStatus.BLOCKED,
            "running elevated; an unknown sample would execute with admin rights",
            details,
            "Run from a dedicated low-privilege account inside a disposable VM or host.",
        )
    if hints or (on_windows and hidden_desktop):
        signals = ", ".join(hints or ["hidden desktop"])
        return Probe(
            "isolation",
            ProbeStatus.READY,
            f"isolation signals present: {signals}",
            details,
        )
    return Probe(
        "isolation",
        ProbeStatus.MISSING,
        "no virtualization or hidden-desktop isolation detected",
        details,
        (
            "Analyse unknown samples in a disposable VM/host, or set "
            "HEADLESS_RE_HIDDEN_DESKTOP=1."
            if on_windows
            else "Analyse unknown samples in a dedicated low-privilege disposable Linux VM/host; "
            "hidden desktop is a Windows-only feature."
        ),
    )


def probe_python() -> Probe:
    version = sys.version_info
    status = ProbeStatus.READY if version >= (3, 11) else ProbeStatus.BLOCKED
    return Probe(
        "python",
        status,
        f"Python {version.major}.{version.minor}.{version.micro}",
        {"executable": sys.executable, "implementation": sys.implementation.name},
        None if status == ProbeStatus.READY else "Install Python 3.11 or newer.",
    )


def probe_ida(settings: Settings) -> Probe:
    home = settings.ida_home
    if home is None or not home.is_dir():
        return Probe(
            "ida_idalib",
            ProbeStatus.MISSING,
            "IDA 9.x installation was not found",
            remediation="Set HEADLESS_RE_IDA_HOME to an authorized IDA 9.x installation.",
        )

    idalib = find_idalib_library(home)
    ida = find_ida_executable(home)
    idapro_spec = importlib.util.find_spec("idapro")
    details: dict[str, Any] = {
        "home": str(home),
        "ida": str(ida) if ida is not None else None,
        "idalib": str(idalib) if idalib is not None else None,
        "expected_idalib_names": list(ida_library_names()),
        "idapro_module": idapro_spec.origin if idapro_spec else None,
    }
    if idalib is None:
        return Probe(
            "ida_idalib",
            ProbeStatus.BLOCKED,
            "IDA was detected but its platform-native idalib library is missing",
            details,
            "Install IDA Professional 9.x with IDA Library support.",
        )
    if idapro_spec is None:
        activation = home / "idalib" / "python" / "py-activate-idalib.py"
        return Probe(
            "ida_idalib",
            ProbeStatus.BLOCKED,
            "idalib exists but the idapro Python package is unavailable",
            {**details, "activation_script": str(activation)},
            f'Run: "{sys.executable}" "{activation}" --ida-install-dir "{home}"',
        )

    env = os.environ.copy()
    env["PATH"] = f"{home}{os.pathsep}{env.get('PATH', '')}"
    command = [
        sys.executable,
        "-c",
        "import idapro; print(idapro.__file__); print(hasattr(idapro, 'open_database'))",
    ]
    try:
        completed = _probe_run(command, timeout=15, env=env)
    except (OSError, TimedOut) as exc:
        return Probe(
            "ida_idalib",
            ProbeStatus.BLOCKED,
            "idapro runtime probe failed to start",
            {**details, "error": str(exc)},
        )
    details.update(
        {
            "probe_exit_code": completed.returncode,
            "probe_stdout": completed.stdout.strip(),
            "probe_stderr": completed.stderr.strip(),
        }
    )
    if completed.returncode == 0 and completed.stdout.rstrip().endswith("True"):
        return Probe("ida_idalib", ProbeStatus.READY, "IDA idalib runtime is importable", details)
    return Probe(
        "ida_idalib",
        ProbeStatus.BLOCKED,
        "idapro is installed but idalib runtime initialization failed",
        details,
        "Run the IDA activation script and check the IDA license/runtime dependencies.",
    )


def probe_x64dbg_source(settings: Settings) -> Probe:
    source = settings.x64dbg_source
    if source is None:
        return Probe(
            "x64dbg_source",
            ProbeStatus.MISSING,
            "x64dbg source was not found",
            remediation="Clone the x64dbg development branch and set HEADLESS_RE_X64DBG_SOURCE.",
        )
    headless = source / "src" / "headless" / "headless.cpp"
    cmake = source / "CMakeLists.txt"
    if not headless.is_file() or not cmake.is_file():
        return Probe(
            "x64dbg_source",
            ProbeStatus.BLOCKED,
            "x64dbg source exists but the official headless target is absent",
            {"source": str(source)},
        )
    try:
        with cmake.open("rb") as stream:
            payload = stream.read(_MAX_CMAKE_FILE_BYTES + 1)
    except OSError as exc:
        return Probe(
            "x64dbg_source",
            ProbeStatus.BLOCKED,
            "x64dbg CMake project could not be read",
            {"source": str(source), "error": str(exc)},
        )
    if len(payload) > _MAX_CMAKE_FILE_BYTES:
        return Probe(
            "x64dbg_source",
            ProbeStatus.BLOCKED,
            "x64dbg CMake project exceeds the safety limit",
            {
                "source": str(source),
                "max_bytes": _MAX_CMAKE_FILE_BYTES,
                "size_at_least": len(payload),
            },
        )
    text = payload.decode("utf-8", errors="replace")
    if "add_executable(headless)" not in text:
        return Probe(
            "x64dbg_source",
            ProbeStatus.BLOCKED,
            "headless.cpp exists but no CMake headless executable target was found",
            {"source": str(source), "headless_source": str(headless)},
        )
    return Probe(
        "x64dbg_source",
        ProbeStatus.READY,
        "Official x64dbg headless source target is present",
        {"source": str(source), "headless_source": str(headless)},
    )


def probe_x64dbg_binaries(settings: Settings) -> Probe:
    paths = {
        Architecture.X64: settings.x64dbg_headless_x64,
        Architecture.X86: settings.x64dbg_headless_x86,
    }
    existing = {
        architecture.value: str(path)
        for architecture, path in paths.items()
        if path is not None and path.is_file()
    }
    if len(existing) != 2:
        return Probe(
            "x64dbg_headless_binaries",
            ProbeStatus.MISSING,
            "Built x86/x64 headless executables were not both configured",
            existing,
            "Build x64dbg for x86 and x64, then set HEADLESS_RE_X64DBG_HEADLESS_X86/X64.",
        )

    gates: dict[str, Any] = {}
    all_ready = True
    for architecture, path in paths.items():
        assert path is not None
        try:
            result = run_command_loop_gate(path, architecture, timeout=15.0)
            gates[architecture.value] = {
                "executable": result.executable,
                "exit_code": result.exit_code,
                "command_loop_seen": result.command_loop_seen,
                "analyzer_windows": list(result.analyzer_windows),
                "stderr": result.stderr[-4000:],
            }
            all_ready = all_ready and result.ok
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            gates[architecture.value] = {
                "executable": str(path),
                "error": f"{type(exc).__name__}: {exc}",
            }
            all_ready = False

    if all_ready:
        return Probe(
            "x64dbg_headless_binaries",
            ProbeStatus.READY,
            "x86 and x64 headless executables passed the zero-window command-loop gate",
            gates,
        )
    return Probe(
        "x64dbg_headless_binaries",
        ProbeStatus.BLOCKED,
        "One or more x64dbg headless executables failed the runtime gate",
        gates,
        "Rebuild the failing architecture and inspect its gate diagnostics.",
    )


def probe_x64dbg_scyllahide(settings: Settings) -> Probe:
    """Optional: ScyllaHide plugin files next to the live headless executables."""
    from headless_re_mcp.backends.x64dbg.stealth import inspect_layout, layout_for_headless

    layouts = {
        Architecture.X86: layout_for_headless(settings.x64dbg_headless_x86, Architecture.X86),
        Architecture.X64: layout_for_headless(settings.x64dbg_headless_x64, Architecture.X64),
    }
    details: dict[str, Any] = {
        architecture.value: inspect_layout(layout)
        for architecture, layout in layouts.items()
    }
    configured = [item for item in details.values() if item.get("configured")]
    if not configured:
        return Probe(
            "x64dbg_scyllahide",
            ProbeStatus.MISSING,
            "x64dbg headless is not configured; ScyllaHide plugin path is unknown",
            details,
            (
                "Set HEADLESS_RE_X64DBG_HEADLESS_X86/X64, then install "
                "ScyllaHide into that plugins directory."
            ),
        )
    missing = [
        arch
        for arch, item in details.items()
        if item.get("configured") and not item.get("plugin_present")
    ]
    if missing:
        return Probe(
            "x64dbg_scyllahide",
            ProbeStatus.MISSING,
            "ScyllaHide plugin files are missing next to one or more live headless executables",
            details,
            (
                "Copy ScyllaHideX64DBGPlugin and HookLibrary into "
                "<headless-dir>/plugins for: " + ", ".join(missing)
            ),
        )
    return Probe(
        "x64dbg_scyllahide",
        ProbeStatus.READY,
        "ScyllaHide plugin files are present beside the configured headless executables",
        details,
    )


def probe_native_toolchain() -> Probe:
    cmake = shutil.which("cmake")
    ninja = shutil.which("ninja")
    cl = shutil.which("cl")
    vswhere = Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    details = {
        "cmake": cmake,
        "ninja": ninja,
        "cl": cl,
        "vswhere": str(vswhere) if vswhere.is_file() else None,
    }
    if cmake and ninja and (cl or vswhere.is_file()):
        return Probe(
            "native_toolchain",
            ProbeStatus.READY,
            "Native CMake toolchain detected",
            details,
        )
    return Probe(
        "native_toolchain",
        ProbeStatus.BLOCKED,
        "MSVC x86/x64 build tools are incomplete",
        details,
        "Install Visual Studio 2022 Build Tools with Desktop development with C++ (x86/x64).",
    )


def probe_die(settings: Settings) -> Probe:
    executable = settings.diec
    if executable is None:
        return Probe(
            "diec",
            ProbeStatus.MISSING,
            "Optional Detect It Easy CLI is not configured",
            remediation=(
                "Install the official diec CLI and set HEADLESS_RE_DIEC to its executable."
            ),
        )
    if not executable.is_file():
        return Probe(
            "diec",
            ProbeStatus.BLOCKED,
            "Configured Detect It Easy CLI does not exist",
            {"executable": str(executable)},
            "Correct HEADLESS_RE_DIEC or remove the stale configuration.",
        )

    details: dict[str, Any] = {"executable": str(executable)}
    try:
        version = _probe_run([str(executable), "--version"], timeout=5)
        help_result = _probe_run([str(executable), "--help"], timeout=5)
    except (OSError, TimedOut) as exc:
        return Probe(
            "diec",
            ProbeStatus.BLOCKED,
            "Detect It Easy CLI probe failed",
            {**details, "error": f"{type(exc).__name__}: {exc}"},
            "Verify that HEADLESS_RE_DIEC points to an official command-line build.",
        )

    version_output = _bounded_text(version.stdout, version.stderr)
    help_output = _bounded_text(help_result.stdout, help_result.stderr)
    match = re.search(r"(?:Detect It Easy v|\bdie\s+)(\d+(?:\.\d+)+)", version_output, re.I)
    json_capable = (
        "--json" in help_output
        or "-j" in help_output
        or "Result as JSON" in help_output
    )
    details.update(
        {
            "version": match.group(1) if match else None,
            "version_exit_code": version.returncode,
            "help_exit_code": help_result.returncode,
            "json_capable": json_capable,
            "version_output": version_output,
        }
    )
    if version.returncode == 0 and help_result.returncode == 0 and match and json_capable:
        return Probe(
            "diec",
            ProbeStatus.READY,
            f"Detect It Easy CLI {match.group(1)} supports JSON output",
            details,
        )
    return Probe(
        "diec",
        ProbeStatus.BLOCKED,
        "Detect It Easy CLI lacks a usable version or JSON interface",
        details,
        "Use an official diec release that supports --version and JSON output (--json/-j).",
    )


def probe_exeinfope(settings: Settings) -> Probe:
    """Optional Exeinfo PE second-opinion probe (missing does not block core ready)."""

    executable = settings.exeinfope
    if executable is None:
        return Probe(
            "exeinfope",
            ProbeStatus.MISSING,
            "Optional Exeinfo PE detector is not configured",
            remediation=(
                "Obtain official Exeinfo PE (Freeware) yourself and set "
                "HEADLESS_RE_EXEINFOPE to its executable. Not bundled."
            ),
        )
    if not executable.is_file():
        return Probe(
            "exeinfope",
            ProbeStatus.BLOCKED,
            "Configured Exeinfo PE executable does not exist",
            {"executable": str(executable)},
            "Correct HEADLESS_RE_EXEINFOPE or remove the stale configuration.",
        )

    details: dict[str, Any] = {
        "executable": str(executable),
        "claims_universal_unpack": False,
        "role": "optional_second_opinion",
    }
    # Honest readiness: run one silent scan against a tiny synthetic PE.
    import struct
    import tempfile

    from headless_re_mcp.detection.exeinfope import (
        ExeinfopeGuiWindowError,
        ExeinfopeScanError,
        scan_with_exeinfope,
    )

    try:
        with tempfile.TemporaryDirectory(prefix="headless-re-exeinfope-doctor-") as tmp:
            tmp_path = Path(tmp)
            sample = tmp_path / "doctor-sample.exe"
            image = bytearray(0x400)
            pe_offset = 0x80
            image[:2] = b"MZ"
            struct.pack_into("<I", image, 0x3C, pe_offset)
            image[pe_offset : pe_offset + 4] = b"PE\0\0"
            file_header = pe_offset + 4
            struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
            optional = file_header + 20
            struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
            struct.pack_into("<I", image, optional + 16, 0x1000)
            struct.pack_into("<Q", image, optional + 24, 0x140000000)
            struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
            struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
            struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
            struct.pack_into("<I", image, optional + 108, 16)
            section = optional + 0xF0
            image[section : section + 8] = b".text\0\0\0"
            struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
            struct.pack_into("<I", image, section + 36, 0x60000020)
            image[0x200:0x202] = b"\xC3\x90"
            sample.write_bytes(image)
            log_path = tmp_path / "doctor-exeinfope.log"
            result = scan_with_exeinfope(
                executable,
                sample,
                log_path=log_path,
                timeout=20.0,
            )
    except ExeinfopeGuiWindowError as exc:
        details.update({"error": str(exc), "analyzer_windows": exc.details.get("analyzer_windows")})
        return Probe(
            "exeinfope",
            ProbeStatus.BLOCKED,
            "Exeinfo PE probe showed a visible analyzer window",
            details,
            "Use a build that stays silent under '/s /log:', or unset HEADLESS_RE_EXEINFOPE.",
        )
    except ExeinfopeScanError as exc:
        details.update({"error": f"{exc.code}: {exc}", "code": exc.code})
        return Probe(
            "exeinfope",
            ProbeStatus.BLOCKED,
            "Exeinfo PE silent-scan probe failed",
            details,
            "Verify HEADLESS_RE_EXEINFOPE points to official Exeinfo PE and supports "
            "'<file>* /s /log:<path>'.",
        )
    except (OSError, ValueError) as exc:
        details.update({"error": f"{type(exc).__name__}: {exc}"})
        return Probe(
            "exeinfope",
            ProbeStatus.BLOCKED,
            "Exeinfo PE probe failed to start",
            details,
            "Verify HEADLESS_RE_EXEINFOPE points to a runnable official Exeinfo PE binary.",
        )

    details.update(
        {
            "findings": len(result.findings),
            "duration_ms": result.source.duration_ms,
            "returncode": result.returncode,
            "log_bytes": len(result.raw_log.encode("utf-8", errors="replace")),
        }
    )
    if not result.findings:
        return Probe(
            "exeinfope",
            ProbeStatus.BLOCKED,
            "Exeinfo PE probe produced an empty finding set",
            details,
            "Confirm the configured binary writes a non-empty /log under silent mode.",
        )
    return Probe(
        "exeinfope",
        ProbeStatus.READY,
        "Exeinfo PE optional second-opinion silent scan is available",
        details,
    )


def probe_upx(settings: Settings) -> Probe:
    executable = settings.upx
    if executable is None:
        return Probe(
            "upx",
            ProbeStatus.MISSING,
            "Optional official UPX CLI is not configured",
            remediation=(
                "Install the official UPX CLI and set HEADLESS_RE_UPX to its executable."
            ),
        )
    if not executable.is_file():
        return Probe(
            "upx",
            ProbeStatus.BLOCKED,
            "Configured UPX CLI does not exist",
            {"executable": str(executable)},
            "Correct HEADLESS_RE_UPX or remove the stale configuration.",
        )

    details: dict[str, Any] = {"executable": str(executable)}
    try:
        version = _probe_run([str(executable), "--version"], timeout=5)
    except (OSError, TimedOut) as exc:
        return Probe(
            "upx",
            ProbeStatus.BLOCKED,
            "UPX CLI probe failed",
            {**details, "error": f"{type(exc).__name__}: {exc}"},
            "Verify that HEADLESS_RE_UPX points to an official upx executable.",
        )

    version_output = _bounded_text(version.stdout, version.stderr)
    match = re.search(r"\bupx\s+(\d+(?:\.\d+)+)", version_output, re.I)
    details.update(
        {
            "version": match.group(1) if match else None,
            "version_exit_code": version.returncode,
            "version_output": version_output,
        }
    )
    if version.returncode == 0 and match:
        return Probe(
            "upx",
            ProbeStatus.READY,
            f"Official UPX CLI {match.group(1)} is available",
            details,
        )
    return Probe(
        "upx",
        ProbeStatus.BLOCKED,
        "UPX CLI did not report a usable version",
        details,
        "Use an official UPX release that supports --version.",
    )


def probe_de4dot(settings: Settings) -> Probe:
    executable = settings.de4dot
    if executable is None:
        return Probe(
            "de4dot",
            ProbeStatus.MISSING,
            "Optional de4dot CLI is not configured",
            remediation=(
                "Install a GPL-licensed de4dot build and set HEADLESS_RE_DE4DOT "
                "to its executable. Do not copy toolkit samples or unknown forks."
            ),
        )
    if not executable.is_file():
        return Probe(
            "de4dot",
            ProbeStatus.BLOCKED,
            "Configured de4dot CLI does not exist",
            {"executable": str(executable)},
            "Correct HEADLESS_RE_DE4DOT or remove the stale configuration.",
        )
    from headless_re_mcp.dotnet.de4dot import probe_de4dot_version

    ok, output = probe_de4dot_version(executable)
    details: dict[str, Any] = {
        "executable": str(executable),
        "probe_output": output[:1000] if output else None,
        "license_note": "caller must use a GPL-licensed official/maintained build",
    }
    if ok:
        return Probe(
            "de4dot",
            ProbeStatus.READY,
            "de4dot CLI is available (optional external .NET deobfuscator)",
            details,
        )
    return Probe(
        "de4dot",
        ProbeStatus.BLOCKED,
        "de4dot CLI probe failed",
        details,
        "Verify HEADLESS_RE_DE4DOT points to a runnable de4dot executable.",
    )


def probe_net_reactor_slayer(settings: Settings) -> Probe:
    executable = settings.net_reactor_slayer
    if executable is None:
        return Probe(
            "net_reactor_slayer",
            ProbeStatus.MISSING,
            "Optional NETReactorSlayer CLI is not configured",
            remediation=(
                "Install GPL-3.0 NETReactorSlayer from "
                "https://github.com/SychicBoy/NETReactorSlayer and set "
                "HEADLESS_RE_NET_REACTOR_SLAYER. Authorized Reactor samples only; "
                "not bundled in portable/MSI."
            ),
        )
    if not executable.is_file():
        return Probe(
            "net_reactor_slayer",
            ProbeStatus.BLOCKED,
            "Configured NETReactorSlayer CLI does not exist",
            {"executable": str(executable)},
            "Correct HEADLESS_RE_NET_REACTOR_SLAYER or remove the stale configuration.",
        )
    from headless_re_mcp.dotnet.net_reactor_slayer import probe_net_reactor_slayer as probe_cli

    ok, output = probe_cli(executable)
    details: dict[str, Any] = {
        "executable": str(executable),
        "probe_output": output[:1000] if output else None,
        "license": "GPL-3.0",
        "upstream": "https://github.com/SychicBoy/NETReactorSlayer",
        "scope": "authorized_reactor_samples_only",
    }
    if ok:
        return Probe(
            "net_reactor_slayer",
            ProbeStatus.READY,
            "NETReactorSlayer CLI is available (optional external Reactor unpacker)",
            details,
        )
    return Probe(
        "net_reactor_slayer",
        ProbeStatus.BLOCKED,
        "NETReactorSlayer CLI probe failed",
        details,
        "Verify HEADLESS_RE_NET_REACTOR_SLAYER points to a runnable CLI executable.",
    )


def probe_xvlkc(settings: Settings) -> Probe:
    executable = settings.xvlkc
    if executable is None:
        return Probe(
            "xvlkc",
            ProbeStatus.MISSING,
            "Optional XVLKC CLI is not configured",
            remediation=(
                "If you have a licensed/authorized XVLKC build, set HEADLESS_RE_XVLKC "
                "to its executable. Not bundled; claims_universal_unpack=false."
            ),
        )
    if not executable.is_file():
        return Probe(
            "xvlkc",
            ProbeStatus.BLOCKED,
            "Configured XVLKC CLI does not exist",
            {"executable": str(executable)},
            "Correct HEADLESS_RE_XVLKC or remove the stale configuration.",
        )
    from headless_re_mcp.unpack.xvlkc import probe_xvlkc as probe_cli

    ok, output = probe_cli(executable)
    details: dict[str, Any] = {
        "executable": str(executable),
        "probe_output": output[:1000] if output else None,
        "claims_universal_unpack": False,
        "scope": "user_configured_external_only",
    }
    if ok:
        return Probe(
            "xvlkc",
            ProbeStatus.READY,
            "XVLKC CLI is available (optional external unpacker)",
            details,
        )
    return Probe(
        "xvlkc",
        ProbeStatus.BLOCKED,
        "XVLKC CLI probe failed",
        details,
        "Verify HEADLESS_RE_XVLKC points to a runnable console executable.",
    )


def probe_vmp_dumper(settings: Settings) -> Probe:
    executable = settings.vmp_dumper
    if executable is None:
        return Probe(
            "vmp_dumper",
            ProbeStatus.MISSING,
            "Optional VMP dumper CLI is not configured",
            remediation=(
                "If you have an authorized VMP dumper build, set HEADLESS_RE_VMP_DUMPER "
                "to its executable. Not bundled; does not claim VM restoration."
            ),
        )
    if not executable.is_file():
        return Probe(
            "vmp_dumper",
            ProbeStatus.BLOCKED,
            "Configured VMP dumper CLI does not exist",
            {"executable": str(executable)},
            "Correct HEADLESS_RE_VMP_DUMPER or remove the stale configuration.",
        )
    from headless_re_mcp.unpack.vmp_dumper import probe_vmp_dumper as probe_cli

    ok, output = probe_cli(executable)
    details: dict[str, Any] = {
        "executable": str(executable),
        "probe_output": output[:1000] if output else None,
        "claims_universal_unpack": False,
        "vm_restored_default": False,
        "scope": "user_configured_external_only",
    }
    if ok:
        return Probe(
            "vmp_dumper",
            ProbeStatus.READY,
            "VMP dumper CLI is available (optional external dump helper)",
            details,
        )
    return Probe(
        "vmp_dumper",
        ProbeStatus.BLOCKED,
        "VMP dumper CLI probe failed",
        details,
        "Verify HEADLESS_RE_VMP_DUMPER points to a runnable console executable.",
    )


def probe_scylla(settings: Settings) -> Probe:
    executable = settings.scylla
    if executable is None:
        return Probe(
            "scylla",
            ProbeStatus.MISSING,
            "Optional Scylla CLI is not configured",
            remediation=(
                "If you have an authorized Scylla build, set HEADLESS_RE_SCYLLA "
                "to its executable. Not bundled; claims_universal_unpack=false."
            ),
        )
    if not executable.is_file():
        return Probe(
            "scylla",
            ProbeStatus.BLOCKED,
            "Configured Scylla CLI does not exist",
            {"executable": str(executable)},
            "Correct HEADLESS_RE_SCYLLA or remove the stale configuration.",
        )
    from headless_re_mcp.unpack.scylla import probe_scylla as probe_cli

    ok, output = probe_cli(executable)
    details: dict[str, Any] = {
        "executable": str(executable),
        "probe_output": output[:1000] if output else None,
        "claims_universal_unpack": False,
        "scope": "user_configured_external_only",
    }
    if ok:
        return Probe(
            "scylla",
            ProbeStatus.READY,
            "Scylla CLI is available (optional external IAT/dump helper)",
            details,
        )
    return Probe(
        "scylla",
        ProbeStatus.BLOCKED,
        "Scylla CLI probe failed",
        details,
        "Verify HEADLESS_RE_SCYLLA points to a runnable executable.",
    )


def probe_command(name: str, candidates: tuple[str, ...]) -> Probe:
    found = {candidate: shutil.which(candidate) for candidate in candidates}
    found = {candidate: path for candidate, path in found.items() if path}
    if found:
        return Probe(name, ProbeStatus.DETECTED, f"{name} command detected", found)
    return Probe(name, ProbeStatus.MISSING, f"Optional {name} backend is not installed")


def probe_optional_tool(
    name: str,
    settings: Settings,
    settings_attr: str,
    commands: tuple[str, ...],
) -> Probe:
    """Detect an optional CLI from its configured path or PATH, never blocking."""
    configured = getattr(settings, settings_attr, None)
    if configured is not None and Path(str(configured)).is_file():
        return Probe(name, ProbeStatus.DETECTED, f"{name} configured", {"path": str(configured)})
    found = {candidate: shutil.which(candidate) for candidate in commands}
    found = {candidate: path for candidate, path in found.items() if path}
    if found:
        return Probe(name, ProbeStatus.DETECTED, f"{name} command detected", found)
    return Probe(name, ProbeStatus.MISSING, f"Optional {name} tool is not installed")


def probe_webcrack(settings: Settings) -> Probe:
    """Report webcrack honestly: it is a Node CLI and cannot run without node.

    webcrack is installed and launched under Node.js (the client runs the
    launcher directly, which shells out to ``node``); it needs Node 22 or 24.
    ``probe_optional_tool`` finds the ``webcrack`` launcher and stops, so a host
    with webcrack but no ``node`` on PATH reads as "detected" while
    ``js.deobfuscate`` / ``js.beautify`` / ``js.unpack_bundle`` all fail at launch.
    Unlike java (which has its own probe), node is checked nowhere else, so this
    is the only place the doctor can catch a webcrack that cannot actually run --
    e.g. HEADLESS_RE_WEBCRACK set on a box whose service PATH has no node.
    """
    probe = probe_optional_tool("webcrack", settings, "webcrack", ("webcrack",))
    if probe.status != ProbeStatus.DETECTED:
        return probe
    node = shutil.which("node")
    details = dict(probe.details)
    details["node"] = node
    if node is not None:
        return Probe("webcrack", ProbeStatus.DETECTED, probe.summary, details, probe.remediation)
    return Probe(
        "webcrack",
        ProbeStatus.DETECTED,
        f"{probe.summary}, but node is not on PATH so it cannot run",
        details,
        "Install Node.js 22 or 24 and put node on PATH before treating webcrack as ready.",
    )


def probe_python_module(name: str, module: str) -> Probe:
    spec = importlib.util.find_spec(module)
    if spec is None:
        return Probe(name, ProbeStatus.MISSING, f"Optional Python module {module} is not installed")
    return Probe(
        name,
        ProbeStatus.DETECTED,
        f"Optional Python module {module} detected",
        {"origin": spec.origin},
    )


def format_report(report: DoctorReport) -> str:
    required = [probe for probe in report.probes if probe.name in report.required_probes]
    optional = [
        probe
        for probe in report.probes
        if probe.name not in report.required_probes
        and probe.status != ProbeStatus.UNSUPPORTED
    ]
    unsupported = [
        probe
        for probe in report.probes
        if probe.name not in report.required_probes
        and probe.status == ProbeStatus.UNSUPPORTED
    ]
    ready_required = sum(1 for probe in required if probe.status == ProbeStatus.READY)
    blocking = [probe for probe in required if probe.status != ProbeStatus.READY]

    lines = [
        f"Overall: {'READY' if report.ready else 'NOT READY'} "
        f"(required {ready_required}/{len(required)} ready)"
    ]

    def _emit(title: str, probes: list[Probe]) -> None:
        if not probes:
            return
        lines.append("")
        lines.append(title)
        for probe in probes:
            lines.append(f"  [{probe.status.value.upper():8}] {probe.name}: {probe.summary}")
            if probe.remediation and probe.status != ProbeStatus.READY:
                lines.append(f"             fix: {probe.remediation}")

    _emit("Required core components:", required)
    _emit("Optional backends:", optional)
    _emit("Unsupported on this platform (optional):", unsupported)

    if blocking:
        lines.append("")
        lines.append("Blocking required backends (resolve these first):")
        for probe in blocking:
            lines.append(f"  - {probe.name} ({probe.status.value})")
            if probe.remediation:
                lines.append(f"      fix: {probe.remediation}")
    return "\n".join(lines)


def _no_window_flags() -> int:
    if os.name != "nt":
        return 0
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


@dataclass(frozen=True, slots=True)
class _ProbeOutput:
    """What the probes read back, decoded, from a run that had a real deadline."""

    returncode: int
    stdout: str
    stderr: str


def _probe_run(command: list[str], *, timeout: float, env: Any = None) -> _ProbeOutput:
    """Run a version/help probe under a deadline that binds what it started.

    These probe operator-configured paths, and a configured path is often a
    launcher: jadx, apktool and Ghidra are scripts that start a JVM.
    ``subprocess.run`` kills only the script on timeout and then drains with no
    deadline of its own on Windows, so a hung tool hangs the doctor -- the one
    command someone runs *because* the machine is misbehaving.
    """
    completed = run_bounded(
        command, timeout=timeout, creationflags=_no_window_flags(), env=env
    )
    return _ProbeOutput(
        completed.returncode,
        completed.stdout.decode("utf-8", errors="replace"),
        completed.stderr.decode("utf-8", errors="replace"),
    )


def _bounded_text(*values: str, limit: int = 4096) -> str:
    result = "\n".join(value.strip() for value in values if value.strip())
    if len(result) <= limit:
        return result
    return result[:limit] + "\n...[truncated]"


def probe_ghidra(settings: Settings) -> Probe:
    home = getattr(settings, "ghidra_home", None)
    if home is None:
        return Probe(
            "ghidra",
            ProbeStatus.MISSING,
            "Ghidra home is not configured",
            {},
            "Set HEADLESS_RE_GHIDRA_HOME to a Ghidra install with support/analyzeHeadless.",
        )
    from headless_re_mcp.backends.ghidra.client import _find_analyze_headless

    analyze = _find_analyze_headless(home)
    if analyze is None or not analyze.is_file():
        return Probe(
            "ghidra",
            ProbeStatus.MISSING,
            "analyzeHeadless not found under ghidra_home",
            {"home": str(home)},
            "Install Ghidra and point HEADLESS_RE_GHIDRA_HOME at its root.",
        )
    java = shutil.which("java")
    if java is None:
        return Probe(
            "ghidra",
            ProbeStatus.DETECTED,
            "analyzeHeadless is present but java is not on PATH",
            {"home": str(home), "analyze_headless": str(analyze)},
            "Install a JRE and put java on PATH before treating Ghidra as ready.",
        )
    return Probe(
        "ghidra",
        ProbeStatus.READY,
        "Ghidra analyzeHeadless is available",
        {"home": str(home), "analyze_headless": str(analyze), "java": java},
        None,
    )
