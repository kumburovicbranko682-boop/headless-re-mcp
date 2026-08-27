"""Live doctor gate: `mcp doctor` must tell the truth about what is installed.

run_doctor probes the real host. Its detection logic -- module names, command
candidates, platform gating -- is otherwise only unit-tested with stubs, so a
drift (a renamed binary candidate, a wrong module name) would ship a doctor
that calls an installed backend "missing". This runs the real probes and, for
every backend genuinely present on this host, asserts the doctor does not
report it missing. Absent backends are simply not asserted, so the gate is
honest on a bare machine and exhaustive in the CI image where every beyond-PE
backend is installed.
"""

from __future__ import annotations

import importlib.util
import shutil

import pytest

from headless_re_mcp.doctor import ProbeStatus, run_doctor
from headless_re_mcp.platform_support import runtime_platform_report

# Probes whose detection is PATH- or import-based, so shutil.which / find_spec
# predicts exactly what the doctor should report. Deliberately excludes probes
# that only look at an explicit settings path (upx/diec/de4dot/...), which stay
# "missing" until configured even when the tool is on PATH.
_MODULE_PROBES = {
    "frida": "frida",
    "androguard": "androguard",
    "adbutils": "adbutils",
    "playwright": "playwright",
    "mitmproxy": "mitmproxy",
}
_COMMAND_PROBES = {
    "radare2": ("r2", "rizin"),
    "adb": ("adb",),
    "jadx": ("jadx", "jadx.bat"),
    "apktool": ("apktool", "apktool.bat"),
    "apksigner": ("apksigner", "apksigner.bat"),
    "webcrack": ("webcrack",),
    "wabt": ("wasm2wat",),
    "java": ("java",),
}


@pytest.mark.integration
def test_doctor_detects_every_backend_actually_installed() -> None:
    report = run_doctor()
    probes = {probe.name: probe for probe in report.probes}

    # The core the beyond-PE lines rest on is present: on a supported host both
    # platform and python are ready, which is the whole Linux required set.
    assert probes["platform"].status is ProbeStatus.READY
    assert probes["python"].status is ProbeStatus.READY
    if runtime_platform_report()["name"] != "windows":
        assert report.required_probes == frozenset({"platform", "python"})
        assert report.ready is True

    checked: list[str] = []
    for name, module in _MODULE_PROBES.items():
        if importlib.util.find_spec(module) is not None:
            assert probes[name].status is not ProbeStatus.MISSING, name
            checked.append(name)
    for name, candidates in _COMMAND_PROBES.items():
        if any(shutil.which(candidate) for candidate in candidates):
            assert probes[name].status is not ProbeStatus.MISSING, name
            checked.append(name)

    # Only meaningful when at least one optional backend is present; a truly
    # bare host makes it a no-op, which should be visible, not a silent green.
    if not checked:
        pytest.skip(
            "no optional backends installed — doctor detection gate is a no-op (skip != pass)"
        )


@pytest.mark.integration
def test_doctor_marks_windows_only_backends_unsupported_on_linux() -> None:
    """Platform gating is honest: Windows-only backends are unsupported, not missing."""
    if runtime_platform_report()["name"] == "windows":
        pytest.skip("Linux-only assertion about platform gating (skip != pass)")
    probes = {probe.name: probe for probe in run_doctor().probes}
    for name in ("x64dbg_headless_binaries", "win32_ui", "scylla", "windbg"):
        assert probes[name].status is ProbeStatus.UNSUPPORTED, name
