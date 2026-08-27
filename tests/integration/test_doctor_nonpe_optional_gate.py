"""Live honesty gate: doctor's optional non-PE detection on a real machine.

Every per-probe path in ``doctor`` is exhaustively unit-tested, but always with
``shutil.which`` / ``importlib.util.find_spec`` monkeypatched. Nothing proves
that ``run_doctor()`` actually wires the optional non-PE backends in and maps a
*genuine* install to ``DETECTED``: a probe dropped from ``run_doctor`` or a
candidate name typo would sail past the mocked unit tests while quietly telling
operators a tool they installed is missing.

This gate runs ``run_doctor()`` against the real host. For every optional non-PE
backend that is truly present it asserts ``DETECTED`` (skip != pass per tool when
absent), and it pins the durable contract that no optional non-PE backend is
ever in the required set on either platform -- accidentally requiring one would
flip Linux readiness to NOT READY for every user who never installed it.
"""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import ProbeStatus, required_probe_names, run_doctor

# Optional CLI backends and the PATH names doctor should detect them by. These
# mirror run_doctor()'s candidate lists: if doctor's list drifts to a name the
# tool does not actually use, doctor reports MISSING while the check below still
# finds the real binary, and the mismatch fails the gate.
_CLI_TOOLS: dict[str, tuple[str, ...]] = {
    "radare2": ("r2", "rizin", "radare2"),
    "adb": ("adb",),
    "jadx": ("jadx", "jadx.bat"),
    "apktool": ("apktool", "apktool.bat"),
    "apksigner": ("apksigner", "apksigner.bat"),
    "webcrack": ("webcrack",),
    "wabt": ("wasm2wat",),
}
# Optional Python-module backends and their import names.
_PY_MODULES: dict[str, str] = {
    "frida": "frida",
    "androguard": "androguard",
    "adbutils": "adbutils",
    "playwright": "playwright",
    "mitmproxy": "mitmproxy",
}
# Every optional non-PE backend doctor reports. None of these may ever be
# required: ghidra/java back the cross-platform decompiler path, the rest are
# the Android and Web lines.
_NONPE_OPTIONAL = frozenset(_CLI_TOOLS) | frozenset(_PY_MODULES) | {"ghidra", "java"}


def _report(artifact_root: Path):
    """Run doctor with no configured tool paths, so detection is PATH/import only."""
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=artifact_root,
    )
    return run_doctor(settings)


@pytest.mark.integration
def test_no_optional_nonpe_backend_is_ever_required() -> None:
    """An optional backend in the required set would block readiness for users
    who never installed it. This must hold on both host platforms."""
    for platform_name in ("windows", "linux"):
        required = required_probe_names(platform_name)
        overlap = _NONPE_OPTIONAL & required
        assert not overlap, (
            f"optional non-PE backends must never be required on {platform_name}: "
            f"{sorted(overlap)}"
        )


@pytest.mark.integration
def test_installed_optional_nonpe_tools_report_detected(tmp_path: Path) -> None:
    report = _report(tmp_path)
    statuses = {probe.name: probe.status for probe in report.probes}

    # doctor must wire every optional non-PE backend into the report at all.
    for name in _NONPE_OPTIONAL:
        assert name in statuses, f"doctor dropped the {name} probe entirely"

    checked = 0
    for name, candidates in _CLI_TOOLS.items():
        if any(shutil.which(candidate) for candidate in candidates):
            assert statuses[name] == ProbeStatus.DETECTED, (
                f"{name} is on PATH but doctor reported {statuses[name].value}"
            )
            checked += 1
    for name, module in _PY_MODULES.items():
        if importlib.util.find_spec(module) is not None:
            assert statuses[name] == ProbeStatus.DETECTED, (
                f"{module} is importable but doctor reported {statuses[name].value}"
            )
            checked += 1

    if checked == 0:
        pytest.skip(
            "no optional non-PE backend installed — detection gate not run (skip != pass)"
        )

    # Whatever the optional statuses, they cannot move readiness: the report is
    # ready exactly when its required probes are ready, nothing else.
    required = report.required_probes
    assert report.ready == all(
        probe.status == ProbeStatus.READY
        for probe in report.probes
        if probe.name in required
    )
    assert not (_NONPE_OPTIONAL & required)
