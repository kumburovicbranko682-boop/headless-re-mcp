"""M11 optional backends: planned tool surface + degrade; skip≠pass for live."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.capabilities_catalog import list_capabilities
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.doctor import DoctorReport, Probe, ProbeStatus

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

_PLANNED_TOOLS = {
    "r2.pipe": {
        "r2.open",
        "r2.info",
        "r2.functions",
        "r2.strings",
        "r2.imports",
        "r2.exports",
        "r2.disasm",
        "r2.xrefs",
        "r2.xrefs_to",
        "r2.xrefs_from",
    },
    "ghidra.headless": {
        "ghidra.analyze",
        "ghidra.functions",
        "ghidra.symbols",
        "ghidra.xrefs",
        "ghidra.decompile",
    },
    "frida.session": {
        "frida.attach",
        "frida.modules",
        "frida.exports",
        "frida.memory.read",
        "frida.hook.template",
    },
    "windbg.cdb": {
        "windbg.open_dump",
        "windbg.threads",
        "windbg.modules",
        "windbg.disasm",
        "windbg.attach",
        "windbg.live_threads",
        "windbg.live_modules",
        "windbg.live_disasm",
    },
}


@pytest.mark.integration
def test_m11_capabilities_and_missing_backends() -> None:
    service = AnalysisService(Settings.load())
    caps = service.capabilities_search()
    assert caps.ok and caps.data is not None
    assert caps.data["count"] >= 8
    described = service.capabilities_describe("x64dbg.headless")
    assert described.ok

    by_id = {item["id"]: item for item in list_capabilities(service.settings)}
    for cap_id, tools in _PLANNED_TOOLS.items():
        assert cap_id in by_id, f"missing capability {cap_id}"
        assert tools.issubset(set(by_id[cap_id]["tools"])), cap_id
        assert by_id[cap_id].get("optional") is True

    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if not fixture.is_file():
        pytest.skip("fixture missing")
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        # No debuggee: frida must fail closed before attach/exports.
        frida = service.frida_modules(session_id)
        assert not frida.ok and frida.error is not None
        assert frida.error.code in {"invalid_state", "capability_unavailable", "backend_unavailable"}
        frida_attach = service.frida_attach(session_id)
        assert not frida_attach.ok and frida_attach.error is not None
        assert frida_attach.error.code in {
            "invalid_state",
            "capability_unavailable",
            "backend_unavailable",
        }
        frida_exports = service.frida_exports(session_id, "kernel32.dll")
        assert not frida_exports.ok and frida_exports.error is not None
        assert frida_exports.error.code in {
            "invalid_state",
            "capability_unavailable",
            "backend_unavailable",
        }

        for call in (
            lambda: service.r2_info(session_id),
            lambda: service.r2_open(session_id),
            lambda: service.r2_disasm(session_id, 0x1000, count=8),
            lambda: service.r2_xrefs(session_id, 0x1000),
            lambda: service.r2_xrefs_to(session_id, 0x1000),
            lambda: service.r2_xrefs_from(session_id, 0x1000),
        ):
            result = call()
            if not result.ok:
                assert result.error is not None
                assert result.error.code == "capability_unavailable"

        for call in (
            lambda: service.ghidra_analyze(session_id, timeout=5.0),
            lambda: service.ghidra_functions(session_id, limit=8, timeout=5.0),
            lambda: service.ghidra_symbols(session_id, limit=8, timeout=5.0),
            lambda: service.ghidra_xrefs(session_id, "0x1000", limit=8, timeout=5.0),
            lambda: service.ghidra_decompile(session_id, "0x1000", timeout=5.0),
        ):
            result = call()
            if not result.ok:
                assert result.error is not None
                assert result.error.code in {
                    "capability_unavailable",
                    "timeout",
                    "backend_error",
                }

        # Kernel dump analysis is fail-closed without explicit config.
        kernel_denied = service.windbg_open_dump(
            str(fixture), commands=["lm"], timeout=5.0, kernel=True
        )
        assert not kernel_denied.ok and kernel_denied.error is not None
        assert kernel_denied.error.code == "permission_denied"

        for call in (
            lambda: service.windbg_attach(session_id, timeout=5.0),
            lambda: service.windbg_live_threads(session_id, timeout=5.0),
            lambda: service.windbg_live_modules(session_id, timeout=5.0),
            lambda: service.windbg_live_disasm(session_id, "0x1000", length=8, timeout=5.0),
        ):
            result = call()
            assert not result.ok and result.error is not None
            assert result.error.code in {
                "invalid_state",
                "capability_unavailable",
                "backend_unavailable",
                "timeout",
                "backend_error",
            }

        for call in (
            lambda: service.windbg_open_dump(str(fixture), commands=["lm"], timeout=5.0),
            lambda: service.windbg_threads(str(fixture), timeout=5.0),
            lambda: service.windbg_modules(str(fixture), timeout=5.0),
            lambda: service.windbg_disasm(str(fixture), "0x1000", length=8, timeout=5.0),
        ):
            result = call()
            if not result.ok:
                assert result.error is not None
                assert result.error.code in {
                    "capability_unavailable",
                    "timeout",
                    "backend_error",
                    "not_found",
                    "invalid_params",
                }
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_m11_doctor_optional_backends_do_not_block_core_ready() -> None:
    """Optional radare2/ghidra/frida/windbg missing must not flip Doctor.ready."""
    required = {
        "platform",
        "python",
        "ida_idalib",
        "x64dbg_headless_binaries",
    }
    core = tuple(
        Probe(name, ProbeStatus.READY, f"{name} ready") for name in sorted(required)
    )
    optional_missing = (
        Probe("radare2", ProbeStatus.MISSING, "missing"),
        Probe("ghidra", ProbeStatus.MISSING, "missing"),
        Probe("frida", ProbeStatus.MISSING, "missing"),
        Probe("java", ProbeStatus.MISSING, "missing"),
        Probe("windbg", ProbeStatus.MISSING, "missing"),
    )
    report = DoctorReport(probes=core + optional_missing)
    assert report.ready is True

    blocked_core = DoctorReport(
        probes=(
            Probe("platform", ProbeStatus.READY, "ok"),
            Probe("python", ProbeStatus.READY, "ok"),
            Probe("ida_idalib", ProbeStatus.READY, "ok"),
            Probe("x64dbg_source", ProbeStatus.READY, "ok"),
            Probe("x64dbg_headless_binaries", ProbeStatus.MISSING, "missing"),
            Probe("native_toolchain", ProbeStatus.READY, "ok"),
            *optional_missing,
        )
    )
    assert blocked_core.ready is False
