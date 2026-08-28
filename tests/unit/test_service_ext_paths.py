"""Coverage for the optional-backend delegating methods on ``ExtAnalysisMixin``.

The r2 / ghidra / frida / windbg tools are absent in unit environments, so every
one of these wrappers is exercised through the arm that matters most for a tool
boundary: a clean ``Result`` failure instead of an escaping exception. Live
sessions reach the client call (which fails ``capability_unavailable`` /
``unsupported_on_platform``); closed sessions and missing debuggees trip the
guards before it.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    FakeStaticWorker,
    _create,
    _service,
    _settings,
    _write_minimal_pe,
)

JsonResult = Result[dict[str, object]]


def _plain_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    return service, _create(service, binary)


def _debuggee_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.dynamic_launch(session_id).ok
    state = service.dynamic_state(session_id)
    assert state.ok and state.data is not None
    assert state.data.get("debuggee_pid")
    return service, session_id


def _assert_failed(result: JsonResult) -> None:
    assert not result.ok and result.error is not None


# ---------------------------------------------------------------------------
# radare2
# ---------------------------------------------------------------------------


def test_r2_methods_fail_closed_without_the_tool(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _assert_failed(service.r2_open(session_id))
    _assert_failed(service.r2_info(session_id))
    _assert_failed(service.r2_functions(session_id))
    _assert_failed(service.r2_strings(session_id))
    _assert_failed(service.r2_imports(session_id))
    _assert_failed(service.r2_exports(session_id))
    _assert_failed(service.r2_disasm(session_id, 0x140001000))
    _assert_failed(service.r2_xrefs(session_id, 0x140001000))


def test_r2_methods_reject_a_closed_session(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)
    assert service.close_session(session_id).ok

    for result in (
        service.r2_open(session_id),
        service.r2_disasm(session_id, 0x140001000),
        service.r2_xrefs(session_id, 0x140001000),
    ):
        _assert_failed(result)
        assert result.error is not None
        assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# ghidra
# ---------------------------------------------------------------------------


def test_ghidra_methods_fail_closed_without_the_tool(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _assert_failed(service.ghidra_analyze(session_id))
    _assert_failed(service.ghidra_functions(session_id))
    _assert_failed(service.ghidra_symbols(session_id))
    _assert_failed(service.ghidra_xrefs(session_id, 0x140001000))
    _assert_failed(service.ghidra_decompile(session_id, 0x140001000))


def test_ghidra_analyze_rejects_a_closed_session(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)
    assert service.close_session(session_id).ok

    result = service.ghidra_analyze(session_id)

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# frida
# ---------------------------------------------------------------------------


def test_frida_methods_reach_the_client_with_a_live_debuggee(tmp_path: Path) -> None:
    service, session_id = _debuggee_session(tmp_path)

    _assert_failed(service.frida_attach(session_id))
    _assert_failed(service.frida_modules(session_id))
    _assert_failed(service.frida_exports(session_id, "kernel32.dll"))
    _assert_failed(service.frida_memory_read(session_id, 0x140001000, 16))
    _assert_failed(service.frida_hook_template(session_id))


def test_frida_attach_rejects_a_session_without_a_debuggee(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    result = service.frida_attach(session_id)

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "invalid_state"


# ---------------------------------------------------------------------------
# windbg
# ---------------------------------------------------------------------------


def test_windbg_dump_methods_fail_closed(tmp_path: Path) -> None:
    service, _session_id = _plain_session(tmp_path)
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"MDMP")

    _assert_failed(service.windbg_open_dump(str(dump)))
    _assert_failed(service.windbg_threads(str(dump)))
    _assert_failed(service.windbg_modules(str(dump)))
    _assert_failed(service.windbg_disasm(str(dump), 0x1000))


def test_windbg_live_methods_reach_the_client_with_a_debuggee(tmp_path: Path) -> None:
    service, session_id = _debuggee_session(tmp_path)

    _assert_failed(service.windbg_attach(session_id))
    _assert_failed(service.windbg_live_threads(session_id))
    _assert_failed(service.windbg_live_modules(session_id))
    _assert_failed(service.windbg_live_disasm(session_id, 0x140001000))


def test_windbg_live_threads_rejects_a_session_without_a_debuggee(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    result = service.windbg_live_threads(session_id)

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "invalid_state"
