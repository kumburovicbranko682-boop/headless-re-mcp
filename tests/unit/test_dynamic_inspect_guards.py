"""Input guards and no-backend arms of the paused-target inspection wrappers.

DynamicInspectMixin is a block of thin wrappers, each validating its arguments
and then delegating to one bounded debugger request. The happy paths that need
a live x64dbg (modules.dump, pe.headers.runtime, memory.regions) are covered in
test_dynamic_service with a fake worker. This module covers the other half: the
argument rejections that must fire *before* any debugger call, and the arms
that a wrapper reaches when the session has no runtime attached.

None of these need a worker. A bad argument returns invalid_params up front; a
good argument on a session with no x64dbg open falls through to _dynamic_request
and comes back backend_unavailable -- which is enough to prove the delegation
line ran without pretending a debugger was present.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject


def _write_minimal_pe(path: Path) -> None:
    """A 64-bit PE just complete enough for create_session to accept it."""
    optional_size = 0xF0
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    image[0x94:0x96] = optional_size.to_bytes(2, "little")
    optional = 0x98
    image[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    image[optional + 24 : optional + 32] = (0x140000000).to_bytes(8, "little")
    image[optional + 56 : optional + 60] = (0x4000).to_bytes(4, "little")
    path.write_bytes(image)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        debug_event_background_drain=False,
    )


@pytest.fixture
def service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(_settings(tmp_path))


@pytest.fixture
def session_id(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _code(result: Result[JsonObject]) -> str:
    assert not result.ok and result.error is not None
    return result.error.code


# --- argument guards: each rejects before any debugger request --------------


def test_memory_regions_rejects_a_negative_offset(service: Any, session_id: str) -> None:
    assert _code(service.memory_regions(session_id, offset=-1)) == "invalid_params"


def test_memory_regions_rejects_a_non_positive_limit(service: Any, session_id: str) -> None:
    assert _code(service.memory_regions(session_id, limit=0)) == "invalid_params"


def test_memory_protect_query_rejects_a_negative_address(service: Any, session_id: str) -> None:
    assert _code(service.memory_protect_query(session_id, -1)) == "invalid_params"


def test_memory_protection_rejects_a_negative_address(service: Any, session_id: str) -> None:
    assert _code(service.memory_protection(session_id, -1)) == "invalid_params"


def test_memory_protection_rejects_empty_rights(service: Any, session_id: str) -> None:
    assert _code(service.memory_protection(session_id, 0x1000, rights="")) == "invalid_params"


@pytest.mark.parametrize("bad", [0, -1.0, None, "soon", float("nan")])
def test_dynamic_request_rejects_a_bad_timeout_before_the_runtime_lookup(
    service: Any, session_id: str, bad: Any
) -> None:
    """The shared _dynamic_request timeout guard fires ahead of the backend check.

    memory_regions forwards its timeout unvalidated; the guard sits at the top of
    _dynamic_request, before _runtime, so a bad timeout on a session with no
    x64dbg open still reads as invalid_params rather than the backend_unavailable
    a missing runtime would otherwise report.
    """
    assert _code(service.memory_regions(session_id, timeout=bad)) == "invalid_params"


def test_threads_list_rejects_a_negative_offset(service: Any, session_id: str) -> None:
    assert _code(service.threads_list(session_id, offset=-1)) == "invalid_params"


def test_threads_list_rejects_an_out_of_range_limit(service: Any, session_id: str) -> None:
    assert _code(service.threads_list(session_id, limit=0)) == "invalid_params"


def test_threads_context_read_rejects_a_non_positive_tid(service: Any, session_id: str) -> None:
    assert _code(service.threads_context_read(session_id, 0)) == "invalid_params"


def test_threads_context_write_rejects_a_non_positive_tid(service: Any, session_id: str) -> None:
    assert _code(service.threads_context_write(session_id, 0, "rax", 1)) == "invalid_params"


def test_stack_read_rejects_an_out_of_range_count(service: Any, session_id: str) -> None:
    assert _code(service.stack_read(session_id, count=0)) == "invalid_params"


def test_stack_read_rejects_a_negative_address(service: Any, session_id: str) -> None:
    assert _code(service.stack_read(session_id, address=-1)) == "invalid_params"


def test_stack_trace_rejects_an_out_of_range_limit(service: Any, session_id: str) -> None:
    assert _code(service.stack_trace(session_id, limit=0)) == "invalid_params"


def test_disassembly_read_rejects_a_negative_address(service: Any, session_id: str) -> None:
    assert _code(service.disassembly_read(session_id, -1)) == "invalid_params"


def test_disassembly_read_rejects_an_out_of_range_count(service: Any, session_id: str) -> None:
    assert _code(service.disassembly_read(session_id, 0x1000, count=0)) == "invalid_params"


def test_symbols_list_rejects_an_out_of_range_limit(service: Any, session_id: str) -> None:
    assert _code(service.symbols_list(session_id, 0x1000, limit=0)) == "invalid_params"


def test_symbols_resolve_rejects_an_empty_expression(service: Any, session_id: str) -> None:
    assert _code(service.symbols_resolve(session_id, "")) == "invalid_params"


def test_modules_dump_rejects_a_non_positive_size(service: Any, session_id: str) -> None:
    assert _code(service.modules_dump(session_id, 0x140000000, size=0)) == "invalid_params"


def test_imports_scan_rejects_an_unknown_mode(service: Any, session_id: str) -> None:
    assert _code(service.imports_scan(session_id, 0x140000000, mode="sideways")) == "invalid_params"


def test_imports_read_rejects_a_non_positive_size(service: Any, session_id: str) -> None:
    assert _code(service.imports_read(session_id, 0x140002000, 0)) == "invalid_params"


def test_hardware_breakpoint_rejects_a_negative_address(service: Any, session_id: str) -> None:
    assert _code(service.breakpoints_hardware_set(session_id, -1)) == "invalid_params"


def test_hardware_breakpoint_rejects_an_unknown_type(service: Any, session_id: str) -> None:
    result = service.breakpoints_hardware_set(session_id, 0x1000, bp_type="q")
    assert _code(result) == "invalid_params"


def test_hardware_breakpoint_rejects_an_unsupported_size(service: Any, session_id: str) -> None:
    assert _code(service.breakpoints_hardware_set(session_id, 0x1000, size=3)) == "invalid_params"


def test_memory_breakpoint_rejects_an_unknown_type(service: Any, session_id: str) -> None:
    result = service.breakpoints_memory_set(session_id, 0x1000, bp_type="q")
    assert _code(result) == "invalid_params"


def test_condition_breakpoint_rejects_an_empty_expression(service: Any, session_id: str) -> None:
    assert _code(service.breakpoints_condition_set(session_id, 0x1000, "")) == "invalid_params"


def test_condition_breakpoint_rejects_shell_metacharacters(service: Any, session_id: str) -> None:
    result = service.breakpoints_condition_set(session_id, 0x1000, "rax==1;stop")
    assert _code(result) == "invalid_params"


def test_patches_apply_rejects_empty_data(service: Any, session_id: str) -> None:
    assert _code(service.patches_apply(session_id, 0x1000, "")) == "invalid_params"


def test_symbols_list_rejects_a_non_positive_module_base(service: Any, session_id: str) -> None:
    assert _code(service.symbols_list(session_id, 0, limit=8)) == "invalid_params"


def test_modules_dump_rejects_a_non_positive_base(service: Any, session_id: str) -> None:
    assert _code(service.modules_dump(session_id, 0)) == "invalid_params"


def test_pe_headers_runtime_rejects_a_non_positive_base(service: Any, session_id: str) -> None:
    assert _code(service.pe_headers_runtime(session_id, 0)) == "invalid_params"


def test_imports_scan_rejects_a_non_positive_module_base(service: Any, session_id: str) -> None:
    assert _code(service.imports_scan(session_id, 0)) == "invalid_params"


def test_imports_read_rejects_a_non_positive_iat_va(service: Any, session_id: str) -> None:
    assert _code(service.imports_read(session_id, 0, 0x40)) == "invalid_params"


# --- delegation lines: valid arguments, no runtime => backend_unavailable ---

# Each entry runs a wrapper with valid arguments on a session that has no
# x64dbg open. The guard passes, so the wrapper reaches _dynamic_request, which
# reports backend_unavailable rather than raising -- proving the delegate line
# ran and that a missing debugger is a clean failure, not a crash.
_DELEGATES: list[tuple[str, Callable[[Any, str], Result[JsonObject]]]] = [
    ("memory_regions", lambda s, sid: s.memory_regions(sid, offset=0, limit=8)),
    ("memory_protect_query", lambda s, sid: s.memory_protect_query(sid, 0x1000)),
    ("memory_protection", lambda s, sid: s.memory_protection(sid, 0x1000)),
    ("threads_list", lambda s, sid: s.threads_list(sid, offset=0, limit=8)),
    ("threads_current", lambda s, sid: s.threads_current(sid)),
    ("threads_context_read", lambda s, sid: s.threads_context_read(sid, 1)),
    ("threads_context_write", lambda s, sid: s.threads_context_write(sid, 1, "rax", 0)),
    ("stack_read", lambda s, sid: s.stack_read(sid, count=8)),
    ("stack_trace", lambda s, sid: s.stack_trace(sid, limit=8)),
    ("disassembly_read", lambda s, sid: s.disassembly_read(sid, 0x1000, count=8)),
    ("symbols_resolve", lambda s, sid: s.symbols_resolve(sid, "main")),
    ("imports_read", lambda s, sid: s.imports_read(sid, 0x140002000, 0x40)),
    ("hardware_set", lambda s, sid: s.breakpoints_hardware_set(sid, 0x1000)),
    ("hardware_remove", lambda s, sid: s.breakpoints_hardware_remove(sid, 0x1000)),
    ("hardware_list", lambda s, sid: s.breakpoints_hardware_list(sid)),
    ("memory_bp_set", lambda s, sid: s.breakpoints_memory_set(sid, 0x1000)),
    ("memory_bp_remove", lambda s, sid: s.breakpoints_memory_remove(sid, 0x1000)),
    ("memory_bp_list", lambda s, sid: s.breakpoints_memory_list(sid)),
    ("condition_set", lambda s, sid: s.breakpoints_condition_set(sid, 0x1000, "rax==1")),
    ("condition_get", lambda s, sid: s.breakpoints_condition_get(sid, 0x1000)),
    ("patches_list", lambda s, sid: s.patches_list(sid)),
    ("patches_apply", lambda s, sid: s.patches_apply(sid, 0x1000, "90")),
    ("patches_restore", lambda s, sid: s.patches_restore(sid, 0x1000)),
]


@pytest.mark.parametrize("name,call", _DELEGATES, ids=[name for name, _ in _DELEGATES])
def test_valid_arguments_delegate_and_report_missing_backend(
    service: Any, session_id: str, name: str, call: Callable[[Any, str], Result[JsonObject]]
) -> None:
    assert _code(call(service, session_id)) == "backend_unavailable"


def test_memory_protection_forwards_valid_rights_then_needs_a_backend(
    service: Any, session_id: str
) -> None:
    """A valid rights string is packed into the request before delegation."""
    result = service.memory_protection(session_id, 0x1000, rights="rwx")
    assert _code(result) == "backend_unavailable"


def test_stack_read_forwards_a_valid_address_then_needs_a_backend(
    service: Any, session_id: str
) -> None:
    assert _code(service.stack_read(session_id, address=0x1000, count=8)) == "backend_unavailable"


def test_symbols_list_forwards_valid_bounds_then_needs_a_backend(
    service: Any, session_id: str
) -> None:
    assert _code(service.symbols_list(session_id, 0x140000000, limit=8)) == "backend_unavailable"


def test_imports_scan_packs_the_search_window_then_needs_a_backend(
    service: Any, session_id: str
) -> None:
    """search_start/search_size are optional params added before the runtime call."""
    result = service.imports_scan(
        session_id,
        0x140000000,
        search_start=0x140002000,
        search_size=0x400,
    )
    assert _code(result) == "backend_unavailable"


# --- session/artifact and no-runtime error arms -----------------------------


def test_modules_dump_rejects_a_session_id_that_is_not_a_bare_name(service: Any) -> None:
    """A slashed session id could escape the dump directory; the wrapper refuses.

    The check happens inside the method's own try, so the ValueError is turned
    into a structured invalid_request rather than escaping as a raw crash.
    """
    result = service.modules_dump("../escape", 0x140000000, size=0x100)
    assert _code(result) == "invalid_request"


def test_pe_headers_runtime_rejects_a_session_id_that_is_not_a_bare_name(service: Any) -> None:
    result = service.pe_headers_runtime("../escape", 0x140000000, save_artifact=True)
    assert _code(result) == "invalid_request"


def test_imports_scan_without_a_runtime_reports_the_missing_backend(
    service: Any, session_id: str
) -> None:
    assert _code(service.imports_scan(session_id, 0x140000000)) == "backend_unavailable"


def test_pe_headers_runtime_without_a_runtime_reports_the_missing_backend(
    service: Any, session_id: str
) -> None:
    """Valid base, artifact skipped: the native request path fails cleanly."""
    result = service.pe_headers_runtime(session_id, 0x140000000, save_artifact=False)
    assert _code(result) == "backend_unavailable"


def test_modules_dump_without_a_runtime_reports_the_missing_backend(
    service: Any, session_id: str
) -> None:
    """The dump directory is prepared, then the missing worker aborts it."""
    result = service.modules_dump(session_id, 0x140000000, size=0x100)
    assert _code(result) == "backend_unavailable"


def test_module_catalog_without_a_runtime_reports_the_missing_backend(
    service: Any, session_id: str
) -> None:
    assert _code(service.module_catalog(session_id)) == "backend_unavailable"


def test_module_resolve_without_a_runtime_fails(service: Any, session_id: str) -> None:
    result = service.module_resolve(session_id, ModuleSelector(name="fixture.exe"))
    assert not result.ok and result.error is not None


def test_imports_scan_on_an_unknown_session_fails_without_raising(service: Any) -> None:
    """An unknown session raises a non-Xdbg error inside the runtime block.

    That lands in the generic handler rather than the XdbgRpcError one, so it
    still comes back as a structured failure instead of escaping the wrapper.
    """
    result = service.imports_scan("no-such-session", 0x140000000)
    assert not result.ok and result.error is not None


def test_module_catalog_on_an_unknown_session_fails_without_raising(service: Any) -> None:
    """The unknown session raises inside _runtime; the wrapper returns a failure."""
    result = service.module_catalog("no-such-session")
    assert not result.ok and result.error is not None
