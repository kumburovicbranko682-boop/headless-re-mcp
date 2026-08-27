"""Input guards and request-shaping of DynamicInspectMixin's thin wrappers.

Each read-side method validates its arguments, then forwards exactly one
bounded ``_dynamic_request``. The rejection branches (``invalid_params`` /
``dump_too_large``) never touch a backend, so a stub that records the forwarded
call is enough to pin both the guard verdicts and the method/params shape the
mixin hands the debugger.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.limits import MAX_MODULE_DUMP_BYTES
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service_dynamic_inspect import (
    DynamicInspectMixin,
    _atomic_write_bytes,
    _module_base_present,
)

JsonObject = dict[str, Any]
SID = "sess-abc"


class _Probe(DynamicInspectMixin):
    """Capture the one forwarded request instead of reaching a live backend."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, JsonObject | None, float]] = []

    def _dynamic_request(
        self,
        session_id: str,
        method: str,
        params: JsonObject | None = None,
        *,
        wait_for: set[str] | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        assert session_id == SID
        self.calls.append((method, params, timeout))
        return Result[JsonObject](ok=True, data={"method": method})

    @property
    def last(self) -> tuple[str, JsonObject | None, float]:
        return self.calls[-1]


@pytest.fixture
def probe() -> _Probe:
    return _Probe()


def _reject(result: Result[JsonObject], code: str = "invalid_params") -> None:
    assert not result.ok
    assert result.error is not None
    assert result.error.code == code


# --- module-level helpers -------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "not-a-dict",
        {"modules": "not-a-list"},
        {"modules": [{"base": 0x1000}, "junk"]},
    ],
)
def test_module_base_present_rejects_bad_shapes(payload: object) -> None:
    assert _module_base_present(payload, 0x2000) is False


def test_module_base_present_matches_declared_base() -> None:
    payload = {"modules": [{"base": 0x400000}, {"base": 0x10000}]}
    assert _module_base_present(payload, 0x400000) is True
    assert _module_base_present(payload, 0x999) is False


def test_atomic_write_bytes_cleans_up_temp_when_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "nested" / "out.bin"

    def boom(_src: object, _dst: object) -> None:
        raise OSError("replace refused")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="replace refused"):
        _atomic_write_bytes(destination, b"payload")

    # The sibling temp file must not survive a failed publish.
    leftovers = list(destination.parent.glob(".out-*.tmp"))
    assert leftovers == []
    assert not destination.exists()


# --- rejection branches (never forward) -----------------------------------


def test_memory_regions_rejects_and_forwards(probe: _Probe) -> None:
    _reject(probe.memory_regions(SID, offset=-1))
    _reject(probe.memory_regions(SID, limit=0))
    _reject(probe.memory_regions(SID, limit=-3))
    assert probe.calls == []

    probe.memory_regions(SID, offset=5, limit=10, timeout=12.0)
    method, params, timeout = probe.last
    assert method == "memory.regions"
    assert params == {"offset": 5, "limit": 10}
    assert timeout == 12.0


def test_memory_protect_query_guard_and_forward(probe: _Probe) -> None:
    _reject(probe.memory_protect_query(SID, -1))
    probe.memory_protect_query(SID, 0x140000)
    assert probe.last[0] == "memory.protect.query"
    assert probe.last[1] == {"address": 0x140000}


def test_memory_protection_guards_and_forward(probe: _Probe) -> None:
    _reject(probe.memory_protection(SID, -5))
    _reject(probe.memory_protection(SID, 0x1000, rights=""))
    probe.memory_protection(SID, 0x1000, rights="rwx")
    assert probe.last[0] == "memory.protection"
    assert probe.last[1] == {"address": 0x1000, "rights": "rwx"}


def test_threads_list_guards_and_forward(probe: _Probe) -> None:
    _reject(probe.threads_list(SID, offset=-1))
    _reject(probe.threads_list(SID, limit=0))
    _reject(probe.threads_list(SID, limit=2048))
    probe.threads_list(SID, offset=2, limit=64)
    assert probe.last[1] == {"offset": 2, "limit": 64}


def test_threads_current_forward(probe: _Probe) -> None:
    probe.threads_current(SID)
    assert probe.last[0] == "threads.current"


def test_threads_context_read_and_write_guards(probe: _Probe) -> None:
    _reject(probe.threads_context_read(SID, 0))
    probe.threads_context_read(SID, 7)
    assert probe.last[1] == {"tid": 7}

    _reject(probe.threads_context_write(SID, -1, "rax", 1))
    probe.threads_context_write(SID, 7, "rax", 0xDEAD)
    assert probe.last[0] == "threads.context.write"
    assert probe.last[1] == {"tid": 7, "name": "rax", "value": 0xDEAD}


def test_stack_read_guards_and_forward(probe: _Probe) -> None:
    _reject(probe.stack_read(SID, count=0))
    _reject(probe.stack_read(SID, count=999))
    _reject(probe.stack_read(SID, address=-1))
    probe.stack_read(SID, address=0x20, count=8)
    assert probe.last[1] == {"count": 8, "address": 0x20}


def test_stack_trace_guard_and_forward(probe: _Probe) -> None:
    _reject(probe.stack_trace(SID, limit=0))
    probe.stack_trace(SID, limit=16)
    assert probe.last[1] == {"limit": 16}


def test_disassembly_read_guards_and_forward(probe: _Probe) -> None:
    _reject(probe.disassembly_read(SID, -1))
    _reject(probe.disassembly_read(SID, 0x400, count=0))
    probe.disassembly_read(SID, 0x400, count=4)
    assert probe.last[1] == {"address": 0x400, "count": 4}


def test_symbols_list_guards_and_forward(probe: _Probe) -> None:
    _reject(probe.symbols_list(SID, 0))
    _reject(probe.symbols_list(SID, 0x400000, limit=99999))
    probe.symbols_list(SID, 0x400000, limit=32)
    assert probe.last[1] == {"module_base": 0x400000, "limit": 32}


def test_symbols_resolve_guard_and_forward(probe: _Probe) -> None:
    _reject(probe.symbols_resolve(SID, ""))
    probe.symbols_resolve(SID, "kernel32.dll!LoadLibraryA")
    assert probe.last[1] == {"expression": "kernel32.dll!LoadLibraryA"}


def test_imports_read_guards_and_forward(probe: _Probe) -> None:
    _reject(probe.imports_read(SID, 0, 16))
    _reject(probe.imports_read(SID, 0x1000, 0))
    probe.imports_read(SID, 0x1000, 64)
    assert probe.last[0] == "imports.read"
    assert probe.last[1] == {"iat_va": 0x1000, "size": 64}


def test_imports_scan_rejects_bad_module_base_and_mode(probe: _Probe) -> None:
    _reject(probe.imports_scan(SID, 0))
    _reject(probe.imports_scan(SID, 0x400000, mode="bogus"))
    assert probe.calls == []


# --- breakpoints & patches -------------------------------------------------


def test_breakpoints_hardware_guards_and_forward(probe: _Probe) -> None:
    _reject(probe.breakpoints_hardware_set(SID, -1))
    _reject(probe.breakpoints_hardware_set(SID, 0x10, bp_type="nope"))
    _reject(probe.breakpoints_hardware_set(SID, 0x10, size=3))
    probe.breakpoints_hardware_set(SID, 0x10, bp_type="x", size=4)
    assert probe.last[1] == {"address": 0x10, "type": "x", "size": 4}

    probe.breakpoints_hardware_remove(SID, 0x10)
    assert probe.last[0] == "breakpoints.hardware.remove"
    probe.breakpoints_hardware_list(SID)
    assert probe.last[0] == "breakpoints.hardware.list"


def test_breakpoints_memory_guards_and_forward(probe: _Probe) -> None:
    _reject(probe.breakpoints_memory_set(SID, 0x10, bp_type="zzz"))
    probe.breakpoints_memory_set(SID, 0x10, bp_type="a")
    assert probe.last[1] == {"address": 0x10, "type": "a"}
    probe.breakpoints_memory_remove(SID, 0x10)
    assert probe.last[0] == "breakpoints.memory.remove"
    probe.breakpoints_memory_list(SID)
    assert probe.last[0] == "breakpoints.memory.list"


def test_breakpoints_condition_guards_and_forward(probe: _Probe) -> None:
    _reject(probe.breakpoints_condition_set(SID, 0x10, ""))
    _reject(probe.breakpoints_condition_set(SID, 0x10, "x" * 513))
    _reject(probe.breakpoints_condition_set(SID, 0x10, "rax == 1; drop"))
    probe.breakpoints_condition_set(SID, 0x10, "rax == 1")
    assert probe.last[1] == {"address": 0x10, "expression": "rax == 1"}
    probe.breakpoints_condition_get(SID, 0x10)
    assert probe.last[0] == "breakpoints.condition.get"


def test_patches_guards_and_forward(probe: _Probe) -> None:
    probe.patches_list(SID)
    assert probe.last[0] == "patches.list"
    _reject(probe.patches_apply(SID, 0x10, ""))
    probe.patches_apply(SID, 0x10, "9090")
    assert probe.last[1] == {"address": 0x10, "data": "9090"}
    probe.patches_restore(SID, 0x10)
    assert probe.last[0] == "patches.restore"


# --- modules_dump guards that return before any backend work ---------------


def test_modules_dump_argument_guards(probe: _Probe) -> None:
    _reject(probe.modules_dump(SID, 0))
    _reject(probe.modules_dump(SID, 0x400000, size=0))
    _reject(
        probe.modules_dump(SID, 0x400000, size=MAX_MODULE_DUMP_BYTES + 1),
        code="dump_too_large",
    )
    assert probe.calls == []


def test_modules_dump_rejects_traversal_session_id(probe: _Probe) -> None:
    result = probe.modules_dump("../escape", 0x400000)
    assert not result.ok
    assert result.error is not None
    assert probe.calls == []


def test_pe_headers_runtime_rejects_bad_base(probe: _Probe) -> None:
    _reject(probe.pe_headers_runtime(SID, 0))
    assert probe.calls == []
