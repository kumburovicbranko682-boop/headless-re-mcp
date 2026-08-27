"""The paused-target inspection surface must bound input and register artifacts.

``DynamicInspectMixin`` is a block of thin, uniform wrappers over one bounded
x64dbg request each: every one validates its arguments before touching the
worker, and the few that write to disk (modules.dump, pe.headers.runtime) bound
the size, check free space, verify the returned artifact stays inside the
session tree, and register it. None of that needs a real Windows debugger -- the
shared ``FakeDynamicWorker`` is extended with the full capability set and a
generic echo so the wrappers, the argument guards, and the artifact bookkeeping
all run here.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.limits import MAX_IMPORT_SCAN_BYTES, MAX_MODULE_DUMP_BYTES
from headless_re_mcp.core.models import BackendKind, ModuleSelector
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_dynamic_inspect import (
    _atomic_write_bytes,
    _module_base_present,
)
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _service,
    _write_minimal_pe,
)

JsonObject = dict[str, Any]

_EXTRA_CAPS = frozenset(
    {
        "memory.protection",
        "threads.list",
        "threads.current",
        "threads.context.read",
        "threads.context.write",
        "stack.read",
        "stack.trace",
        "disassembly.read",
        "symbols.list",
        "symbols.resolve",
        "breakpoints.hardware.set",
        "breakpoints.hardware.remove",
        "breakpoints.hardware.list",
        "breakpoints.memory.set",
        "breakpoints.memory.remove",
        "breakpoints.memory.list",
        "breakpoints.condition.set",
        "breakpoints.condition.get",
        "patches.list",
        "patches.apply",
        "patches.restore",
    }
)


class FakeInspectWorker(FakeDynamicWorker):
    """A dynamic worker that answers the whole read-side inspection surface."""

    def __init__(self, *, drop_caps: frozenset[str] = frozenset(), **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # "normal" delegates modules.dump to the parent (writes module_size
        # bytes); the other modes exercise the post-dump guards.
        self.dump_mode = "normal"
        self.memory_read_hex: str | None = None
        self._drop_caps = drop_caps
        self._dumped = False

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset((set(super().capabilities) | _EXTRA_CAPS) - self._drop_caps)

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        values = params or {}
        if command == "modules.list" and self.dump_mode == "unload" and self._dumped:
            # The module vanished after the dump: report an empty snapshot.
            return {"modules": [], "count": 0, "total": 0, "offset": 0, "limit": 256}
        if command == "modules.dump" and self.dump_mode != "normal":
            self.requests.append((command, dict(values)))
            out = Path(str(values["output_path"]))
            if self.dump_mode == "crash":
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(b"\x90" * 64)
                raise RuntimeError("dump worker crashed after writing")
            if self.dump_mode == "unload":
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(b"\x90" * 64)
                self._dumped = True
                return {"base": values["base"], "output_path": str(out), "size": 64}
            if self.dump_mode == "badpath":
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(b"\x90" * 64)
                # A NUL byte makes Path.resolve() reject the returned path.
                return {"base": values["base"], "output_path": "\x00bad", "size": 64}
            if self.dump_mode == "missing":
                return {"base": values["base"], "output_path": str(out), "size": 0}
            if self.dump_mode == "oversize":
                out.parent.mkdir(parents=True, exist_ok=True)
                overflow = int(values.get("size", 4096)) + 4096
                out.write_bytes(b"\x90" * overflow)
                return {"base": values["base"], "output_path": str(out), "size": overflow}
        if command == "memory.read" and self.memory_read_hex is not None:
            self.requests.append((command, dict(values)))
            return {
                "address": values["address"],
                "size": values["size"],
                "encoding": "hex",
                "data": self.memory_read_hex,
            }
        if command in _EXTRA_CAPS:
            self.requests.append((command, dict(values)))
            return {"method": command, **values}
        return super().request(command, params, timeout=timeout)


@pytest.fixture
def env(tmp_path: Path) -> Iterator[tuple[AnalysisService, str, FakeInspectWorker]]:
    worker = FakeInspectWorker()
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.dynamic_launch(session_id).ok
    try:
        yield service, session_id, worker
    finally:
        service.close_all()


def _launch(tmp_path: Path, worker: FakeInspectWorker) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.dynamic_launch(session_id).ok
    return service, session_id


# --------------------------------------------------------------------------
# pure helpers
# --------------------------------------------------------------------------


def test_module_base_present_handles_bad_shapes() -> None:
    assert _module_base_present("not a dict", 0x1000) is False
    assert _module_base_present({"modules": "not a list"}, 0x1000) is False
    assert _module_base_present({"modules": [{"base": 0x1000}]}, 0x1000) is True
    assert _module_base_present({"modules": [{"base": 0x2000}]}, 0x1000) is False


def test_atomic_write_bytes_cleans_up_on_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "sub" / "out.bin"

    def _boom(src: Any, dst: Any) -> None:
        raise OSError("replace refused")

    monkeypatch.setattr(os, "replace", _boom)
    with pytest.raises(OSError, match="replace refused"):
        _atomic_write_bytes(destination, b"payload")
    # The sibling temp file must not linger after the failed publish.
    leftovers = list((tmp_path / "sub").glob(".out-*.tmp"))
    assert leftovers == []


# --------------------------------------------------------------------------
# wrapper smoke: every wrapper reaches the backend on valid input
# --------------------------------------------------------------------------


def test_every_wrapper_reaches_the_backend(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, _ = env
    calls = [
        service.memory_regions(sid),
        service.memory_regions(sid, limit=10),
        service.memory_protect_query(sid, 0x1000),
        service.memory_protection(sid, 0x1000),
        service.memory_protection(sid, 0x1000, rights="rwx"),
        service.threads_list(sid),
        service.threads_current(sid),
        service.threads_context_read(sid, 1),
        service.threads_context_write(sid, 1, "rax", 5),
        service.stack_read(sid),
        service.stack_read(sid, address=0x1000),
        service.stack_trace(sid),
        service.disassembly_read(sid, 0x1000),
        service.symbols_list(sid, 0x140000000),
        service.symbols_resolve(sid, "kernel32!CreateFileW"),
        service.imports_read(sid, 0x2000, 0x40),
        service.breakpoints_hardware_set(sid, 0x1000),
        service.breakpoints_hardware_remove(sid, 0x1000),
        service.breakpoints_hardware_list(sid),
        service.breakpoints_memory_set(sid, 0x1000),
        service.breakpoints_memory_remove(sid, 0x1000),
        service.breakpoints_memory_list(sid),
        service.breakpoints_condition_set(sid, 0x1000, "eax==1"),
        service.breakpoints_condition_get(sid, 0x1000),
        service.patches_list(sid),
        service.patches_apply(sid, 0x1000, "90"),
        service.patches_restore(sid, 0x1000),
    ]
    for result in calls:
        assert result.ok, result.error


# --------------------------------------------------------------------------
# argument validation guards
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method, args, kwargs, code",
    [
        ("memory_regions", (), {"offset": -1}, "invalid_params"),
        ("memory_regions", (), {"limit": 0}, "invalid_params"),
        ("memory_protect_query", (-1,), {}, "invalid_params"),
        ("memory_protection", (-1,), {}, "invalid_params"),
        ("memory_protection", (0x1000,), {"rights": ""}, "invalid_params"),
        ("threads_list", (), {"offset": -1}, "invalid_params"),
        ("threads_list", (), {"limit": 0}, "invalid_params"),
        ("threads_context_read", (0,), {}, "invalid_params"),
        ("threads_context_write", (0, "rax", 1), {}, "invalid_params"),
        ("stack_read", (), {"count": 0}, "invalid_params"),
        ("stack_read", (), {"address": -1}, "invalid_params"),
        ("stack_trace", (), {"limit": 0}, "invalid_params"),
        ("disassembly_read", (-1,), {}, "invalid_params"),
        ("disassembly_read", (0x1000,), {"count": 0}, "invalid_params"),
        ("symbols_list", (0,), {}, "invalid_params"),
        ("symbols_list", (0x1000,), {"limit": 0}, "invalid_params"),
        ("symbols_resolve", ("",), {}, "invalid_params"),
        ("modules_dump", (0,), {}, "invalid_params"),
        ("modules_dump", (0x1000,), {"size": 0}, "invalid_params"),
        ("modules_dump", (0x1000,), {"size": MAX_MODULE_DUMP_BYTES + 1}, "dump_too_large"),
        ("pe_headers_runtime", (0,), {}, "invalid_params"),
        ("imports_scan", (0,), {}, "invalid_params"),
        ("imports_scan", (0x1000,), {"mode": "bogus"}, "invalid_params"),
        ("imports_scan", (0x1000,), {"search_size": 0}, "invalid_params"),
        ("imports_scan", (0x1000,), {"search_size": MAX_IMPORT_SCAN_BYTES + 1}, "invalid_params"),
        ("imports_read", (0, 0x40), {}, "invalid_params"),
        ("imports_read", (0x2000, 0), {}, "invalid_params"),
        ("imports_read", (0x2000, MAX_IMPORT_SCAN_BYTES + 1), {}, "invalid_params"),
        ("breakpoints_hardware_set", (-1,), {}, "invalid_params"),
        ("breakpoints_hardware_set", (0x1000,), {"bp_type": "z"}, "invalid_params"),
        ("breakpoints_hardware_set", (0x1000,), {"size": 3}, "invalid_params"),
        ("breakpoints_hardware_remove", (-1,), {}, "invalid_params"),
        ("breakpoints_memory_set", (-1,), {}, "invalid_params"),
        ("breakpoints_memory_set", (0x1000,), {"bp_type": "z"}, "invalid_params"),
        ("breakpoints_memory_remove", (-1,), {}, "invalid_params"),
        ("breakpoints_condition_set", (0x1000, ""), {}, "invalid_params"),
        ("breakpoints_condition_set", (0x1000, "a;b"), {}, "invalid_params"),
        ("patches_apply", (0x1000, ""), {}, "invalid_params"),
    ],
)
def test_wrappers_reject_bad_arguments(
    env: tuple[AnalysisService, str, FakeInspectWorker],
    method: str,
    args: tuple[Any, ...],
    kwargs: JsonObject,
    code: str,
) -> None:
    service, sid, _ = env
    result = getattr(service, method)(sid, *args, **kwargs)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == code


# --------------------------------------------------------------------------
# modules_dump
# --------------------------------------------------------------------------


def test_modules_dump_registers_the_artifact(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, _ = env
    result = service.modules_dump(sid, 0x140000000)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["artifact_id"]
    assert result.data["artifact_kind"] == "module_dump"
    assert Path(result.data["output_path"]).is_file()


def test_modules_dump_refuses_when_disk_is_too_small(
    env: tuple[AnalysisService, str, FakeInspectWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, _ = env

    class _Usage:
        free = 4

    monkeypatch.setattr(
        "headless_re_mcp.core.service_dynamic_inspect.shutil.disk_usage",
        lambda _p: _Usage(),
    )
    result = service.modules_dump(sid, 0x140000000, size=1024)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "insufficient_disk_space"


def test_modules_dump_reports_a_module_missing_before_the_dump(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, _ = env
    result = service.modules_dump(sid, 0xDEAD0000)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "module_not_found"


def test_modules_dump_detects_a_missing_artifact(tmp_path: Path) -> None:
    worker = FakeInspectWorker()
    worker.dump_mode = "missing"
    service, sid = _launch(tmp_path, worker)
    try:
        result = service.modules_dump(sid, 0x140000000)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "artifact_missing"
    finally:
        service.close_all()


def test_modules_dump_refuses_an_oversized_artifact(tmp_path: Path) -> None:
    worker = FakeInspectWorker()
    worker.dump_mode = "oversize"
    service, sid = _launch(tmp_path, worker)
    try:
        result = service.modules_dump(sid, 0x140000000, size=1024)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "dump_too_large"
    finally:
        service.close_all()


def test_modules_dump_reports_a_module_unloaded_during_the_dump(tmp_path: Path) -> None:
    worker = FakeInspectWorker()
    worker.dump_mode = "unload"
    service, sid = _launch(tmp_path, worker)
    try:
        result = service.modules_dump(sid, 0x140000000)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "module_unloaded_during_dump"
    finally:
        service.close_all()


def test_modules_dump_rejects_an_unparseable_returned_path(tmp_path: Path) -> None:
    worker = FakeInspectWorker()
    worker.dump_mode = "badpath"
    service, sid = _launch(tmp_path, worker)
    try:
        result = service.modules_dump(sid, 0x140000000)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "rpc_protocol_error"
    finally:
        service.close_all()


def test_modules_dump_cleans_up_after_a_worker_crash(tmp_path: Path) -> None:
    worker = FakeInspectWorker()
    worker.dump_mode = "crash"
    service, sid = _launch(tmp_path, worker)
    try:
        result = service.modules_dump(sid, 0x140000000)
        assert result.ok is False
        assert result.error is not None
        # The partially written artifact must not survive the failed dump.
        dump_dir = service.settings.artifact_root.expanduser().resolve() / "dump" / sid
        if dump_dir.is_dir():
            assert list(dump_dir.glob("dumped-module-*.bin")) == []
    finally:
        service.close_all()


def test_modules_dump_refuses_a_stale_snapshot(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, _ = env
    runtime = service._runtime_owner.get(sid, BackendKind.X64DBG)
    assert runtime is not None
    runtime.snapshot_resync_required = True
    result = service.modules_dump(sid, 0x140000000)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "event_gap_resync_required"


def test_modules_dump_rejects_a_hostile_session_id(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, _, _ = env
    result = service.modules_dump("../escape", 0x140000000)
    assert result.ok is False
    assert result.error is not None


def test_modules_dump_refuses_when_the_capability_is_missing(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, worker = env
    # Drop the capability after launch so open_dynamic's own sync is unaffected.
    worker._drop_caps = frozenset({"modules.dump"})
    result = service.modules_dump(sid, 0x140000000)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_modules_dump_skips_presence_checks_without_modules_list(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, worker = env
    worker._drop_caps = frozenset({"modules.list"})
    # With no modules.list capability the pre/post presence guards are skipped
    # and the dump is registered straight from the write.
    result = service.modules_dump(sid, 0x140000000)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["artifact_id"]


# --------------------------------------------------------------------------
# pe_headers_runtime
# --------------------------------------------------------------------------


def test_pe_headers_runtime_registers_the_header_artifact(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, _ = env
    result = service.pe_headers_runtime(sid, 0x140000000)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["header_artifact"]
    assert result.data["artifact_id"]


def test_pe_headers_runtime_without_saving_skips_the_artifact(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, _ = env
    result = service.pe_headers_runtime(sid, 0x140000000, save_artifact=False)
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data


def test_pe_headers_runtime_rejects_a_hostile_session_id(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, _, _ = env
    result = service.pe_headers_runtime("../escape", 0x140000000)
    assert result.ok is False
    assert result.error is not None


def test_pe_headers_runtime_fallback_returns_when_memory_read_fails(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, worker = env
    # No native headers and no memory.read: the fallback gives up and returns
    # the original capability_unavailable rather than inventing headers.
    worker._drop_caps = frozenset({"pe.headers.runtime", "memory.read"})
    result = service.pe_headers_runtime(sid, 0x140000000)
    assert result.ok is False
    assert result.error is not None


def test_pe_headers_runtime_fallback_without_saving(tmp_path: Path) -> None:
    worker = FakeInspectWorker()
    service, sid = _launch(tmp_path, worker)
    try:
        pe_bytes = bytearray(0x1000)
        source = tmp_path / "img.bin"
        _write_minimal_pe(source)
        raw = source.read_bytes()
        pe_bytes[: len(raw)] = raw
        worker.memory_read_hex = bytes(pe_bytes).hex()

        def _no_headers(
            command: str, params: JsonObject | None = None, *, timeout: float = 120.0
        ) -> JsonObject:
            if command == "pe.headers.runtime":
                raise XdbgRpcError("method_not_found", "no native headers")
            return FakeInspectWorker.request(worker, command, params, timeout=timeout)

        worker.request = _no_headers  # type: ignore[method-assign]
        result = service.pe_headers_runtime(sid, 0x140000000, save_artifact=False)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["source"] == "memory.read_fallback"
        assert "header_artifact" not in result.data
    finally:
        service.close_all()


def test_pe_headers_runtime_native_success_without_a_file(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, worker = env

    def _no_file(
        command: str, params: JsonObject | None = None, *, timeout: float = 120.0
    ) -> JsonObject:
        if command == "pe.headers.runtime":
            return {"base": (params or {})["base"], "module_size": worker.module_size}
        return FakeInspectWorker.request(worker, command, params, timeout=timeout)

    worker.request = _no_file  # type: ignore[method-assign]
    result = service.pe_headers_runtime(sid, 0x140000000)
    assert result.ok, result.error
    assert result.data is not None
    assert "header_artifact" not in result.data


def test_pe_headers_runtime_falls_back_to_a_bad_memory_image(tmp_path: Path) -> None:
    worker = FakeInspectWorker(module_name="fixture.exe")
    service, sid = _launch(tmp_path, worker)
    try:
        # Drop the native header capability so pe.headers.runtime falls back to
        # memory.read + the Python parser; a non-PE image reads as invalid.
        worker.memory_read_hex = "90" * 0x1000

        def _no_headers(
            command: str, params: JsonObject | None = None, *, timeout: float = 120.0
        ) -> JsonObject:
            if command == "pe.headers.runtime":
                raise XdbgRpcError("capability_unavailable", "no native headers")
            return FakeInspectWorker.request(worker, command, params, timeout=timeout)

        worker.request = _no_headers  # type: ignore[method-assign]
        result = service.pe_headers_runtime(sid, 0x140000000)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_pe"
    finally:
        service.close_all()


def test_pe_headers_runtime_fallback_parses_a_real_image(tmp_path: Path) -> None:
    worker = FakeInspectWorker()
    service, sid = _launch(tmp_path, worker)
    try:
        pe_bytes = bytearray(0x1000)
        source = Path(tmp_path / "img.bin")
        _write_minimal_pe(source)
        raw = source.read_bytes()
        pe_bytes[: len(raw)] = raw
        worker.memory_read_hex = bytes(pe_bytes).hex()

        def _no_headers(
            command: str, params: JsonObject | None = None, *, timeout: float = 120.0
        ) -> JsonObject:
            if command == "pe.headers.runtime":
                raise XdbgRpcError("method_not_found", "no native headers")
            return FakeInspectWorker.request(worker, command, params, timeout=timeout)

        worker.request = _no_headers  # type: ignore[method-assign]
        result = service.pe_headers_runtime(sid, 0x140000000)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["source"] == "memory.read_fallback"
        assert result.data["header_artifact"]
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# imports.scan / module_catalog / module_resolve
# --------------------------------------------------------------------------


def test_imports_scan_reaches_the_backend(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, _ = env
    result = service.imports_scan(sid, 0x140000000, search_start=0x140002000, search_size=0x1000)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["candidate_count"] == 1


def test_imports_scan_refuses_a_stale_snapshot(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, _ = env
    runtime = service._runtime_owner.get(sid, BackendKind.X64DBG)
    assert runtime is not None
    runtime.snapshot_resync_required = True
    result = service.imports_scan(sid, 0x140000000)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "event_gap_resync_required"


def test_module_catalog_reports_the_current_snapshot(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, _ = env
    result = service.module_catalog(sid)
    assert result.ok, result.error
    assert result.data is not None


def test_module_catalog_refuses_without_modules_list(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, worker = env
    worker._drop_caps = frozenset({"modules.list"})
    result = service.module_catalog(sid)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_module_catalog_surfaces_an_unexpected_worker_error(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, worker = env

    def _boom(
        command: str, params: JsonObject | None = None, *, timeout: float = 120.0
    ) -> JsonObject:
        if command == "modules.list":
            raise RuntimeError("modules.list blew up")
        return FakeInspectWorker.request(worker, command, params, timeout=timeout)

    worker.request = _boom  # type: ignore[method-assign]
    result = service.module_catalog(sid)
    assert result.ok is False
    assert result.error is not None


def test_module_resolve_dispatches_to_the_explicit_operation(
    env: tuple[AnalysisService, str, FakeInspectWorker],
) -> None:
    service, sid, _ = env
    # module_resolve is a one-line delegation to _explicit_module_operation; the
    # backing file is absent in this fake, so it resolves to a typed refusal
    # rather than an unhandled error.
    result = service.module_resolve(sid, ModuleSelector(base=0x140000000))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "module_file_unavailable"
