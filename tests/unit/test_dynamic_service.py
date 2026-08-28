from __future__ import annotations

import os
from collections import deque
from pathlib import Path
from typing import cast

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.events import DebugEvent, DebugEventBatch
from headless_re_mcp.core.models import (
    BackendKind,
    ModuleSelector,
    Result,
    Session,
    SessionState,
)
from headless_re_mcp.core.service import (
    AnalysisService,
    DynamicWorker,
    JsonObject,
    StaticWorker,
)


def _write_minimal_pe(
    path: Path,
    machine: int = 0x8664,
    *,
    preferred_base: int | None = None,
    image_size: int = 0x4000,
) -> None:
    is_x86 = machine == 0x014C
    optional_size = 0xE0 if is_x86 else 0xF0
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    image[0x94:0x96] = optional_size.to_bytes(2, "little")
    optional = 0x98
    image[optional : optional + 2] = (0x10B if is_x86 else 0x20B).to_bytes(
        2,
        "little",
    )
    resolved_base = preferred_base
    if resolved_base is None:
        resolved_base = 0x400000 if is_x86 else 0x140000000
    base_offset = optional + (28 if is_x86 else 24)
    base_size = 4 if is_x86 else 8
    image[base_offset : base_offset + base_size] = resolved_base.to_bytes(
        base_size,
        "little",
    )
    image[optional + 56 : optional + 60] = image_size.to_bytes(4, "little")
    path.write_bytes(image)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        # Unit fakes queue scripted batches; background drain would race them.
        debug_event_background_drain=False,
    )


def _state(name: str) -> JsonObject:
    debugging = name != "idle"
    return {
        "debugging": debugging,
        "running": name == "running",
        "state": name,
        "process_id": 7100 if debugging else 0,
        "thread_id": 7200 if debugging else 0,
    }


def _event_batch(
    cursor: int,
    sequences: tuple[int, ...] = (),
    *,
    latest: int | None = None,
    capacity: int = 1024,
) -> DebugEventBatch:
    resolved_latest = latest if latest is not None else (sequences[-1] if sequences else cursor)
    oldest = max(1, resolved_latest - capacity + 1) if resolved_latest else 0
    dropped = max(0, oldest - cursor - 1) if oldest else 0
    events = tuple(
        DebugEvent(
            sequence=sequence,
            timestamp_unix_ms=1_700_000_000_000 + sequence,
            source="x64dbg.plugin_callback",
            kind="debug.paused",
            data={},
        )
        for sequence in sequences
    )
    next_cursor = events[-1].sequence if events else cursor + dropped
    return DebugEventBatch(
        events=events,
        cursor=cursor,
        next_cursor=next_cursor,
        oldest_sequence=oldest,
        latest_sequence=resolved_latest,
        dropped=dropped,
        dropped_total=max(0, resolved_latest - capacity),
        has_more=next_cursor < resolved_latest,
        capacity=capacity,
    )


def _debug_batch(
    cursor: int,
    *events: DebugEvent,
    dropped: int = 0,
) -> DebugEventBatch:
    next_cursor = events[-1].sequence if events else cursor + dropped
    latest = max(cursor, next_cursor)
    return DebugEventBatch(
        events=events,
        cursor=cursor,
        next_cursor=next_cursor,
        oldest_sequence=(1 if latest else 0),
        latest_sequence=latest,
        dropped=dropped,
        dropped_total=dropped,
        has_more=False,
        capacity=1024,
    )


def _debug_event(
    sequence: int,
    kind: str,
    data: JsonObject | None = None,
) -> DebugEvent:
    return DebugEvent(
        sequence=sequence,
        timestamp_unix_ms=1_700_000_000_000 + sequence,
        source="x64dbg.plugin_callback",
        kind=kind,
        data=data or {},
    )


class FakeDynamicWorker:
    def __init__(
        self,
        failure: XdbgRpcError | None = None,
        *,
        architecture: str = "x64",
        module_name: str = "fixture.exe",
        module_path: str | None = None,
        module_base: int = 0x140000000,
        module_size: int = 0x4000,
        event_batches: list[DebugEventBatch] | None = None,
    ) -> None:
        self.failure = failure
        self.breakpoint_removal_error: XdbgRpcError | None = None
        self.breakpoint_addresses: set[int] = set()
        self.architecture = architecture
        self.module_name = module_name
        self.module_path = module_path or module_name
        self.module_base = module_base
        self.module_size = module_size
        self.current_state = _state("idle")
        self.closed = False
        self.terminated = False
        self.requests: list[tuple[str, JsonObject]] = []
        self.waits: list[
            tuple[set[str], float, int | None, frozenset[str]]
        ] = []
        self.event_batches = deque(event_batches or [])
        self.event_reads: list[tuple[int, int, float]] = []

    @property
    def pid(self) -> int:
        return 7000

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(
            {
                "debug.state",
                "debug.launch",
                "debug.attach",
                "debug.stop",
                "debug.pause",
                "debug.resume",
                "debug.step_into",
                "debug.step_over",
                "registers.read",
                "registers.write",
                "memory.read",
                "memory.write",
                "memory.regions",
                "memory.protect.query",
                "modules.list",
                "modules.dump",
                "pe.headers.runtime",
                "imports.scan",
                "imports.read",
                "breakpoints.list",
                "breakpoints.set",
                "breakpoints.remove",
                "events.read",
            }
        )

    @property
    def metadata(self) -> JsonObject:
        return {
            "architecture": self.architecture,
            "server": "fake-x64dbg",
            "capabilities": sorted(self.capabilities),
        }

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        del timeout
        values = params or {}
        self.requests.append((command, values))
        if self.failure is not None:
            raise self.failure
        if command in {"debug.launch", "debug.attach", "debug.resume"}:
            self.current_state = _state("running")
            return dict(self.current_state)
        if command in {"debug.pause", "debug.step_into", "debug.step_over"}:
            self.current_state = _state("running")
            return dict(self.current_state)
        if command == "debug.stop":
            self.current_state = _state("idle")
            return dict(self.current_state)
        if command == "debug.state":
            return dict(self.current_state)
        if command == "registers.read":
            return {"registers": {"rip": 0x140001000, "rsp": 0x120000}}
        if command == "registers.write":
            return {"name": values["name"], "value": values["value"]}
        if command == "memory.read":
            return {
                "address": values["address"],
                "size": values["size"],
                "encoding": "hex",
                "data": "90" * int(values["size"]),
            }
        if command == "memory.write":
            return {
                "address": values["address"],
                "size": len(str(values["data"])) // 2,
            }
        if command == "memory.regions":
            offset = int(values.get("offset", 0))
            limit = int(values.get("limit", 100))
            region = {
                "base": self.module_base,
                "allocation_base": self.module_base,
                "size": self.module_size,
                "protect": 0x20,
                "protect_name": "execute_read",
                "allocation_protect": 0x40,
                "allocation_protect_name": "execute_readwrite",
                "state": "commit",
                "type": "image",
                "info": self.module_name,
            }
            page = [] if offset > 0 else [region]
            page = page[:limit]
            return {
                "regions": page,
                "count": len(page),
                "total": 1,
                "offset": offset,
                "limit": limit,
                "has_more": False,
            }
        if command == "memory.protect.query":
            return {
                "address": values["address"],
                "base": self.module_base,
                "allocation_base": self.module_base,
                "size": self.module_size,
                "protect": 0x20,
                "protect_name": "execute_read",
                "allocation_protect": 0x40,
                "allocation_protect_name": "execute_readwrite",
                "state": "commit",
                "type": "image",
                "info": self.module_name,
            }
        if command == "modules.list":
            offset = int(values.get("offset", 0))
            limit = int(values.get("limit", 256))
            modules = [
                {
                    "base": self.module_base,
                    "size": self.module_size,
                    "name": self.module_name,
                    "path": self.module_path,
                }
            ]
            page = modules[offset : offset + limit]
            return {
                "modules": page,
                "count": len(page),
                "total": len(modules),
                "offset": offset,
                "limit": limit,
                "has_more": offset + len(page) < len(modules),
            }
        if command == "modules.dump":
            output_path = Path(str(values["output_path"]))
            dump_size = int(values.get("size", self.module_size))
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(b"\x90" * dump_size)
            return {
                "base": values["base"],
                "size": dump_size,
                "bytes_written": dump_size,
                "output_path": str(output_path),
                "name": self.module_name,
                "path": self.module_path,
                "max_dump_bytes": 64 * 1024 * 1024,
            }
        if command == "pe.headers.runtime":
            payload = {
                "base": values["base"],
                "module_size": self.module_size,
                "name": self.module_name,
                "path": self.module_path,
                "architecture": self.architecture,
                "entry_point_rva": 0x1000,
                "image_base": self.module_base,
                "image_size": self.module_size,
                "section_count": 1,
                "sections": [
                    {
                        "index": 0,
                        "name": ".text",
                        "virtual_size": 0x1000,
                        "virtual_address": 0x1000,
                        "raw_size": 0x200,
                        "raw_offset": 0x200,
                        "characteristics": 0x60000020,
                    }
                ],
                "directories": [],
            }
            if "output_path" in values:
                header_path = Path(str(values["output_path"]))
                header_path.parent.mkdir(parents=True, exist_ok=True)
                header_path.write_bytes(b"MZ" + b"\0" * 62)
                payload["header_artifact"] = str(header_path)
            return payload
        if command == "imports.scan":
            return {
                "module_base": values["module_base"],
                "module_size": self.module_size,
                "candidates": [
                    {
                        "iat_va": self.module_base + 0x2000,
                        "iat_rva": 0x2000,
                        "size": 0x40,
                        "matched_count": 8,
                        "slot_count": 8,
                        "kind": "consecutive",
                        "confidence": 1.0,
                        "sample_apis": [
                            {"module": "kernel32.dll", "name": "VirtualAlloc"},
                            {"module": "kernel32.dll", "name": "VirtualProtect"},
                        ],
                    }
                ],
                "candidate_count": 1,
                "blind_selection": False,
            }
        if command == "imports.read":
            iat_va = int(values["iat_va"])
            names = [
                "VirtualAlloc",
                "VirtualProtect",
                "VirtualFree",
                "GetProcAddress",
                "LoadLibraryA",
                "GetModuleHandleA",
                "CreateFileA",
                "CloseHandle",
            ]
            entries = [
                {
                    "thunk_va": iat_va + index * 8,
                    "value": 0x7FF00000 + index * 0x10,
                    "kind": "api",
                    "module": "kernel32.dll",
                    "name": name,
                    "ordinal": 0,
                }
                for index, name in enumerate(names)
            ]
            return {
                "iat_va": iat_va,
                "size": values["size"],
                "resolved_count": len(entries),
                "entries": entries,
            }
        if command == "breakpoints.list":
            return {
                "breakpoints": [
                    {
                        "type": "software",
                        "address": address,
                        "enabled": True,
                        "active": True,
                        "single_shot": False,
                        "hit_count": 0,
                        "name": "",
                        "module": self.module_name,
                    }
                    for address in sorted(self.breakpoint_addresses)
                ],
                "count": len(self.breakpoint_addresses),
            }
        if command == "breakpoints.set":
            address = int(values["address"])
            self.breakpoint_addresses.add(address)
            return {"address": address, "set": True}
        if command == "breakpoints.remove":
            if self.breakpoint_removal_error is not None:
                raise self.breakpoint_removal_error
            address = int(values["address"])
            self.breakpoint_addresses.discard(address)
            return {"address": address, "set": False}
        raise AssertionError(f"unexpected command: {command}")

    def read_events(
        self,
        cursor: int,
        *,
        limit: int = 100,
        timeout: float = 10.0,
    ) -> DebugEventBatch:
        self.event_reads.append((cursor, limit, timeout))
        if self.failure is not None:
            raise self.failure
        if self.event_batches:
            batch = self.event_batches.popleft()
            assert batch.cursor == cursor
            assert len(batch.events) <= limit
            return batch
        return DebugEventBatch(
            events=(),
            cursor=cursor,
            next_cursor=cursor,
            oldest_sequence=1 if cursor else 0,
            latest_sequence=cursor,
            dropped=0,
            dropped_total=0,
            has_more=False,
            capacity=1024,
        )

    def wait_for_state(
        self,
        states: set[str],
        *,
        timeout: float = 30.0,
        after_event_sequence: int | None = None,
        transition_event_kinds: frozenset[str] = frozenset(),
    ) -> JsonObject:
        self.waits.append(
            (states, timeout, after_event_sequence, transition_event_kinds)
        )
        if "paused" in states:
            self.current_state = _state("paused")
        elif "idle" in states:
            self.current_state = _state("idle")
        elif "running" in states:
            self.current_state = _state("running")
        return dict(self.current_state)

    def close(self, *, timeout: float = 15.0) -> None:
        del timeout
        self.closed = True

    def terminate(self) -> None:
        self.terminated = True


class FakeStaticWorker:
    closed = False
    terminated = False

    @property
    def pid(self) -> int:
        return 7300

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"static.functions"})

    @property
    def metadata(self) -> JsonObject:
        return {
            "image_base": 0x140000000,
            "capabilities": sorted(self.capabilities),
        }

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        del command, params, timeout
        return {"items": [], "total": 0}

    def close(self, *, timeout: float = 15.0) -> None:
        del timeout
        self.closed = True

    def terminate(self) -> None:
        self.terminated = True


def _service(
    tmp_path: Path,
    dynamic: FakeDynamicWorker,
    static: FakeStaticWorker | None = None,
) -> AnalysisService:
    def dynamic_factory(session: Session, settings: Settings) -> DynamicWorker:
        del session, settings
        return dynamic

    def static_factory(session: Session, settings: Settings) -> StaticWorker:
        del session, settings
        assert static is not None
        return static

    return AnalysisService(
        _settings(tmp_path),
        dynamic_worker_factory=dynamic_factory,
        static_worker_factory=static_factory if static is not None else None,
    )


def _service_with_dynamic_workers(
    tmp_path: Path,
    workers: list[FakeDynamicWorker],
) -> AnalysisService:
    remaining = deque(workers)

    def dynamic_factory(session: Session, settings: Settings) -> DynamicWorker:
        del session, settings
        return remaining.popleft()

    return AnalysisService(
        _settings(tmp_path),
        dynamic_worker_factory=dynamic_factory,
    )


def _create(service: AnalysisService, binary: Path) -> str:
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    session = created.data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _workflow(service: AnalysisService, session_id: str) -> JsonObject:
    result = service.workflow_status(session_id)
    assert result.ok and result.data is not None
    workflow = result.data["workflow"]
    assert isinstance(workflow, dict)
    return workflow


def _workflow_state(workflow: JsonObject) -> JsonObject:
    state = workflow["state"]
    assert isinstance(state, dict)
    return state


def test_dynamic_session_state_machine(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)

    opened = service.open_dynamic(session_id)
    assert opened.ok
    assert service.registry.get(session_id).state == SessionState.READY
    assert BackendKind.X64DBG in service.registry.get(session_id).backends

    launched = service.dynamic_launch(session_id, arguments="--fixture")
    assert launched.ok and launched.data is not None
    assert launched.data["state"]["state"] == "paused"
    assert worker.requests[-1][1]["path"] == str(binary.resolve())
    assert service.registry.get(session_id).state == SessionState.SUSPENDED

    registers = service.dynamic_registers_read(session_id)
    memory = service.dynamic_memory_read(session_id, 0x140001000, 4)
    modules = service.dynamic_modules(session_id)
    assert registers.ok and registers.data is not None
    assert registers.data["registers"]["rip"] == 0x140001000
    assert memory.ok and memory.data is not None
    assert memory.data["data"] == "90909090"
    assert modules.ok and modules.data is not None
    assert modules.data["count"] == 1
    assert worker.requests[-1] == ("modules.list", {"offset": 0, "limit": 256})
    empty_page = service.dynamic_modules(session_id, offset=1, limit=1)
    assert empty_page.ok and empty_page.data is not None
    assert empty_page.data["modules"] == []
    assert empty_page.data["total"] == 1
    assert empty_page.data["has_more"] is False

    resumed = service.dynamic_resume(session_id)
    assert resumed.ok
    assert service.registry.get(session_id).state == SessionState.RUNNING
    paused = service.dynamic_pause(session_id)
    assert paused.ok
    assert service.registry.get(session_id).state == SessionState.SUSPENDED
    stepped = service.dynamic_step_into(session_id)
    assert stepped.ok
    assert service.registry.get(session_id).state == SessionState.SUSPENDED
    stopped = service.dynamic_stop(session_id)
    assert stopped.ok
    assert service.registry.get(session_id).state == SessionState.READY

    closed = service.close_session(session_id)
    assert closed.ok
    assert worker.closed
    assert service.registry.get(session_id).state == SessionState.CLOSED


def test_static_and_dynamic_backends_can_coexist(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    dynamic = FakeDynamicWorker()
    static = FakeStaticWorker()
    service = _service(tmp_path, dynamic, static)
    session_id = _create(service, binary)

    assert service.open_dynamic(session_id).ok
    assert service.open_static(session_id).ok
    session = service.registry.get(session_id)
    assert set(session.backends) == {BackendKind.IDA, BackendKind.X64DBG}
    assert service.static_functions(session_id).ok
    assert service.dynamic_state(session_id).ok

    static_to_runtime = service.sync_static_to_runtime(session_id, 0x140001234)
    assert static_to_runtime.ok and static_to_runtime.data is not None
    assert static_to_runtime.data["rva"] == 0x1234
    assert static_to_runtime.data["runtime"]["address"] == 0x140001234
    runtime_to_static = service.sync_runtime_to_static(session_id, 0x140001234)
    assert runtime_to_static.ok and runtime_to_static.data is not None
    assert runtime_to_static.data["static"]["address"] == 0x140001234

    assert service.close_session(session_id).ok
    assert static.closed
    assert dynamic.closed


def test_sync_requires_both_backends(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())
    session_id = _create(service, binary)

    assert service.open_static(session_id).ok
    result = service.sync_static_to_runtime(session_id, 0x140001000)

    assert not result.ok and result.error is not None
    assert result.error.code == "backend_unavailable"
    assert result.error.details["backend"] == BackendKind.X64DBG.value
    assert service.close_session(session_id).ok


def test_sync_reports_missing_runtime_module(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(
        tmp_path,
        FakeDynamicWorker(module_name="other.dll"),
        FakeStaticWorker(),
    )
    session_id = _create(service, binary)

    assert service.open_static(session_id).ok
    assert service.open_dynamic(session_id).ok
    result = service.sync_static_to_runtime(session_id, 0x140001000)

    assert not result.ok and result.error is not None
    assert result.error.code == "module_not_found"
    assert result.error.details["name"] == binary.name
    assert service.close_session(session_id).ok


def test_sync_reports_runtime_architecture_mismatch(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(
        tmp_path,
        FakeDynamicWorker(architecture="x86"),
        FakeStaticWorker(),
    )
    session_id = _create(service, binary)

    assert service.open_static(session_id).ok
    assert service.open_dynamic(session_id).ok
    result = service.sync_static_to_runtime(session_id, 0x140001000)

    assert not result.ok and result.error is not None
    assert result.error.code == "architecture_mismatch"
    assert result.error.details["expected"] == "x64"
    assert result.error.details["actual"] == "x86"
    assert service.close_session(session_id).ok


def test_sync_reports_out_of_range_address(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())
    session_id = _create(service, binary)

    assert service.open_static(session_id).ok
    assert service.open_dynamic(session_id).ok
    result = service.sync_runtime_to_static(session_id, 0x140004000)

    assert not result.ok and result.error is not None
    assert result.error.code == "address_out_of_range"
    assert result.error.details["backend"] == BackendKind.X64DBG.value
    assert service.close_session(session_id).ok


def test_fatal_dynamic_error_marks_session_failed(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker(
        XdbgRpcError("worker_exited", "x64dbg exited with code 1", retryable=False)
    )
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    result = service.dynamic_state(session_id)
    assert not result.ok and result.error is not None
    assert result.error.code == "worker_exited"
    assert worker.terminated
    session = service.registry.get(session_id)
    assert session.state == SessionState.FAILED
    assert BackendKind.X64DBG not in session.backends
    workflow = service.workflow_status(session_id)
    assert workflow.ok and workflow.data is not None
    terminal = workflow.data["workflow"]
    assert isinstance(terminal, dict)
    assert terminal["status"] == "failed"
    assert terminal["failure"]["code"] == "worker_exited"


def test_a_transport_fault_does_not_terminate_the_worker(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker(
        XdbgRpcError("rpc_transport_error", "pipe disconnected", retryable=True)
    )
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    result = service.dynamic_state(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_transport_error"
    # The client only raises this after confirming the worker is alive, so
    # terminating it here would kill the debuggee that the next call reconnects
    # to, and turn a recoverable fault into a lost session.
    assert not worker.terminated
    session = service.registry.get(session_id)
    assert session.state is not SessionState.FAILED
    assert BackendKind.X64DBG in session.backends


def test_dynamic_events_cursor_advances_and_empty_batch_preserves_position(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker(
        event_batches=[
            _event_batch(0, (1, 2)),
            _event_batch(2, latest=2),
        ]
    )
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    first = service.dynamic_events(session_id, limit=7, timeout=2.5)
    empty_after = service.dynamic_events(session_id, limit=7, timeout=2.5)

    assert first.ok and first.data is not None
    assert first.data["next_cursor"] == 2
    assert first.data["durable_log"] is True
    assert [event["sequence"] for event in first.data["events"]] == [1, 2]
    assert empty_after.ok and empty_after.data is not None
    assert empty_after.data["cursor"] == 2
    # Durable path: short drain + optional long-poll against native ring.
    assert worker.event_reads[0] == (0, 256, 0.05)
    assert any(read[0] == 2 for read in worker.event_reads)


def test_dynamic_event_peek_keeps_bounded_workflow_transition_budget(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker(event_batches=[_event_batch(0)])
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    transition_timeouts: list[float] = []

    def consume(*_args: object, timeout: float, **_kwargs: object) -> None:
        transition_timeouts.append(timeout)

    service._consume_workflow_batch_locked = consume  # type: ignore[method-assign]

    result = service.dynamic_events(session_id, limit=16, timeout=0.05)

    assert result.ok
    assert worker.event_reads[0] == (0, 256, 0.05)
    assert transition_timeouts == [5.0]


def test_durable_log_replays_when_consumer_lags_behind_drained_events(
    tmp_path: Path,
) -> None:
    """Drain captures the full native window; a slow consumer still reads by sequence."""
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker(
        event_batches=[_event_batch(0, (1, 2, 3, 4, 5), latest=5)]
    )
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    first = service.dynamic_events(session_id, limit=2)
    second = service.dynamic_events(session_id, limit=10)

    assert first.ok and first.data is not None
    assert [event["sequence"] for event in first.data["events"]] == [1, 2]
    assert second.ok and second.data is not None
    assert [event["sequence"] for event in second.data["events"]] == [3, 4, 5]
    assert second.data["dropped"] == 0
    assert second.data["unrecovered_gap"] is False
    assert second.data["replayed_from_store"] is True
    assert second.data["durable_log"] is True


def test_dynamic_events_reports_overwritten_loss_and_advances_to_available_window(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker(
        event_batches=[
            _event_batch(0, (4, 5), latest=6, capacity=3),
            _event_batch(5, (6,), latest=6, capacity=3),
        ]
    )
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    overwritten = service.dynamic_events(session_id, limit=2)
    remainder = service.dynamic_events(session_id, limit=2)

    assert overwritten.ok and overwritten.data is not None
    assert overwritten.data["dropped"] == 3
    assert overwritten.data["unrecovered_gap"] is True
    assert overwritten.data["next_cursor"] == 5
    assert overwritten.data["has_more"] is True
    assert remainder.ok and remainder.data is not None
    assert remainder.data["cursor"] == 5
    assert remainder.data["next_cursor"] == 6


def test_dynamic_event_cursors_are_isolated_per_session(tmp_path: Path) -> None:
    first_binary = tmp_path / "first.exe"
    second_binary = tmp_path / "second.exe"
    _write_minimal_pe(first_binary)
    _write_minimal_pe(second_binary)
    first_worker = FakeDynamicWorker(
        event_batches=[_event_batch(0, (1,)), _event_batch(1, (2,))]
    )
    second_worker = FakeDynamicWorker(event_batches=[_event_batch(0, (1,))])
    service = _service_with_dynamic_workers(tmp_path, [first_worker, second_worker])
    first_session = _create(service, first_binary)
    second_session = _create(service, second_binary)
    assert service.open_dynamic(first_session).ok
    assert service.open_dynamic(second_session).ok

    assert service.dynamic_events(first_session).ok
    assert service.dynamic_events(second_session).ok
    assert service.dynamic_events(first_session).ok

    assert first_worker.event_reads[0][0] == 0
    assert any(read[0] == 1 for read in first_worker.event_reads)
    assert second_worker.event_reads[0][0] == 0
    assert first_worker is not second_worker


def test_dynamic_events_require_live_backend_and_validate_bounds(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)

    missing = service.dynamic_events(session_id)
    assert not missing.ok and missing.error is not None
    assert missing.error.code == "backend_unavailable"
    assert service.open_dynamic(session_id).ok

    for limit, timeout in ((0, 10.0), (257, 10.0), (True, 10.0), (100, 0.0), (100, float("nan"))):
        invalid = service.dynamic_events(session_id, limit=limit, timeout=timeout)
        assert not invalid.ok and invalid.error is not None
        assert invalid.error.code == "invalid_request"
    assert worker.event_reads == []

    assert service.close_session(session_id).ok
    closed = service.dynamic_events(session_id)
    assert not closed.ok and closed.error is not None
    assert closed.error.code == "invalid_request"


def test_dynamic_events_times_out_acquiring_a_busy_runtime_lock(tmp_path: Path) -> None:
    """A 100 ms event poll queued indefinitely behind another runtime owner."""
    from threading import Event, Thread

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    runtime = service._runtime(session_id, BackendKind.X64DBG)
    lock_held = Event()
    release_lock = Event()

    def hold_runtime_lock() -> None:
        with runtime.lock:
            lock_held.set()
            assert release_lock.wait(2)

    blocker = Thread(target=hold_runtime_lock, daemon=True)
    blocker.start()
    assert lock_held.wait(1)
    outcomes: list[Result[JsonObject]] = []
    poll = Thread(
        target=lambda: outcomes.append(service.dynamic_events(session_id, timeout=0.1)),
        daemon=True,
    )
    poll.start()
    poll.join(timeout=0.4)
    returned_within_bound = not poll.is_alive()
    release_lock.set()
    blocker.join(timeout=2)
    poll.join(timeout=2)

    assert returned_within_bound, "dynamic.events remained blocked acquiring the runtime lock"
    (result,) = outcomes
    assert not result.ok and result.error is not None
    assert result.error.code == "timeout"
    assert result.error.retryable is True


class ClockBurningEventWorker(FakeDynamicWorker):
    """Burns simulated seconds inside each native read so budgets are visible."""

    def __init__(self, clock: dict[str, float]) -> None:
        super().__init__()
        self.clock = clock

    def read_events(
        self,
        cursor: int,
        *,
        limit: int = 100,
        timeout: float = 10.0,
    ) -> DebugEventBatch:
        batch = super().read_events(cursor, limit=limit, timeout=timeout)
        self.clock["now"] += 4.0
        return batch


def test_dynamic_events_long_poll_only_gets_the_remaining_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The native long poll must not re-spend time the poll already used."""
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    clock = {"now": 0.0}
    worker = ClockBurningEventWorker(clock)
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr("headless_re_mcp.core.service.monotonic", lambda: clock["now"])

    polled = service.dynamic_events(session_id, timeout=10.0)

    assert polled.ok, polled.error
    # The 50 ms catch-up drain burns 4 simulated seconds, so the long poll may
    # only wait for the 6 that remain of the 10-second budget, not a fresh 10.
    assert [read[2] for read in worker.event_reads] == [0.05, 6.0]


def test_fatal_event_protocol_error_invalidates_runtime(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker(
        XdbgRpcError("rpc_protocol_error", "malformed event batch")
    )
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    result = service.dynamic_events(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_protocol_error"
    assert worker.terminated
    session = service.registry.get(session_id)
    assert session.state == SessionState.FAILED
    assert BackendKind.X64DBG not in session.backends


def test_explicit_module_catalog_resolve_and_rebase_round_trip(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    module = tmp_path / "event_fixture.dll"
    _write_minimal_pe(binary)
    _write_minimal_pe(
        module,
        preferred_base=0x180000000,
        image_size=0x5000,
    )
    runtime_base = 0x7FF800000000
    worker = FakeDynamicWorker(
        module_name=module.name,
        module_path=str(module),
        module_base=runtime_base,
        module_size=0x5000,
    )
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)

    missing = service.module_catalog(session_id)
    assert not missing.ok and missing.error is not None
    assert missing.error.code == "backend_unavailable"
    assert service.open_dynamic(session_id).ok

    catalog = service.module_catalog(session_id)
    resolved = service.module_resolve(
        session_id,
        ModuleSelector(name="EVENT_FIXTURE.DLL"),
    )
    to_runtime = service.sync_module_preferred_to_runtime(
        session_id,
        ModuleSelector(base=runtime_base),
        0x180001234,
    )
    to_preferred = service.sync_module_runtime_to_preferred(
        session_id,
        ModuleSelector(path=str(module)),
        runtime_base + 0x1234,
    )

    assert catalog.ok and catalog.data is not None
    assert catalog.data == {
        "modules": [
            {
                "base": runtime_base,
                "size": 0x5000,
                "name": module.name,
                "path": str(module),
            }
        ],
        "count": 1,
    }
    assert resolved.ok and resolved.data is not None
    assert resolved.data["module"]["sha256"]
    assert resolved.data["preferred"]["base"] == 0x180000000
    assert resolved.data["runtime"]["base"] == runtime_base
    assert to_runtime.ok and to_runtime.data is not None
    assert to_runtime.data["runtime"]["address"] == runtime_base + 0x1234
    assert to_preferred.ok and to_preferred.data is not None
    assert to_preferred.data["preferred"]["address"] == 0x180001234
    assert [command for command, _ in worker.requests].count("modules.list") == 4

    assert service.close_session(session_id).ok
    closed = service.module_resolve(session_id, ModuleSelector(base=runtime_base))
    assert not closed.ok and closed.error is not None
    assert closed.error.code == "invalid_request"


def test_explicit_module_identity_and_address_errors_are_structured(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    module = tmp_path / "event_fixture.dll"
    _write_minimal_pe(binary)
    _write_minimal_pe(module, preferred_base=0x180000000, image_size=0x5000)
    runtime_base = 0x7FF800000000
    worker = FakeDynamicWorker(
        module_name=module.name,
        module_path=str(module),
        module_base=runtime_base,
        module_size=0x5000,
    )
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    wrong_hash = service.module_resolve(
        session_id,
        ModuleSelector(base=runtime_base, sha256="0" * 64),
    )
    missing = service.module_resolve(
        session_id,
        ModuleSelector(name="missing.dll"),
    )
    out_of_range = service.sync_module_runtime_to_preferred(
        session_id,
        ModuleSelector(base=runtime_base),
        runtime_base + 0x5000,
    )

    assert not wrong_hash.ok and wrong_hash.error is not None
    assert wrong_hash.error.code == "module_identity_mismatch"
    assert not missing.ok and missing.error is not None
    assert missing.error.code == "module_not_found"
    assert not out_of_range.ok and out_of_range.error is not None
    assert out_of_range.error.code == "address_out_of_range"
    assert out_of_range.error.details["coordinate"] == "runtime"
    assert service.close_session(session_id).ok


def test_workflow_runtime_persists_and_resets_at_shared_cursor(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    module = tmp_path / "payload.dll"
    _write_minimal_pe(binary)
    _write_minimal_pe(module, preferred_base=0x180000000, image_size=0x5000)
    worker = FakeDynamicWorker(
        module_name=module.name,
        module_path=str(module),
        module_base=0x7FF800000000,
        module_size=0x5000,
    )
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    initial = _workflow(service, session_id)
    tracked = service.workflow_module_track(
        session_id,
        "payload",
        ModuleSelector(name=module.name),
    )
    breakpoint = service.workflow_breakpoint_put(
        session_id,
        "oep",
        "payload",
        0x1234,
    )

    assert tracked.ok
    assert breakpoint.ok
    persisted = _workflow(service, session_id)
    assert persisted["id"] == initial["id"]
    assert persisted["operation_count"] > initial["operation_count"]
    state = _workflow_state(persisted)
    modules = state["modules"]
    assert isinstance(modules, list) and modules[0]["key"] == "payload"
    breakpoints = state["breakpoints"]
    assert isinstance(breakpoints, dict)
    assert breakpoints["bindings"][0]["address"] == 0x7FF800001234

    removed = service.workflow_breakpoint_remove(session_id, "oep")
    reset = service.workflow_reset(session_id)
    assert removed.ok
    assert reset.ok and reset.data is not None
    reset_workflow = reset.data["workflow"]
    assert isinstance(reset_workflow, dict)
    assert reset_workflow["id"] != initial["id"]
    assert _workflow_state(reset_workflow)["cursor"] == 0
    assert service.close_session(session_id).ok
    assert not service.workflow_status(session_id).ok


def test_workflow_event_consume_rebinds_after_module_reload_in_order(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    module = tmp_path / "payload.dll"
    _write_minimal_pe(binary)
    _write_minimal_pe(module, preferred_base=0x180000000, image_size=0x5000)
    old_base = 0x7FF800000000
    new_base = 0x7FF900000000
    worker = FakeDynamicWorker(
        module_name=module.name,
        module_path=str(module),
        module_base=old_base,
        module_size=0x5000,
    )
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.workflow_module_track(
        session_id,
        "payload",
        ModuleSelector(name=module.name),
    ).ok
    assert service.workflow_breakpoint_put(
        session_id,
        "oep",
        "payload",
        0x1234,
    ).ok

    worker.requests.clear()
    worker.module_base = new_base
    worker.event_batches.append(
        _debug_batch(
            0,
            _debug_event(1, "module.unloaded", {"base": old_base}),
            _debug_event(
                2,
                "module.loaded",
                {"base": new_base, "size": 0x5000, "name": module.name},
            ),
        )
    )
    consumed = service.workflow_events_consume(session_id)

    assert consumed.ok and consumed.data is not None
    assert consumed.data["next_cursor"] == 2
    workflow = _workflow(service, session_id)
    state = _workflow_state(workflow)
    assert state["cursor"] == 2
    breakpoints = state["breakpoints"]
    assert isinstance(breakpoints, dict)
    assert breakpoints["bindings"][0]["address"] == new_base + 0x1234
    relevant = [
        command
        for command, _ in worker.requests
        if command in {"breakpoints.remove", "modules.list", "breakpoints.set"}
    ]
    assert relevant == ["breakpoints.remove", "modules.list", "breakpoints.set"]
    assert worker.event_reads[0] == (0, 256, 0.05)
    assert any(read[0] == 0 for read in worker.event_reads)


def test_workflow_navigation_matches_breakpoint_using_shared_cursor(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    module = tmp_path / "payload.dll"
    _write_minimal_pe(binary)
    _write_minimal_pe(module, preferred_base=0x180000000, image_size=0x5000)
    base = 0x7FF800000000
    worker = FakeDynamicWorker(
        module_name=module.name,
        module_path=str(module),
        module_base=base,
        module_size=0x5000,
    )
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.workflow_module_track(
        session_id,
        "payload",
        ModuleSelector(name=module.name),
    ).ok
    assert service.workflow_breakpoint_put(
        session_id,
        "oep",
        "payload",
        0x1234,
    ).ok

    address = base + 0x1234
    worker.event_batches.append(
        _debug_batch(
            0,
            _debug_event(
                1,
                "breakpoint.hit",
                {"address": address, "type": 0},
            ),
        )
    )
    navigated = service.workflow_navigate_to_breakpoint(
        session_id,
        "oep",
        timeout=2.0,
        event_budget=8,
    )

    assert navigated.ok and navigated.data is not None
    workflow = navigated.data["workflow"]
    assert isinstance(workflow, dict)
    state = _workflow_state(workflow)
    navigation = state["navigation"]
    assert isinstance(navigation, dict)
    assert navigation["status"] == "matched"
    assert navigation["matched_event"]["sequence"] == 1
    assert state["cursor"] == 1
    assert worker.current_state["state"] == "paused"
    assert worker.event_reads[0][0] == 0
    assert any(read[2] == 2.0 or read[1] == 8 for read in worker.event_reads)


def test_workflow_event_loss_fails_closed_and_pauses_target(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker(event_batches=[_debug_batch(0, dropped=4)])
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    navigated = service.workflow_navigate_to_event(
        session_id,
        "breakpoint.hit",
        timeout=2.0,
        event_budget=8,
    )

    assert navigated.ok and navigated.data is not None
    workflow = navigated.data["workflow"]
    assert isinstance(workflow, dict)
    state = _workflow_state(workflow)
    navigation = state["navigation"]
    assert isinstance(navigation, dict)
    assert navigation["status"] == "event_loss"
    assert state["stream_reliable"] is False
    assert state["cursor"] == 4
    assert worker.current_state["state"] == "paused"


def test_workflow_navigation_budget_exhaustion_ensures_paused(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker(
        event_batches=[
            _debug_batch(
                0,
                _debug_event(1, "debug.resumed"),
                _debug_event(2, "thread.created", {"thread_id": 9}),
            )
        ]
    )
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    navigated = service.workflow_navigate_to_event(
        session_id,
        "breakpoint.hit",
        timeout=2.0,
        event_budget=2,
    )

    assert navigated.ok and navigated.data is not None
    workflow = navigated.data["workflow"]
    assert isinstance(workflow, dict)
    state = _workflow_state(workflow)
    navigation = state["navigation"]
    assert isinstance(navigation, dict)
    assert navigation["status"] == "budget_exhausted"
    assert navigation.get("matched_event") is None
    assert worker.current_state["state"] == "paused"
    assert "debug.pause" in {command for command, _ in worker.requests} or any(
        "paused" in wait[0] for wait in worker.waits
    )


def test_workflow_cancel_stops_in_flight_navigation(tmp_path: Path) -> None:
    from threading import Event, Thread
    from time import monotonic

    entered = Event()
    release = Event()

    class BlockingWorker(FakeDynamicWorker):
        def read_events(
            self,
            cursor: int,
            *,
            limit: int = 100,
            timeout: float = 10.0,
        ) -> DebugEventBatch:
            self.event_reads.append((cursor, limit, timeout))
            entered.set()
            assert release.wait(10)
            return DebugEventBatch(
                events=(),
                cursor=cursor,
                next_cursor=cursor,
                oldest_sequence=1 if cursor else 0,
                latest_sequence=cursor,
                dropped=0,
                dropped_total=0,
                has_more=False,
                capacity=1024,
            )

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = BlockingWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    outcome: dict[str, object] = {}

    def navigate() -> None:
        outcome["nav"] = service.workflow_navigate_to_event(
            session_id,
            "breakpoint.hit",
            timeout=8.0,
            event_budget=8,
        )

    # Daemon: if navigate wedges, the join assert below names the failure, and
    # a daemon thread cannot then hold interpreter shutdown hostage after the
    # suite ends -- no watchdog covers the post-suite join of non-daemon
    # threads (pytest-timeout and faulthandler are both per-test).
    thread = Thread(target=navigate, daemon=True)
    thread.start()
    assert entered.wait(5)
    started = monotonic()
    cancelled = service.workflow_cancel(session_id, timeout=3.0)
    elapsed = monotonic() - started
    assert cancelled.ok, cancelled.error
    assert elapsed < 2.0
    release.set()
    thread.join(5)
    assert not thread.is_alive()
    navigated = outcome["nav"]
    assert isinstance(navigated, Result)
    assert navigated.ok
    assert cancelled.data is not None
    workflow = cancelled.data["workflow"]
    assert isinstance(workflow, dict)
    assert workflow.get("status") == "cancelled" or _workflow_state(workflow).get(
        "navigation", {}
    ).get("status") in {"cancelled", "canceled"}


def test_workflow_acknowledges_breakpoint_already_removed_by_debugger(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    module = tmp_path / "payload.dll"
    _write_minimal_pe(binary)
    _write_minimal_pe(module, preferred_base=0x180000000, image_size=0x5000)
    base = 0x7FF800000000
    worker = FakeDynamicWorker(
        module_name=module.name,
        module_path=str(module),
        module_base=base,
        module_size=0x5000,
    )
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.workflow_module_track(
        session_id,
        "payload",
        ModuleSelector(name=module.name),
    ).ok
    assert service.workflow_breakpoint_put(
        session_id,
        "oep",
        "payload",
        0x1234,
    ).ok

    address = base + 0x1234
    assert worker.breakpoint_addresses == {address}
    worker.breakpoint_addresses.clear()
    worker.breakpoint_removal_error = XdbgRpcError(
        "debugger_command_failed",
        "breakpoint is already absent",
    )
    disabled = service.workflow_breakpoint_disable(session_id, "oep")

    assert disabled.ok and disabled.data is not None
    workflow = disabled.data["workflow"]
    assert isinstance(workflow, dict)
    assert workflow["status"] == "idle"
    breakpoints = _workflow_state(workflow)["breakpoints"]
    assert isinstance(breakpoints, dict)
    assert breakpoints["intents"][0]["enabled"] is False
    assert breakpoints["bindings"] == []
    relevant = [
        command
        for command, _ in worker.requests
        if command in {"breakpoints.remove", "breakpoints.list"}
    ]
    assert relevant[-2:] == ["breakpoints.remove", "breakpoints.list"]


def test_workflow_failure_does_not_acknowledge_failed_breakpoint_removal(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    module = tmp_path / "payload.dll"
    _write_minimal_pe(binary)
    _write_minimal_pe(module, preferred_base=0x180000000, image_size=0x5000)
    base = 0x7FF800000000
    worker = FakeDynamicWorker(
        module_name=module.name,
        module_path=str(module),
        module_base=base,
        module_size=0x5000,
    )
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.workflow_module_track(
        session_id,
        "payload",
        ModuleSelector(name=module.name),
    ).ok
    assert service.workflow_breakpoint_put(
        session_id,
        "oep",
        "payload",
        0x1234,
    ).ok

    worker.breakpoint_removal_error = XdbgRpcError(
        "debugger_command_failed",
        "remove failed",
        retryable=True,
    )
    failed = service.workflow_breakpoint_disable(session_id, "oep")

    assert not failed.ok and failed.error is not None
    assert failed.error.code == "debugger_command_failed"
    workflow = _workflow(service, session_id)
    assert workflow["status"] == "failed"
    assert workflow["failure"]["retryable"] is True
    state = _workflow_state(workflow)
    breakpoints = state["breakpoints"]
    assert isinstance(breakpoints, dict)
    assert breakpoints["intents"][0]["enabled"] is False
    assert breakpoints["bindings"][0]["address"] == base + 0x1234
    rejected = service.workflow_breakpoint_put(
        session_id,
        "other",
        "payload",
        0x40,
    )
    assert not rejected.ok and rejected.error is not None
    assert rejected.error.code == "invalid_request"


def test_memory_regions_and_modules_dump_service_wrappers(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    regions = service.memory_regions(session_id, offset=0, limit=8)
    assert regions.ok and regions.data is not None
    assert regions.data["count"] == 1
    assert worker.requests[-1][0] == "memory.regions"

    protect = service.memory_protect_query(session_id, worker.module_base + 0x10)
    assert protect.ok and protect.data is not None
    assert protect.data["protect_name"] == "execute_read"

    dumped = service.modules_dump(session_id, worker.module_base, size=0x100)
    assert dumped.ok and dumped.data is not None
    output = Path(str(dumped.data["output_path"]))
    assert output.is_file()
    assert output.stat().st_size == 0x100
    assert dumped.data["sha256"]
    assert dumped.data["artifact_kind"] == "module_dump"
    assert "dump" in output.parts
    assert session_id in output.parts
    dump_requests = [req for req in worker.requests if req[0] == "modules.dump"]
    assert dump_requests
    assert dump_requests[-1][1]["output_path"] == str(output)
    # Success path may refresh modules.list for unload-race checks after dump.
    assert worker.requests[-1][0] in {"modules.dump", "modules.list"}

    too_large = service.modules_dump(
        session_id,
        worker.module_base,
        size=65 * 1024 * 1024,
    )
    assert not too_large.ok and too_large.error is not None
    assert too_large.error.code == "dump_too_large"


def test_modules_dump_rejects_a_worker_redirecting_the_artifact_path(tmp_path: Path) -> None:
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"keep")

    class RedirectingWorker(FakeDynamicWorker):
        def request(
            self,
            command: str,
            params: JsonObject | None = None,
            *,
            timeout: float = 120.0,
        ) -> JsonObject:
            if command == "modules.dump":
                values = params or {}
                self.requests.append((command, values))
                requested = Path(str(values["output_path"]))
                requested.write_bytes(b"requested")
                return {"output_path": str(outside)}
            return super().request(command, params, timeout=timeout)

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = RedirectingWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    dumped = service.modules_dump(session_id, worker.module_base, size=0x100)

    assert not dumped.ok and dumped.error is not None
    assert dumped.error.code == "rpc_protocol_error"
    assert outside.read_bytes() == b"keep"
    assert list((tmp_path / "artifacts" / "dump" / session_id).glob("*.bin")) == []
    assert service.repository.list_artifacts(session_id)["total"] == 0


def test_modules_dump_deletes_an_artifact_larger_than_requested(tmp_path: Path) -> None:
    class OversizedWorker(FakeDynamicWorker):
        def request(
            self,
            command: str,
            params: JsonObject | None = None,
            *,
            timeout: float = 120.0,
        ) -> JsonObject:
            if command == "modules.dump":
                values = params or {}
                self.requests.append((command, values))
                requested = Path(str(values["output_path"]))
                requested.write_bytes(b"x" * 0x101)
                return {"output_path": str(requested)}
            return super().request(command, params, timeout=timeout)

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = OversizedWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    dumped = service.modules_dump(session_id, worker.module_base, size=0x100)

    assert not dumped.ok and dumped.error is not None
    assert dumped.error.code == "dump_too_large"
    assert list((tmp_path / "artifacts" / "dump" / session_id).glob("*.bin")) == []
    assert service.repository.list_artifacts(session_id)["total"] == 0


def test_dynamic_state_exposes_debuggee_and_debugger_pids(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    idle = service.dynamic_state(session_id)
    assert idle.ok and idle.data is not None
    assert idle.data["state"] == "idle"
    assert idle.data["process_id"] == 0
    assert idle.data["debuggee_pid"] is None
    assert idle.data["debugger_pid"] == worker.pid
    assert "debuggee_pid is the target process" in str(idle.data["pid_note"])

    assert service.dynamic_launch(session_id).ok
    active = service.dynamic_state(session_id)
    assert active.ok and active.data is not None
    assert active.data["debuggee_pid"] == 7100
    assert active.data["debugger_pid"] == 7000
    assert active.data["debuggee_pid"] != active.data["debugger_pid"]
    session = service.registry.get(session_id)
    assert session.metadata.get("debuggee_pid") == 7100
    assert session.metadata.get("debugger_pid") == 7000


@pytest.mark.skipif(os.name != "nt", reason="Win32 UI automation requires Windows")
def test_ui_windows_list_pid_boundary(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    idle = service.ui_windows_list(session_id)
    assert not idle.ok and idle.error is not None
    assert idle.error.code == "invalid_state"

    assert service.dynamic_launch(session_id).ok
    listed = service.ui_windows_list(session_id)
    assert listed.ok and listed.data is not None
    assert listed.data["debuggee_pid"] == 7100
    assert listed.data["debugger_pid"] == 7000
    assert listed.data["allowed_pids"] == [7100]
    assert 7000 in listed.data["blocked_pids"]
    for window in listed.data["windows"]:
        assert window["pid"] == 7100

    blocked_child = service.ui_windows_list(
        session_id,
        allow_child_pids=[worker.pid],
    )
    assert not blocked_child.ok and blocked_child.error is not None
    assert blocked_child.error.code == "permission_denied"


class _NoNativePeHeadersWorker(FakeDynamicWorker):
    """Force pe.headers.runtime fallback through memory.read + atomic write."""

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(c for c in super().capabilities if c != "pe.headers.runtime")

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        values = params or {}
        if command == "memory.read":
            self.requests.append((command, values))
            if self.failure is not None:
                raise self.failure
            pe = bytearray(0x1000)
            _write_minimal_pe_into(pe)
            size = int(values["size"])
            return {
                "address": values["address"],
                "size": size,
                "encoding": "hex",
                "data": bytes(pe[:size]).hex(),
            }
        return super().request(command, params, timeout=timeout)


def _write_minimal_pe_into(image: bytearray) -> None:
    path_bytes = bytearray(0x200)
    # Reuse the same layout as _write_minimal_pe without touching disk.
    machine = 0x8664
    optional_size = 0xF0
    path_bytes[:2] = b"MZ"
    path_bytes[0x3C:0x40] = (0x80).to_bytes(4, "little")
    path_bytes[0x80:0x84] = b"PE\0\0"
    path_bytes[0x84:0x86] = machine.to_bytes(2, "little")
    path_bytes[0x94:0x96] = optional_size.to_bytes(2, "little")
    optional = 0x98
    path_bytes[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    path_bytes[optional + 16 : optional + 20] = (0x1000).to_bytes(4, "little")
    path_bytes[optional + 24 : optional + 32] = (0x140000000).to_bytes(8, "little")
    path_bytes[optional + 32 : optional + 36] = (0x1000).to_bytes(4, "little")
    path_bytes[optional + 36 : optional + 40] = (0x200).to_bytes(4, "little")
    path_bytes[optional + 56 : optional + 60] = (0x2000).to_bytes(4, "little")
    path_bytes[optional + 60 : optional + 64] = (0x200).to_bytes(4, "little")
    path_bytes[optional + 68 : optional + 70] = (3).to_bytes(2, "little")
    path_bytes[optional + 108 : optional + 112] = (16).to_bytes(4, "little")
    section = optional + optional_size
    path_bytes[section : section + 8] = b".text\0\0\0"
    path_bytes[section + 8 : section + 12] = (0x100).to_bytes(4, "little")
    path_bytes[section + 12 : section + 16] = (0x1000).to_bytes(4, "little")
    path_bytes[section + 16 : section + 20] = (0x200).to_bytes(4, "little")
    path_bytes[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    path_bytes[section + 36 : section + 40] = (0x60000020).to_bytes(4, "little")
    image[: len(path_bytes)] = path_bytes


def test_pe_headers_memory_fallback_uses_atomic_write(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = _NoNativePeHeadersWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.dynamic_launch(session_id).ok

    headers = service.pe_headers_runtime(session_id, worker.module_base, save_artifact=True)
    assert headers.ok and headers.data is not None
    assert headers.data.get("source") == "memory.read_fallback"
    artifact = Path(str(headers.data["header_artifact"]))
    assert artifact.is_file()
    assert artifact.read_bytes()[:2] == b"MZ"
    assert not list(artifact.parent.glob("*.tmp"))
    assert not list(artifact.parent.glob("*.partial"))


def _rebased_service(
    tmp_path: Path, runtime_base: int
) -> tuple[AnalysisService, str, FakeDynamicWorker]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    dynamic = FakeDynamicWorker(module_base=runtime_base)
    service = _service(tmp_path, dynamic, FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.open_static(session_id).ok
    return service, session_id, dynamic


def test_resolve_runtime_address_rebases_every_coordinate(tmp_path: Path) -> None:
    runtime_base = 0x7FF700000000
    service, session_id, _ = _rebased_service(tmp_path, runtime_base)

    from_static = service.resolve_runtime_address(session_id, 0x140001234, source="static")
    assert from_static.ok and from_static.data is not None
    assert from_static.data["runtime_address"] == runtime_base + 0x1234
    assert from_static.data["static_address"] == 0x140001234
    assert from_static.data["rva"] == 0x1234

    from_rva = service.resolve_runtime_address(session_id, 0x1234, source="rva")
    assert from_rva.ok and from_rva.data is not None
    assert from_rva.data["runtime_address"] == runtime_base + 0x1234

    from_runtime = service.resolve_runtime_address(
        session_id,
        runtime_base + 0x1234,
        source="runtime",
    )
    assert from_runtime.ok and from_runtime.data is not None
    assert from_runtime.data["runtime_address"] == runtime_base + 0x1234
    assert from_runtime.data["static_address"] == 0x140001234


def test_resolve_runtime_address_rejects_unknown_source(tmp_path: Path) -> None:
    service, session_id, _ = _rebased_service(tmp_path, 0x7FF700000000)

    rejected = service.resolve_runtime_address(session_id, 0x1000, source="nonsense")
    assert not rejected.ok and rejected.error is not None
    assert rejected.error.code == "invalid_request"


def test_breakpoint_set_rebases_static_and_rva_coordinates(tmp_path: Path) -> None:
    runtime_base = 0x7FF700000000
    service, session_id, dynamic = _rebased_service(tmp_path, runtime_base)

    assert service.dynamic_breakpoint_set(
        session_id,
        0x140001234,
        address_space="static",
    ).ok
    assert service.dynamic_breakpoint_set(session_id, 0x1234, address_space="rva").ok
    assert service.dynamic_breakpoint_set(session_id, runtime_base + 0x40).ok

    requested = [
        int(params["address"])
        for command, params in dynamic.requests
        if command == "breakpoints.set"
    ]
    assert requested == [
        runtime_base + 0x1234,
        runtime_base + 0x1234,
        runtime_base + 0x40,
    ]

    rejected = service.dynamic_breakpoint_set(session_id, 0x1000, address_space="bogus")
    assert not rejected.ok and rejected.error is not None
    assert rejected.error.code == "invalid_request"


@pytest.mark.parametrize("bad_address", [-1, "0x1000", 1.5, None, True])
def test_breakpoint_set_rejects_a_bad_runtime_address_before_the_worker(
    tmp_path: Path, bad_address: object
) -> None:
    """The default runtime coordinate validates its address like static/rva do.

    A negative, non-integer or otherwise malformed address used to be returned
    untranslated and forwarded whole to breakpoints.set; only the static and rva
    coordinates -- which round-trip through _require_address -- rejected it. The
    guard now makes the default space fail the same structured invalid_address
    way, and nothing reaches the worker.
    """
    service, session_id, dynamic = _rebased_service(tmp_path, 0x7FF700000000)

    rejected = service.dynamic_breakpoint_set(session_id, cast(int, bad_address))

    assert not rejected.ok and rejected.error is not None
    assert rejected.error.code == "invalid_address"
    assert not [command for command, _ in dynamic.requests if command == "breakpoints.set"]


def test_analyze_function_dynamic_reports_stop_on_its_breakpoint(tmp_path: Path) -> None:
    service, session_id, dynamic = _rebased_service(tmp_path, 0x140000000)

    report = service.analyze_function_dynamic(session_id, 0x140001000)

    assert report.ok and report.data is not None
    data = report.data
    assert data["function"]["static_address"] == 0x140001000
    assert data["function"]["runtime_address"] == 0x140001000
    assert data["breakpoint"] == {"address": 0x140001000, "armed": True}
    assert data["execution"]["resumed"] is True
    assert data["execution"]["instruction_pointer"] == 0x140001000
    assert data["execution"]["stopped_at_breakpoint"] is True
    assert [
        int(params["address"])
        for command, params in dynamic.requests
        if command == "breakpoints.set"
    ] == [0x140001000]


def test_analyze_function_dynamic_arms_the_rebased_address(tmp_path: Path) -> None:
    runtime_base = 0x7FF700000000
    service, session_id, dynamic = _rebased_service(tmp_path, runtime_base)

    report = service.analyze_function_dynamic(
        session_id,
        0x140001000,
        decompile=False,
    )

    assert report.ok and report.data is not None
    data = report.data
    assert data["function"]["runtime_address"] == runtime_base + 0x1000
    assert data["static"]["decompiled"] is False
    assert [
        int(params["address"])
        for command, params in dynamic.requests
        if command == "breakpoints.set"
    ] == [runtime_base + 0x1000]
    # The fake reports a static-looking rip, so the stop is honestly not ours.
    assert data["execution"]["stopped_at_breakpoint"] is False


class _ResumeFailWorker(FakeDynamicWorker):
    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "debug.resume":
            self.requests.append((command, params or {}))
            raise XdbgRpcError(
                "debugger_command_failed",
                "resume rejected",
                details={"method": "debug.resume", "command": "resume"},
            )
        return super().request(command, params, timeout=timeout)


def test_analyze_function_dynamic_fails_closed_when_resume_fails(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, _ResumeFailWorker(), FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.open_static(session_id).ok

    report = service.analyze_function_dynamic(session_id, 0x140001000, decompile=False)

    assert not report.ok and report.error is not None
    assert report.error.code == "debugger_command_failed"
    assert report.data is not None
    assert report.data["execution"]["resumed"] is False
    assert report.data["breakpoint"] == {"address": 0x140001000, "armed": True}


class _ArgumentRegisterWorker(FakeDynamicWorker):
    """Fake reporting Microsoft x64 argument registers while parked on one API."""

    def __init__(self, api_address: int) -> None:
        super().__init__()
        self.api_address = api_address
        self.hits = 0

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "registers.read":
            self.requests.append((command, params or {}))
            self.hits += 1
            return {
                "registers": {
                    "rip": self.api_address,
                    "rsp": 0x120000,
                    "rcx": 0x1000 + self.hits,
                    "rdx": 0x2000 + self.hits,
                    "r8": 0x3000 + self.hits,
                    "r9": 0x4000 + self.hits,
                }
            }
        return super().request(command, params, timeout=timeout)


def test_trace_api_arguments_captures_register_arguments(tmp_path: Path) -> None:
    api_address = 0x140002000
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = _ArgumentRegisterWorker(api_address)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    traced = service.trace_api_arguments(session_id, address=api_address, max_hits=2)

    assert traced.ok and traced.data is not None
    data = traced.data
    assert data["hit_count"] == 2
    assert data["truncated"] is True
    assert data["stopped_elsewhere"] is False
    assert data["convention"] == "microsoft_x64_integer_registers"
    first = data["hits"][0]
    assert first["instruction_pointer"] == api_address
    assert [argument["source"] for argument in first["arguments"]] == [
        "rcx",
        "rdx",
        "r8",
        "r9",
    ]
    assert first["arguments"][0]["value"] == 0x1001
    assert data["hits"][1]["arguments"][0]["value"] == 0x1002

    commands = [command for command, _ in worker.requests]
    assert commands.count("breakpoints.set") == 1
    assert commands.count("breakpoints.remove") == 1


def test_trace_api_arguments_stops_when_break_is_not_ours(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = _ArgumentRegisterWorker(0x140002000)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    traced = service.trace_api_arguments(session_id, address=0x140009000, max_hits=3)

    assert traced.ok and traced.data is not None
    assert traced.data["hit_count"] == 0
    assert traced.data["stopped_elsewhere"] is True
    commands = [command for command, _ in worker.requests]
    assert commands.count("breakpoints.remove") == 1


def test_stack_arguments_skip_the_return_address() -> None:
    from headless_re_mcp.core.service_trace import _stack_arguments

    payload = {
        "base": 0x120000,
        "pointer_size": 4,
        "entries": [
            {"index": 0, "address": 0x120000, "value": 0x401234},  # return address
            {"index": 1, "address": 0x120004, "value": 0xAAAA},
            {"index": 2, "address": 0x120008, "value": 0xBBBB},
        ],
    }

    arguments = _stack_arguments(payload, 3)

    assert [item["value"] for item in arguments] == [0xAAAA, 0xBBBB, None]
    assert [item["source"] for item in arguments] == [
        "[esp+0x4]",
        "[esp+0x8]",
        "[esp+0xc]",
    ]


def test_stack_arguments_tolerate_missing_payloads() -> None:
    from headless_re_mcp.core.service_trace import _stack_arguments

    assert _stack_arguments(None, 2) == []
    assert _stack_arguments({"entries": "nope"}, 2) == []
    assert _stack_arguments({"entries": []}, 0) == []


def test_trace_api_arguments_requires_exactly_one_target(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    rejected = service.trace_api_arguments(session_id)

    assert not rejected.ok and rejected.error is not None
    assert rejected.error.code == "invalid_request"


def test_session_recover_reopens_only_dead_backends(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.open_static(session_id).ok

    kept = service.session_recover(session_id)
    assert kept.ok and kept.data is not None
    assert kept.data["kept"] == 2
    assert kept.data["recovered"] == 0

    # A dead x64dbg worker also marks the session FAILED, which is terminal by
    # design, so recovery must rebuild the session rather than revive it.
    service._fail_runtime(session_id, BackendKind.X64DBG)
    recovered = service.session_recover(session_id)

    assert recovered.ok and recovered.data is not None
    assert recovered.data["replaced"] is True
    assert recovered.data["previous_session_id"] == session_id
    replacement = str(recovered.data["session_id"])
    assert replacement != session_id
    assert recovered.data["recovered"] == 2
    assert service.dynamic_state(replacement).ok
    # The dead session is closed so it stops holding its backend workers.
    assert service.registry.get(session_id).state == SessionState.CLOSED


class RaceyPauseWorker(FakeDynamicWorker):
    """Rejects pause once the target already stopped, as the debugger does."""

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "debug.pause":
            self.requests.append((command, params or {}))
            self.current_state = _state("paused")
            raise XdbgRpcError(
                "debugger_command_failed",
                "x64dbg rejected command: pause",
                details={"method": "debug.pause", "command": "pause"},
            )
        return super().request(command, params, timeout=timeout)


def test_pause_succeeds_when_the_target_stopped_before_the_command_landed(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = RaceyPauseWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    paused = service.dynamic_pause(session_id, timeout=2.0)

    # The debugger checks "is it running" and only then issues pause, so a
    # breakpoint hit in that window rejects a pause that already happened.
    assert paused.ok, paused.error
    assert "debug.state" in {command for command, _ in worker.requests}


class RejectingStepWorker(FakeDynamicWorker):
    """Rejects a step while the target sits paused, as the debugger does."""

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "debug.step_into":
            self.requests.append((command, params or {}))
            self.current_state = _state("paused")
            raise XdbgRpcError(
                "debugger_command_failed",
                "x64dbg rejected command: StepInto",
                details={"method": "debug.step_into", "command": "StepInto"},
            )
        return super().request(command, params, timeout=timeout)


def test_a_rejected_step_is_reported_not_absorbed(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, RejectingStepWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    stepped = service.dynamic_step_into(session_id, timeout=2.0)

    # A step is rejected while the target is paused, which is also its state
    # before the step, so "already paused" can never show the step happened.
    # Absorbing it would report an instruction pointer that never moved.
    assert not stepped.ok and stepped.error is not None
    assert stepped.error.code == "debugger_command_failed"
    assert stepped.error.details["command"] == "StepInto"


class BrokenPauseWorker(FakeDynamicWorker):
    """Rejects pause while the target keeps running."""

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "debug.pause":
            self.requests.append((command, params or {}))
            self.current_state = _state("running")
            raise XdbgRpcError(
                "debugger_command_failed",
                "x64dbg rejected command: pause",
                details={"method": "debug.pause", "command": "pause"},
            )
        return super().request(command, params, timeout=timeout)


def test_pause_still_fails_when_the_target_keeps_running(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, BrokenPauseWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    paused = service.dynamic_pause(session_id, timeout=2.0)

    # Absorbing this too would hide a debugger that genuinely cannot stop.
    assert not paused.ok and paused.error is not None
    assert paused.error.code == "debugger_command_failed"


def test_session_recover_rebuilds_a_dropped_connection_instead_of_reporting_it_kept(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    # Isolate explicit recovery: the background monitor would otherwise repair
    # the connection first and this would test the monitor instead.
    service._health.stop()

    # A transport fault drops the connection but leaves the worker alive, so the
    # backend stays registered and the session never reaches FAILED.
    reconnects: list[str] = []

    def reconnect() -> None:
        reconnects.append("reconnect")
        worker.transport_connected = True  # type: ignore[attr-defined]

    worker.transport_connected = False  # type: ignore[attr-defined]
    worker.reconnect = reconnect  # type: ignore[attr-defined]

    recovered = service.session_recover(session_id, ["x64dbg"])

    assert recovered.ok and recovered.data is not None
    assert reconnects == ["reconnect"]
    entry = recovered.data["backends"][0]
    assert entry["action"] == "reconnected" and entry["ok"]
    assert recovered.data["recovered"] == 1
    assert recovered.data["kept"] == 0
    # Restarting would have discarded the debuggee the live worker still owns.
    assert recovered.data["replaced"] is False


def test_session_recover_replaces_a_dead_worker_it_could_still_reach_over(
    tmp_path: Path,
) -> None:
    """A worker can die while its registration and connection object survive.

    Nothing had to call into the backend for the process to exit, so the runtime
    is still registered and ``transport_connected`` still answers True. Trusting
    either would report the session as kept and healthy immediately before every
    subsequent call fails against a process that is gone.
    """
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    dead = FakeDynamicWorker()
    replacement = FakeDynamicWorker()
    service = _service_with_dynamic_workers(tmp_path, [dead, replacement])
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    service._health.stop()

    dead.exit_code = 1  # type: ignore[attr-defined]

    recovered = service.session_recover(session_id, ["x64dbg"])

    assert recovered.ok and recovered.data is not None
    entry = recovered.data["backends"][0]
    assert entry["action"] == "reopened" and entry["ok"]
    assert recovered.data["kept"] == 0
    assert recovered.data["failed"] == 0
    assert dead.terminated
    # The replacement has to be the worker the session now talks to.
    assert service.dynamic_state(session_id).ok
    assert replacement.requests


def test_session_recover_reports_a_failed_reconnect_per_backend(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    service._health.stop()

    def reconnect() -> None:
        raise XdbgRpcError("rpc_startup_timeout", "pipe never came back")

    worker.transport_connected = False  # type: ignore[attr-defined]
    worker.reconnect = reconnect  # type: ignore[attr-defined]

    recovered = service.session_recover(session_id, ["x64dbg"])

    # A worker stuck long enough to refuse the reconnect must not be reported as
    # recovered, or the caller keeps issuing calls that cannot succeed.
    assert not recovered.ok and recovered.error is not None
    assert recovered.error.code == "recovery_failed"
    assert recovered.data is not None
    entry = recovered.data["backends"][0]
    assert entry["action"] == "reconnected" and entry["ok"] is False
    assert entry["error"]["code"] == "XdbgRpcError"
    assert recovered.data["recovered"] == 0
    assert recovered.data["failed"] == 1


def test_failed_session_recover_moves_knowledge_to_the_replacement_id(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    recorded = service.knowledge_record(
        session_id, "function", "0x140001000", {"name": "main"}
    )
    assert recorded.ok

    service._fail_runtime(session_id, BackendKind.X64DBG)
    recovered = service.session_recover(session_id)

    assert recovered.ok and recovered.data is not None
    replacement = str(recovered.data["session_id"])
    assert replacement != session_id
    found = service.knowledge_query(replacement)
    assert found.ok and found.data is not None
    assert found.data["total"] >= 1
    assert any(entry.get("key") == "0x140001000" for entry in found.data["entries"])


def test_session_recover_rejects_unknown_backend(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())
    session_id = _create(service, binary)

    rejected = service.session_recover(session_id, ["nonsense"])

    assert not rejected.ok and rejected.error is not None
    assert rejected.error.code == "invalid_request"


def test_batch_analyze_reports_per_binary_outcomes(tmp_path: Path) -> None:
    first = tmp_path / "one.exe"
    second = tmp_path / "two.exe"
    _write_minimal_pe(first)
    _write_minimal_pe(second)
    missing = tmp_path / "missing.exe"
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())

    result = service.batch_analyze(
        [str(first), str(second), str(missing)],
        max_workers=2,
        open_static=False,
    )

    assert result.ok and result.data is not None
    data = result.data
    assert data["count"] == 3
    assert data["succeeded"] == 2
    assert data["failed"] == 1
    failed = [entry for entry in data["entries"] if not entry["ok"]]
    assert len(failed) == 1
    assert failed[0]["binary"] == str(missing)
    assert failed[0]["session_id"] is None


def test_batch_analyze_validates_inputs(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())

    assert not service.batch_analyze([]).ok
    assert not service.batch_analyze(["sample.exe"], max_workers=99).ok


def test_analyze_function_dynamic_rejects_out_of_range_timeout(tmp_path: Path) -> None:
    service, session_id, _ = _rebased_service(tmp_path, 0x140000000)

    rejected = service.analyze_function_dynamic(session_id, 0x140001000, timeout=0)

    assert not rejected.ok and rejected.error is not None
    assert rejected.error.code == "invalid_request"


def test_a_dump_onto_a_full_volume_says_the_disk_is_full(tmp_path: Path) -> None:
    """Nothing prunes the artifact root, so a full volume is a matter of time.

    Without the check the write fails partway through as an OSError and reaches
    the caller as internal_error, naming neither the disk nor the directory that
    filled -- so the agent retries a dump that cannot succeed, and the operator
    reads an incident that points at the code. trace.start already refuses this
    way; dumps are the other thing that writes a large file.
    """
    import shutil
    from dataclasses import replace
    from unittest.mock import patch

    from headless_re_mcp.config import Settings

    usage_type = shutil.disk_usage(".").__class__
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        with patch(
            "headless_re_mcp.core.service_dynamic_inspect.shutil.disk_usage",
            return_value=usage_type(total=100, used=100, free=1024),
        ):
            result = service.modules_dump("s1", 0x140000000, size=8 * 1024 * 1024)
    finally:
        service.close_all()

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "insufficient_disk_space"
    assert result.error.details["available_disk_bytes"] == 1024
    assert result.error.details["required_bytes"] == 8 * 1024 * 1024
    assert "artifact_root" in result.error.details


class _BlockingEventWorker(FakeDynamicWorker):
    """Holds the native events.read that navigation uses while WAITING."""

    def __init__(self) -> None:
        from threading import Event

        super().__init__()
        self.entered = Event()
        self.release = Event()

    def read_events(
        self,
        cursor: int,
        *,
        limit: int = 100,
        timeout: float = 10.0,
    ) -> DebugEventBatch:
        self.event_reads.append((cursor, limit, timeout))
        self.entered.set()
        assert self.release.wait(10)
        return DebugEventBatch(
            events=(),
            cursor=cursor,
            next_cursor=cursor,
            oldest_sequence=1 if cursor else 0,
            latest_sequence=cursor,
            dropped=0,
            dropped_total=0,
            has_more=False,
            capacity=1024,
        )


def test_events_consume_during_navigation_does_not_read_native_or_kill_worker(
    tmp_path: Path,
) -> None:
    from threading import Thread

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = _BlockingEventWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    runtime = service._runtime_owner.get(session_id, BackendKind.X64DBG)
    assert runtime is not None and runtime.event_log is not None
    runtime.event_log.append_events((_debug_event(1, "debug.paused"),))

    outcome: dict[str, object] = {}

    def navigate() -> None:
        outcome["nav"] = service.workflow_navigate_to_event(
            session_id,
            "breakpoint.hit",
            timeout=8.0,
            event_budget=8,
        )

    thread = Thread(target=navigate, daemon=True)
    thread.start()
    assert worker.entered.wait(5)
    native_reads = len(worker.event_reads)

    consumed = service.workflow_events_consume(session_id, timeout=0.2)
    peeked = service.dynamic_events(session_id, timeout=0.2)

    assert len(worker.event_reads) == native_reads
    assert consumed.ok and consumed.data is not None
    assert [event["sequence"] for event in consumed.data["events"]] == [1]
    assert peeked.ok and peeked.data is not None
    assert [event["sequence"] for event in peeked.data["events"]] == [1]
    replayed = service.workflow_events_consume(session_id, timeout=0.2)
    assert replayed.ok and replayed.data is not None
    assert [event["sequence"] for event in replayed.data["events"]] == []
    assert runtime.event_cursor is not None
    assert runtime.event_cursor.value == 0
    assert not worker.terminated
    assert service.registry.get(session_id).state != SessionState.FAILED
    assert service.dynamic_state(session_id).ok

    cancelled = service.workflow_cancel(session_id, timeout=3.0)
    worker.release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert cancelled.ok, cancelled.error
    assert not worker.terminated
    assert service.registry.get(session_id).state != SessionState.FAILED


def test_navigate_cursor_desync_does_not_kill_the_debuggee(tmp_path: Path) -> None:
    from threading import Thread

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = _BlockingEventWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    outcome: dict[str, object] = {}

    def navigate() -> None:
        outcome["nav"] = service.workflow_navigate_to_event(
            session_id,
            "breakpoint.hit",
            timeout=8.0,
            event_budget=8,
        )

    thread = Thread(target=navigate, daemon=True)
    thread.start()
    assert worker.entered.wait(5)
    runtime = service._runtime_owner.get(session_id, BackendKind.X64DBG)
    assert runtime is not None and runtime.event_cursor is not None
    runtime.event_cursor.value = 99
    worker.release.set()
    thread.join(5)
    assert not thread.is_alive()

    navigated = outcome["nav"]
    assert isinstance(navigated, Result)
    assert not navigated.ok and navigated.error is not None
    assert navigated.error.code == "event_cursor_inconsistent"
    assert not worker.terminated
    assert service.registry.get(session_id).state != SessionState.FAILED
    assert service.dynamic_state(session_id).ok


def test_open_dynamic_terminates_worker_if_event_log_create_fails(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)

    def fail_log(*_args: object, **_kwargs: object) -> object:
        raise OSError("disk full")

    monkeypatch.setattr(  # type: ignore[attr-defined]
        "headless_re_mcp.core.service.PersistentDebugEventLog",
        fail_log,
    )

    opened = service.open_dynamic(session_id)

    assert not opened.ok and opened.error is not None
    assert worker.terminated
    assert BackendKind.X64DBG not in service.registry.get(session_id).backends


def test_recover_discards_dead_runtime_stops_drain_and_closes_log(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    dead = FakeDynamicWorker()
    replacement = FakeDynamicWorker()
    service = _service_with_dynamic_workers(tmp_path, [dead, replacement])
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    service._health.stop()

    runtime = service._runtime_owner.get(session_id, BackendKind.X64DBG)
    assert runtime is not None and runtime.event_log is not None
    closed: list[bool] = []
    inner_close = runtime.event_log.close

    def spy_close() -> None:
        closed.append(True)
        inner_close()

    runtime.event_log.close = spy_close  # type: ignore[method-assign]

    class _FakePump:
        def __init__(self) -> None:
            self.stopped = False

        def stop(self, *, timeout: float = 2.0) -> None:
            del timeout
            self.stopped = True

    pump = _FakePump()
    runtime.event_drain_pump = pump  # type: ignore[assignment]
    dead.exit_code = 1  # type: ignore[attr-defined]

    recovered = service.session_recover(session_id, ["x64dbg"])

    assert recovered.ok and recovered.data is not None
    assert recovered.data["backends"][0]["action"] == "reopened"
    assert dead.terminated
    assert pump.stopped
    assert closed
    assert service.dynamic_state(session_id).ok


def test_pe_tools_on_web_session_report_target_mismatch(tmp_path: Path) -> None:
    service = AnalysisService(_settings(tmp_path))
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    session = created.data["session"]
    assert isinstance(session, dict)
    session_id = str(session["id"])

    dynamic = service.dynamic_state(session_id)
    static = service.static_functions(session_id)

    assert not dynamic.ok and dynamic.error is not None
    assert dynamic.error.code == "target_mismatch"
    assert not static.ok and static.error is not None
    assert static.error.code == "target_mismatch"