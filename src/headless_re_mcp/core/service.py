from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path
from threading import RLock
from time import monotonic, sleep
from typing import Any, Literal, Protocol, cast
from uuid import uuid4

from headless_re_mcp.backends.ida.client import IdaWorkerClient, IdaWorkerError
from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.addressing import (
    AddressSyncError,
    ModuleMapping,
    RebasedModuleMapping,
    RuntimeModuleCatalog,
    build_main_module_mapping,
    build_rebased_module_mapping,
)
from headless_re_mcp.core.application_services import (
    ApplicationServices,
    ArtifactApplicationService,
    DynamicApplicationService,
    InteractionApplicationService,
    RuntimeApplicationService,
)
from headless_re_mcp.core.event_drain import EventDrainPump, drain_native_into_log
from headless_re_mcp.core.event_log import PersistentDebugEventLog
from headless_re_mcp.core.events import (
    DEFAULT_DEBUG_EVENT_BATCH,
    MAX_DEBUG_EVENT_BATCH,
    DebugEventBatch,
    DebugEventCursor,
    DebugEventProtocolError,
)
from headless_re_mcp.core.health import BackendHealthMonitor
from headless_re_mcp.core.models import (
    Architecture,
    BackendHandle,
    BackendKind,
    ModuleSelector,
    Result,
    RpcError,
    Session,
    SessionState,
)
from headless_re_mcp.core.repository import AnalysisRepository, SqliteAnalysisRepository
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.runtime_state import (
    BackendRuntimeOwner,
    BackendRuntimePhase,
    DebuggeeSnapshot,
    DebuggeeStateOwner,
    TraceStateOwner,
    UnpackStateOwner,
    WorkflowStateOwner,
)
from headless_re_mcp.core.service_detect import DetectAnalysisMixin
from headless_re_mcp.core.service_dotnet import DotnetAnalysisMixin
from headless_re_mcp.core.service_ext import (
    _DEBUG_EVENT_BUDGET_PER_BATCH,
    ExtAnalysisMixin,
    _timeline_append,
    note_session_closed,
    note_session_created,
)
from headless_re_mcp.core.service_static import StaticAnalysisMixin
from headless_re_mcp.core.service_unpack_cli import UnpackCliMixin
from headless_re_mcp.core.service_workflow import WorkflowAnalysisMixin
from headless_re_mcp.core.session import (
    InvalidStateTransition,
    SessionRegistry,
    file_sha256,
)
from headless_re_mcp.core.ui_ocr import ocr_hwnd
from headless_re_mcp.core.ui_sendinput import click_hwnd_sendinput, send_key_sendinput
from headless_re_mcp.core.ui_uia import (
    build_uia_tree,
    click_hwnd_uia,
    set_value_uia,
    uia_available,
)
from headless_re_mcp.core.ui_win32 import (
    build_window_tree,
    capture_hwnd_screenshot,
    click_hwnd,
    click_hwnd_at,
    close_hwnd,
    invoke_hwnd,
    resolve_hwnd,
    send_key,
    set_window_text,
    wait_for_window,
)
from headless_re_mcp.core.windows import (
    UiPidBoundaryError,
    is_pid_alive,
    list_process_windows,
    list_windows_for_pids,
    resolve_allowed_ui_pids,
)
from headless_re_mcp.detection import (
    PeFormatError,
    ScanMode,
    scan_pe,
)
from headless_re_mcp.detection.die import DieScanError, DieScanResult, scan_with_die
from headless_re_mcp.detection.exeinfope import (
    ExeinfopeScanResult,
    scan_with_exeinfope,
)
from headless_re_mcp.doctor import run_doctor
from headless_re_mcp.dotnet.de4dot import run_de4dot
from headless_re_mcp.dotnet.net_reactor_slayer import (
    run_net_reactor_slayer,
)
from headless_re_mcp.unpack.iat_rank import (
    analyze_import_entries,
    gate_iat_rebuild,
    rank_iat_candidates,
)
from headless_re_mcp.unpack.observe import (
    collect_oep_observations,
    stub_rva_ranges_from_sections,
)
from headless_re_mcp.unpack.oep import score_oep_candidates
from headless_re_mcp.unpack.pause_quality import assess_pause_quality
from headless_re_mcp.unpack.pe_rebuild import (
    PeRebuildError,
    parse_runtime_headers,
    rebuild_imports,
    remap_dump_to_file,
    write_rebuilt_pe,
)
from headless_re_mcp.unpack.phase_bridge import (
    note_dump_success,
    note_imports_rebuilt,
    note_verified,
)
from headless_re_mcp.unpack.plan import build_unpack_plan
from headless_re_mcp.unpack.recommend import pe_suggests_vm_protector, recommend_unpack_route
from headless_re_mcp.unpack.scylla import (
    run_scylla,
)
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    UnpackSessionError,
    UnpackSessionState,
    add_artifact,
    append_timeline,
    cancel_unpack_session,
    check_timeout,
    create_unpack_session,
    ensure_unpack_active,
    fail_unpack_session,
    persist_state_snapshot,
    transition,
    write_timeline_jsonl,
)
from headless_re_mcp.unpack.stage_labels import (
    STAGE_DUMPED,
    STAGE_IAT_REBUILT,
    STAGE_RUNNABLE,
    gate_stage_upgrade,
    resolve_artifact_kind_for_stage,
)
from headless_re_mcp.unpack.stub_calls import analyze_dump_stub_coupling
from headless_re_mcp.unpack.upx import (
    UpxResult,
    test_upx,
    unpack_upx,
)
from headless_re_mcp.unpack.vmp_dumper import (
    run_vmp_dumper,
)
from headless_re_mcp.unpack.xvlkc import (
    run_xvlkc,
)
from headless_re_mcp.workflows.breakpoints import (
    BreakpointOperation,
    BreakpointOperationKind,
)
from headless_re_mcp.workflows.engine import (
    WorkflowState,
    WorkflowTransition,
    consume_workflow_events,
    start_workflow_navigation,
    timeout_workflow_navigation,
)
from headless_re_mcp.workflows.executor import (
    WorkflowExecutionError,
    execute_workflow_transition,
)
from headless_re_mcp.workflows.models import WorkflowInvariantError
from headless_re_mcp.workflows.navigation import EventPattern, NavigationStatus
from headless_re_mcp.workflows.runtime import (
    WorkflowRunStatus,
    WorkflowRuntime,
    advance_workflow_runtime,
    create_workflow_runtime,
    fail_workflow_runtime,
)

JsonObject = dict[str, Any]


class BackendWorker(Protocol):
    @property
    def pid(self) -> int: ...

    @property
    def capabilities(self) -> frozenset[str]: ...

    @property
    def metadata(self) -> JsonObject: ...

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject: ...

    def close(self, *, timeout: float = 15.0) -> None: ...

    def terminate(self) -> None: ...


class DynamicWorker(BackendWorker, Protocol):
    def read_events(
        self,
        cursor: int,
        *,
        limit: int = 100,
        timeout: float = 10.0,
    ) -> DebugEventBatch: ...

    def wait_for_state(
        self,
        states: set[str],
        *,
        timeout: float = 30.0,
        after_event_sequence: int | None = None,
        transition_event_kinds: frozenset[str] = frozenset(),
    ) -> JsonObject: ...


StaticWorker = BackendWorker
StaticWorkerFactory = Callable[[Session, Settings], BackendWorker]
DynamicWorkerFactory = Callable[[Session, Settings], DynamicWorker]
DieScanner = Callable[..., DieScanResult]
ExeinfopeScanner = Callable[..., ExeinfopeScanResult]
UpxTester = Callable[..., UpxResult]
UpxUnpacker = Callable[..., UpxResult]


@dataclass(slots=True)
class _BackendRuntime:
    worker: BackendWorker
    lock: RLock = field(default_factory=RLock)
    event_cursor: DebugEventCursor | None = None
    # Drain cursor runs ahead of event_cursor and fills event_log for true replay.
    drain_cursor: DebugEventCursor | None = None
    event_log: PersistentDebugEventLog | None = None
    event_drain_pump: EventDrainPump | None = None
    # Set when an event batch reports dropped>0; cleared by a fresh modules.list.
    snapshot_resync_required: bool = False


@dataclass(slots=True)
class _TraceArtifactState:
    session_id: str
    path: Path
    requested_path: str
    max_events: int
    timeout_ms: int
    max_file_bytes: int
    started_monotonic: float
    active: bool = True
    terminal_reason: str = "none"
    artifact_id: str | None = None
    artifact_sha256: str | None = None
    artifact_size: int | None = None
    artifact_truncated: bool = False
    artifact_error: str | None = None
    last_status: JsonObject = field(default_factory=dict)


@dataclass(slots=True)
class _ServiceWorkflowPort:
    service: AnalysisService
    session_id: str
    runtime: _BackendRuntime

    def resume(self, *, timeout: float) -> None:
        self.service._workflow_resume_locked(self.session_id, self.runtime, timeout=timeout)

    def ensure_paused(self, *, timeout: float) -> None:
        self.service._workflow_ensure_paused_locked(
            self.session_id,
            self.runtime,
            timeout=timeout,
        )

    def apply_breakpoint(
        self,
        operation: BreakpointOperation,
        *,
        timeout: float,
    ) -> None:
        self.service._workflow_apply_breakpoint_locked(
            self.session_id,
            self.runtime,
            operation,
            timeout=timeout,
        )

    def refresh_modules(
        self,
        selectors: Mapping[str, ModuleSelector],
        *,
        timeout: float,
    ) -> dict[str, RebasedModuleMapping | None]:
        return self.service._workflow_refresh_modules_locked(
            self.session_id,
            self.runtime,
            selectors,
            timeout=timeout,
        )


# rpc_transport_error is deliberately absent: the client raises it only after
# confirming the worker is still running (a dead one raises worker_exited), so it
# means the connection broke and not the backend. Failing the runtime for it
# terminated x64dbg and the debuggee it owned, destroying the very session the
# next call would have reconnected.
_FATAL_WORKER_ERRORS = frozenset(
    {
        "analyzer_window_detected",
        "rpc_peer_mismatch",
        "rpc_protocol_error",
        "worker_exited",
        "worker_protocol_error",
    }
)
_MAX_WORKFLOW_EVENT_BUDGET = 100_000
_MAX_WORKFLOW_TIMEOUT = 300.0
_MAX_MODULE_DUMP_BYTES = 64 * 1024 * 1024
_MAX_STATIC_INLINE_TEXT = 64 * 1024
_MAX_STATIC_BATCH_COMMANDS = 32
_OEP_REGION_SNAPSHOT_LIMIT = 512
_RUN_CONTROL_TRANSITION_EVENTS: dict[str, frozenset[str]] = {
    "debug.resume": frozenset({"debug.resumed"}),
    "debug.step_into": frozenset({"debug.resumed", "debug.stepped"}),
    "debug.step_over": frozenset({"debug.resumed", "debug.stepped"}),
}


class AnalysisService(
    StaticAnalysisMixin,
    DetectAnalysisMixin,
    DotnetAnalysisMixin,
    UnpackCliMixin,
    WorkflowAnalysisMixin,
    ExtAnalysisMixin,
):
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        registry: SessionRegistry | None = None,
        worker_factory: StaticWorkerFactory | None = None,
        static_worker_factory: StaticWorkerFactory | None = None,
        dynamic_worker_factory: DynamicWorkerFactory | None = None,
        die_scanner: DieScanner | None = None,
        exeinfope_scanner: ExeinfopeScanner | None = None,
        upx_tester: UpxTester | None = None,
        upx_unpacker: UpxUnpacker | None = None,
        de4dot_runner: Any | None = None,
        net_reactor_slayer_runner: Any | None = None,
        xvlkc_runner: Any | None = None,
        vmp_dumper_runner: Any | None = None,
        scylla_runner: Any | None = None,
        repository: AnalysisRepository | None = None,
    ) -> None:
        if worker_factory is not None and static_worker_factory is not None:
            raise ValueError("configure worker_factory or static_worker_factory, not both")
        self.settings = settings or Settings.load()
        self.registry = registry or SessionRegistry()
        self._static_worker_factory = static_worker_factory or worker_factory or _create_ida_worker
        self._dynamic_worker_factory = dynamic_worker_factory or _create_xdbg_worker
        self._die_scanner = die_scanner or scan_with_die
        self._exeinfope_scanner = exeinfope_scanner or scan_with_exeinfope
        self._upx_tester = upx_tester or test_upx
        self._upx_unpacker = upx_unpacker or unpack_upx
        self._de4dot_runner = de4dot_runner or run_de4dot
        self._net_reactor_slayer_runner = net_reactor_slayer_runner or run_net_reactor_slayer
        self._xvlkc_runner = xvlkc_runner or run_xvlkc
        self._vmp_dumper_runner = vmp_dumper_runner or run_vmp_dumper
        self._scylla_runner = scylla_runner or run_scylla
        self.repository = repository or SqliteAnalysisRepository(self.settings.artifact_root)
        self._runtime_owner: BackendRuntimeOwner[_BackendRuntime] = BackendRuntimeOwner()
        self._workflow_owner: WorkflowStateOwner[WorkflowRuntime] = WorkflowStateOwner()
        self._unpack_owner: UnpackStateOwner[UnpackSessionState] = UnpackStateOwner()
        self._trace_owner: TraceStateOwner[_TraceArtifactState] = TraceStateOwner()
        self._debuggee_owner = DebuggeeStateOwner(self.registry)

        # Compatibility views for callers and existing tests. Ownership stays in the
        # dedicated state components above; new code must use those components.
        self._runtimes = self._runtime_owner.items
        self._terminal_workflows = self._workflow_owner.terminal
        self._unpack_sessions = self._unpack_owner.sessions
        self._unpack_protect_snapshots = self._unpack_owner.protection_snapshots
        self._trace_sessions = self._trace_owner.sessions
        self._lock = self._runtime_owner.lock
        # Started when the first backend opens, so a service that never opens one
        # does not leave a sweep thread behind.
        self._health = BackendHealthMonitor(
            self._runtime_owner,
            interval_s=float(getattr(self.settings, "health_check_interval_s", 5.0)),
        )
        self.services = ApplicationServices(
            runtime=RuntimeApplicationService(self, self._runtime_owner),
            dynamic=DynamicApplicationService(self, self._debuggee_owner),
            interaction=InteractionApplicationService(self),
            artifacts=ArtifactApplicationService(self, self.repository),
            workflow_state=self._workflow_owner,
            unpack_state=self._unpack_owner,
            trace_state=self._trace_owner,
        )

    def doctor(self) -> Result[JsonObject]:
        return _success(run_doctor(self.settings).to_dict())

    def create_session(self, binary: str) -> Result[JsonObject]:
        try:
            session = self.registry.create(Path(binary))
            result = _success({"session": _session_json(session)})
            note_session_created(self, binary, result)
            return result
        except BaseException as exc:
            return _failure(exc)

    def get_session(self, session_id: str) -> Result[JsonObject]:
        try:
            return _success({"session": _session_json(self.registry.get(session_id))})
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def list_sessions(self) -> Result[JsonObject]:
        sessions = [_session_json(session) for session in self.registry.list()]
        return _success({"sessions": sessions, "count": len(sessions)})

    def open_static(self, session_id: str) -> Result[JsonObject]:
        return self.services.runtime.open_static(session_id)

    def _open_static(self, session_id: str) -> Result[JsonObject]:
        return self._open_backend(
            session_id,
            kind=BackendKind.IDA,
            metadata_key="static",
            worker_prefix="ida",
            endpoint_scheme="stdio",
            factory=self._static_worker_factory,
        )

    def open_dynamic(self, session_id: str) -> Result[JsonObject]:
        return self.services.runtime.open_dynamic(session_id)

    def session_recover(
        self,
        session_id: str,
        backends: list[str] | None = None,
    ) -> Result[JsonObject]:
        """Re-open backends whose worker process died, without resuming execution.

        Recovery is deliberate rather than implicit: a crashed dynamic backend
        comes back attached to nothing, so the caller decides whether to relaunch.
        Live backends are kept as-is, and by default only backends this session
        already had are restored.
        """
        try:
            session = self.registry.get(session_id)
            if session.state in {SessionState.CLOSING, SessionState.CLOSED}:
                raise InvalidStateTransition(
                    f"session cannot be recovered in {session.state.value} state"
                )
            if backends:
                requested = _recover_backend_kinds(backends)
            else:
                # A crashed backend is dropped from session.backends, so the
                # runtime phase is the only durable "this died" signal.
                attached = set(session.backends)
                requested = tuple(
                    kind
                    for kind in (BackendKind.IDA, BackendKind.X64DBG)
                    if kind in attached
                    or self._runtime_owner.phase(session_id, kind)
                    is BackendRuntimePhase.FAILED
                )
            if session.state is SessionState.FAILED:
                # FAILED is terminal by design, so recovery rebuilds the session
                # instead of quietly reviving one whose invariants already broke.
                return self._recover_by_replacement(
                    session_id,
                    str(session.binary),
                    requested,
                )

            entries: list[JsonObject] = []
            for kind in requested:
                backend = self._runtime_owner.get(session_id, kind)
                if backend is not None:
                    entries.append(self._restore_backend_transport(kind, backend))
                    continue
                entries.append(self._reopen_backend(session_id, kind))
            return _success(
                {
                    "backends": entries,
                    "requested": [kind.value for kind in requested],
                    "replaced": False,
                    "session_id": session_id,
                    "recovered": sum(
                        1
                        for item in entries
                        if item["action"] in {"reopened", "reconnected"} and item["ok"]
                    ),
                    "kept": sum(1 for item in entries if item["action"] == "kept"),
                    "failed": sum(1 for item in entries if not item["ok"]),
                },
                session_id=session_id,
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    @staticmethod
    def _restore_backend_transport(kind: BackendKind, runtime: _BackendRuntime) -> JsonObject:
        """Rebuild a live backend's dropped connection, or report it as healthy.

        A transport fault kills the connection but not the worker, so the
        backend is still registered. Reporting it as kept would leave the caller
        with a session that fails every later call and a recovery tool that
        claims there was nothing to do.
        """
        worker = runtime.worker
        reconnect = getattr(worker, "reconnect", None)
        connected = getattr(worker, "transport_connected", True)
        if connected or not callable(reconnect):
            return {"backend": kind.value, "action": "kept", "ok": True}
        entry: JsonObject = {"backend": kind.value, "action": "reconnected", "ok": True}
        try:
            reconnect()
        except BaseException as exc:  # noqa: BLE001 - reported per backend
            entry["ok"] = False
            entry["error"] = {"code": type(exc).__name__, "message": str(exc)}
        return entry

    def _reopen_backend(self, session_id: str, kind: BackendKind) -> JsonObject:
        opened = (
            self.open_static(session_id)
            if kind == BackendKind.IDA
            else self.open_dynamic(session_id)
        )
        entry: JsonObject = {
            "backend": kind.value,
            "action": "reopened",
            "ok": bool(opened.ok),
        }
        if not opened.ok and opened.error is not None:
            entry["error"] = opened.error.model_dump(mode="json")
        return entry

    def _recover_by_replacement(
        self,
        session_id: str,
        binary: str,
        requested: tuple[BackendKind, ...],
    ) -> Result[JsonObject]:
        """Rebuild a failed session as a fresh one over the same binary."""
        # Release the dead session first: a surviving IDA worker still holds the
        # database lock for this binary, and a second open would fail with
        # idapro.open_database code 4.
        with suppress(BaseException):
            self.close_session(session_id)
        created = self.create_session(binary)
        if not created.ok or created.data is None:
            return created
        payload = created.data.get("session")
        if not isinstance(payload, dict):
            raise XdbgRpcError(
                "rpc_protocol_error",
                "session creation did not return a session object",
            )
        replacement_id = str(payload["id"])
        entries: list[JsonObject] = []
        for kind in requested:
            if entries and not entries[-1]["ok"]:
                # One failed backend marks the whole session failed, so opening
                # the next one would only add a confusing cascade error.
                entries.append(
                    {
                        "backend": kind.value,
                        "action": "skipped",
                        "ok": False,
                        "reason": "an earlier backend failed, leaving the session unusable",
                    }
                )
                continue
            entries.append(self._reopen_backend(replacement_id, kind))
        return _success(
            {
                "backends": entries,
                "requested": [kind.value for kind in requested],
                "replaced": True,
                "previous_session_id": session_id,
                "session_id": replacement_id,
                "recovered": sum(1 for item in entries if item["ok"]),
                "kept": 0,
                "failed": sum(1 for item in entries if not item["ok"]),
            },
            session_id=replacement_id,
        )

    def _open_dynamic(self, session_id: str) -> Result[JsonObject]:
        return self._open_backend(
            session_id,
            kind=BackendKind.X64DBG,
            metadata_key="dynamic",
            worker_prefix="x64dbg",
            endpoint_scheme="xdbg-rpc",
            factory=self._dynamic_worker_factory,
        )

    def _open_backend(
        self,
        session_id: str,
        *,
        kind: BackendKind,
        metadata_key: str,
        worker_prefix: str,
        endpoint_scheme: str,
        factory: StaticWorkerFactory,
    ) -> Result[JsonObject]:
        with self._lock:
            try:
                session = self.registry.get(session_id)
                existing = self._runtime_owner.get(session_id, kind)
                if existing is not None:
                    if session.state in {
                        SessionState.CLOSING,
                        SessionState.CLOSED,
                        SessionState.FAILED,
                    }:
                        raise InvalidStateTransition(
                            f"cannot reuse {kind.value} in {session.state.value} state"
                        )
                    return _success(
                        {
                            "session": _session_json(session),
                            "backend": existing.worker.metadata,
                            "reused": True,
                        }
                    )
                if session.state not in {
                    SessionState.CREATED,
                    SessionState.READY,
                    SessionState.RUNNING,
                    SessionState.SUSPENDED,
                }:
                    raise InvalidStateTransition(
                        f"{metadata_key}.open cannot run in {session.state.value} state"
                    )

                opening_session = session.state == SessionState.CREATED
                if opening_session:
                    self.registry.transition(session_id, SessionState.OPENING)
                self._runtime_owner.begin_open(session_id, kind)
                try:
                    worker = factory(session, self.settings)
                    workflow = (
                        create_workflow_runtime() if kind == BackendKind.X64DBG else None
                    )
                    event_log: PersistentDebugEventLog | None = None
                    drain_cursor: DebugEventCursor | None = None
                    event_cursor = None
                    if kind == BackendKind.X64DBG:
                        event_cursor = DebugEventCursor()
                        drain_cursor = DebugEventCursor()
                        log_dir = self.settings.artifact_root / "debug-events" / session_id
                        event_log = PersistentDebugEventLog(log_dir / "events.sqlite3")
                    runtime = _BackendRuntime(
                        worker,
                        event_cursor=event_cursor,
                        drain_cursor=drain_cursor,
                        event_log=event_log,
                    )
                    if (
                        kind == BackendKind.X64DBG
                        and event_log is not None
                        and drain_cursor is not None
                        and hasattr(worker, "read_events")
                        and bool(getattr(self.settings, "debug_event_background_drain", True))
                    ):
                        pump = EventDrainPump(
                            cast(DynamicWorker, worker),
                            drain_cursor,
                            event_log,
                            lock=runtime.lock,
                        )
                        runtime.event_drain_pump = pump
                        pump.start()
                    self._runtime_owner.put(session_id, kind, runtime)
                    if self._health.interval_s > 0:
                        self._health.start()
                    if workflow is not None:
                        self._workflow_owner.put(session_id, workflow)
                    handle = BackendHandle(
                        kind=kind,
                        worker_id=f"{worker_prefix}:{session_id}",
                        pid=worker.pid,
                        endpoint=f"{endpoint_scheme}://pid/{worker.pid}",
                        capabilities=worker.capabilities,
                    )
                    self.registry.attach_backend(session_id, handle)
                    self.registry.update_metadata(session_id, {metadata_key: worker.metadata})
                    if opening_session:
                        current = self.registry.transition(session_id, SessionState.READY)
                    else:
                        current = self.registry.get(session_id)
                except BaseException:
                    self._runtime_owner.fail(session_id, kind)
                    if "worker" in locals():
                        worker.terminate()
                    if opening_session:
                        self.registry.transition(session_id, SessionState.FAILED)
                    raise
                return _success(
                    {
                        "session": _session_json(current),
                        "backend": worker.metadata,
                        "reused": False,
                    }
                )
            except BaseException as exc:
                return _failure(exc, session_id=session_id, backend=kind.value)

    def close_session(self, session_id: str) -> Result[JsonObject]:
        return self.services.runtime.close_session(session_id)

    def _close_session(self, session_id: str) -> Result[JsonObject]:
        result: Result[JsonObject]
        with self._lock:
            try:
                session = self.registry.get(session_id)
                if session.state == SessionState.CLOSED:
                    result = _success({"session": _session_json(session), "already_closed": True})
                    note_session_closed(self, session_id, result)
                    return result
                self.registry.transition(session_id, SessionState.CLOSING)
                runtimes = self._runtime_owner.pop_session(session_id)
                self._health.forget(session_id)
                self._workflow_owner.clear(session_id)
                self._unpack_owner.clear(session_id)
                self._debuggee_owner.clear(session_id)
            except BaseException as exc:
                result = _failure(exc, session_id=session_id)
                note_session_closed(self, session_id, result)
                return result

        close_errors: list[tuple[BackendKind, BaseException]] = []
        for kind, runtime in runtimes:
            if kind == BackendKind.X64DBG:
                self._stop_event_drain(runtime)
            with runtime.lock:
                try:
                    runtime.worker.close()
                except BaseException as exc:
                    close_errors.append((kind, exc))
                    runtime.worker.terminate()
            if kind == BackendKind.X64DBG:
                self._finalize_trace_after_worker_loss(
                    session_id,
                    reason="session_closed" if not close_errors else "worker_close_failed",
                )

        # A caller that closes sessions one at a time never reaches close_all, so
        # without this the sweep thread outlives every backend it existed for.
        if not self._runtime_owner.snapshot():
            self._health.stop()

        try:
            for kind in tuple(session.backends):
                self.registry.detach_backend(session_id, kind)
            if close_errors:
                self.registry.transition(session_id, SessionState.FAILED)
            closed = self.registry.transition(session_id, SessionState.CLOSED)
        except BaseException as exc:
            result = _failure(exc, session_id=session_id)
            note_session_closed(self, session_id, result)
            return result
        if close_errors:
            kind, error = close_errors[0]
            result = _failure(
                error,
                session_id=session_id,
                backend=kind.value,
                state=closed.state.value,
                close_error_count=len(close_errors),
            )
            note_session_closed(self, session_id, result)
            return result
        result = _success({"session": _session_json(closed), "already_closed": False})
        note_session_closed(self, session_id, result)
        return result

    def session_health(self, session_id: str | None = None) -> Result[JsonObject]:
        """Report backend liveness and any connections the monitor rebuilt.

        Checking synchronously means the answer reflects the moment it was asked
        rather than the last background sweep, which matters when a caller is
        deciding whether to recover.
        """
        try:
            if session_id is not None:
                self.registry.get(session_id)
            self._health.check_once()
            backends = self._health.report(session_id)
            return _success(
                {
                    "backends": backends,
                    "count": len(backends),
                    # None rather than True when nothing is open: "all zero
                    # backends are fine" reads as a clean bill of health.
                    "healthy": (
                        all(item["healthy"] for item in backends) if backends else None
                    ),
                },
                session_id=session_id,
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def close_all(self) -> Result[JsonObject]:
        session_ids = [session.id for session in self.registry.list()]
        errors: list[JsonObject] = []
        closed = 0
        for session_id in session_ids:
            result = self.close_session(session_id)
            if result.ok:
                closed += 1
            elif result.error is not None:
                errors.append(
                    {
                        "session_id": session_id,
                        "error": result.error.model_dump(mode="json"),
                    }
                )
        self._health.stop()
        if errors:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="close_all_failed",
                    message="one or more sessions failed to close cleanly",
                    details={"closed": closed, "errors": errors},
                ),
            )
        return _success({"closed": closed})

    def dynamic_state(self, session_id: str) -> Result[JsonObject]:
        return self.services.dynamic.state(session_id)

    def _dynamic_state(self, session_id: str) -> Result[JsonObject]:
        result = self._dynamic_request(session_id, "debug.state")
        if not result.ok or result.data is None:
            return result
        annotated = self._observe_debuggee_state(session_id, dict(result.data))
        return Result[JsonObject](ok=True, data=annotated, error=None, meta=dict(result.meta))

    def virtual_desktop_snapshot(self, session_id: str) -> Result[JsonObject]:
        """Return a passive, PID-bounded snapshot of the session desktop."""
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            snapshot_fn = getattr(runtime.worker, "desktop_snapshot", None)
            if not callable(snapshot_fn):
                raise XdbgRpcError(
                    "capability_unavailable",
                    "x64dbg worker does not expose desktop monitoring",
                )
            with runtime.lock:
                state = runtime.worker.request("debug.state", timeout=5.0)
                allowed, debuggee_pid = _desktop_monitor_pids(state)
                snapshot = snapshot_fn(allowed_pids=allowed)
            if not isinstance(snapshot, dict):
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    "desktop monitor returned a non-object snapshot",
                )
            payload = dict(snapshot)
            payload.update(
                {
                    "session_id": session_id,
                    "debuggee_pid": debuggee_pid,
                    "debugger_pid": runtime.worker.pid,
                    "allowed_pids": sorted(allowed),
                    "capture_mode": "passive",
                }
            )
            return _success(
                payload,
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except BaseException as exc:
            return _failure(
                exc,
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )

    def virtual_desktop_capture(
        self,
        session_id: str,
        *,
        hwnd: int | None = None,
    ) -> Result[JsonObject]:
        """Capture one authorized hidden-desktop window without switching desktops."""
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            snapshot_fn = getattr(runtime.worker, "desktop_snapshot", None)
            capture_fn = getattr(runtime.worker, "desktop_capture", None)
            if not callable(snapshot_fn) or not callable(capture_fn):
                raise XdbgRpcError(
                    "capability_unavailable",
                    "x64dbg worker does not expose hidden-desktop capture",
                )
            with runtime.lock:
                state = runtime.worker.request("debug.state", timeout=5.0)
                allowed, debuggee_pid = _desktop_monitor_pids(state)
                snapshot = snapshot_fn(allowed_pids=allowed)
                windows = snapshot.get("windows") if isinstance(snapshot, dict) else None
                rows = [row for row in windows or [] if isinstance(row, dict)]
                selected = _select_desktop_window(rows, hwnd)
                selected_hwnd = int(selected["hwnd"])
                output = (
                    self.settings.artifact_root.expanduser().resolve()
                    / "sessions"
                    / session_id
                    / "desktop"
                    / f"window-{selected_hwnd}.bmp"
                )
                capture = capture_fn(
                    selected_hwnd,
                    allowed_pids=allowed,
                    output_path=output,
                )
            if not isinstance(capture, dict):
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    "desktop capture returned a non-object payload",
                )
            return _success(
                {
                    **capture,
                    "session_id": session_id,
                    "debuggee_pid": debuggee_pid,
                    "window": selected,
                    "intrusion": "on_demand_printwindow",
                },
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except BaseException as exc:
            return _failure(
                exc,
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )

    def ui_windows_list(
        self,
        session_id: str,
        *,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
    ) -> Result[JsonObject]:
        return self.services.interaction.windows_list(
            session_id,
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
        )

    def _ui_windows_list(
        self,
        session_id: str,
        *,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
    ) -> Result[JsonObject]:
        """List top-level windows owned by the session debuggee (PID-bounded)."""
        return self._ui_call(
            session_id,
            capability="ui.windows.list",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=lambda ctx: {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                "allowed_pids": sorted(ctx["allowed"]),
                "blocked_pids": sorted(ctx["blocked"]),
                "windows": list_windows_for_pids(sorted(ctx["allowed"])),
                "count": 0,  # filled below
                "note": (
                    "windows are filtered to debuggee_pid "
                    "(plus explicit allow_child_pids); "
                    "debugger_pid/host are blocked"
                ),
            },
            finalize=lambda payload, ctx: _ui_finalize_windows(payload, ctx),
        )

    def ui_process_tree(
        self,
        session_id: str,
        *,
        allow_child_pids: list[int] | None = None,
    ) -> Result[JsonObject]:
        """Read-only process tree + window probe for debuggee (does not grant UI rights)."""

        def action(ctx: JsonObject) -> JsonObject:
            from headless_re_mcp.core.process_tree import (
                enumerate_direct_children,
                probe_child_window_candidates,
                process_image_path,
            )

            debuggee_pid = int(ctx["debuggee_pid"])
            children = enumerate_direct_children(debuggee_pid)
            child_rows = []
            for child in children:
                wins = list_windows_for_pids([child])
                child_rows.append(
                    {
                        "pid": child,
                        "image": process_image_path(child),
                        "alive": is_pid_alive(child),
                        "top_level_windows": wins[:16],
                    }
                )
            return {
                "debuggee_pid": debuggee_pid,
                "debugger_pid": ctx["debugger_pid"],
                "debuggee_image": process_image_path(debuggee_pid),
                "debuggee_windows": list_windows_for_pids([debuggee_pid]),
                "children": child_rows,
                "child_candidates": probe_child_window_candidates(
                    debuggee_pid, list_windows_fn=None
                ),
                "note": (
                    "Read-only probe; pass allow_child_pids or "
                    "include_same_image_children to interact"
                ),
            }

        return self._ui_call(
            session_id,
            capability="ui.process_tree",
            allow_child_pids=allow_child_pids,
            ensure_running_for_interact=False,
            action=action,
        )

    def ui_tree(
        self,
        session_id: str,
        *,
        allow_child_pids: list[int] | None = None,
        max_depth: int = 3,
        max_nodes: int = 256,
        root_hwnd: int | None = None,
        backend: str = "win32",
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            key = (backend or "win32").strip().casefold()
            if key in {"uia", "uiautomation"}:
                if root_hwnd is None:
                    raise UiPidBoundaryError(
                        "invalid_params",
                        "ui.tree backend=uia requires root_hwnd",
                    )
                tree = build_uia_tree(
                    root_hwnd,
                    allowed,
                    max_depth=max_depth,
                    max_nodes=max_nodes,
                )
                return {
                    "debuggee_pid": ctx["debuggee_pid"],
                    "debugger_pid": ctx["debugger_pid"],
                    "allowed_pids": sorted(allowed),
                    "blocked_pids": sorted(ctx["blocked"]),
                    **tree,
                }
            if root_hwnd is not None:
                roots = [resolve_hwnd(allowed, hwnd=root_hwnd)]
            else:
                roots = list_windows_for_pids(sorted(allowed))
            tree = build_window_tree(
                roots,
                allowed,
                max_depth=max_depth,
                max_nodes=max_nodes,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                "allowed_pids": sorted(allowed),
                "blocked_pids": sorted(ctx["blocked"]),
                **tree,
                "backend": "win32_enum",
                "uia_available": uia_available(),
            }

        return self._ui_call(
            session_id,
            capability="ui.tree",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def ui_resolve(
        self,
        session_id: str,
        *,
        hwnd: int | None = None,
        parent_hwnd: int | None = None,
        class_name: str | None = None,
        title: str | None = None,
        title_contains: str | None = None,
        control_id: int | None = None,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            window = resolve_hwnd(
                allowed,
                hwnd=hwnd,
                parent_hwnd=parent_hwnd,
                class_name=class_name,
                title=title,
                title_contains=title_contains,
                control_id=control_id,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                "window": window,
                "backend": "win32_enum",
            }

        return self._ui_call(
            session_id,
            capability="ui.resolve",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def ui_click(
        self,
        session_id: str,
        hwnd: int,
        *,
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        backend: str = "win32",
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            key = (backend or "win32").strip().casefold()
            if key in {"uia", "uiautomation"}:
                result = click_hwnd_uia(hwnd, allowed)
            elif key in {"sendinput", "input"}:
                result = click_hwnd_sendinput(hwnd, allowed)
            else:
                result = click_hwnd(hwnd, allowed, timeout_ms=timeout_ms)
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.click",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def ui_click_at(
        self,
        session_id: str,
        hwnd: int,
        x: int,
        y: int,
        *,
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        include_same_image_children: bool = False,
    ) -> Result[JsonObject]:
        """Background client-area click (PostMessage); does not steal foreground."""

        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            result = click_hwnd_at(
                hwnd, allowed, x=x, y=y, timeout_ms=timeout_ms
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.click_at",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def ui_window_close(
        self,
        session_id: str,
        hwnd: int,
        *,
        method: str = "nc_close",
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        include_same_image_children: bool = False,
    ) -> Result[JsonObject]:
        """Close window via posted NC-click/WM_CLOSE; never SetForegroundWindow."""

        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            result = close_hwnd(
                hwnd, allowed, method=method, timeout_ms=timeout_ms
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.window.close",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def ui_text_set(
        self,
        session_id: str,
        hwnd: int,
        text: str,
        *,
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        backend: str = "win32",
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            key = (backend or "win32").strip().casefold()
            if key in {"uia", "uiautomation"}:
                result = set_value_uia(hwnd, text, allowed)
            else:
                result = set_window_text(hwnd, text, allowed, timeout_ms=timeout_ms)
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.text.set",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def ui_key(
        self,
        session_id: str,
        hwnd: int,
        *,
        text: str | None = None,
        vk: int | None = None,
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        backend: str = "win32",
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            key = (backend or "win32").strip().casefold()
            if key in {"sendinput", "input"}:
                result = send_key_sendinput(
                    hwnd,
                    allowed_pids=allowed,
                    text=text,
                    vk=vk,
                )
            else:
                result = send_key(
                    hwnd,
                    allowed_pids=allowed,
                    text=text,
                    vk=vk,
                    timeout_ms=timeout_ms,
                )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.key",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def ui_invoke(
        self,
        session_id: str,
        hwnd: int,
        *,
        action_name: str = "click",
        text: str | None = None,
        control_id: int | None = None,
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            result = invoke_hwnd(
                hwnd,
                allowed,
                action=action_name,
                text=text,
                control_id=control_id,
                timeout_ms=timeout_ms,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.invoke",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def ui_wait(
        self,
        session_id: str,
        *,
        timeout: float = 10.0,
        poll_interval: float = 0.1,
        class_name: str | None = None,
        title: str | None = None,
        title_contains: str | None = None,
        control_id: int | None = None,
        parent_hwnd: int | None = None,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            result = wait_for_window(
                allowed,
                timeout=timeout,
                poll_interval=poll_interval,
                class_name=class_name,
                title=title,
                title_contains=title_contains,
                control_id=control_id,
                parent_hwnd=parent_hwnd,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
                "backend": "win32_poll",
            }

        return self._ui_call(
            session_id,
            capability="ui.wait",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def ui_screenshot(
        self,
        session_id: str,
        hwnd: int,
        *,
        allow_child_pids: list[int] | None = None,
        client_only: bool = False,
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        """Capture a PID-bounded hwnd to a BMP under artifact_root/ui/<session>."""
        directory = self.settings.artifact_root.expanduser().resolve() / "ui" / session_id
        directory.mkdir(parents=True, exist_ok=True)
        artifact_path = directory / f"screenshot-{uuid4().hex}.bmp"

        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            result = capture_hwnd_screenshot(
                hwnd,
                allowed,
                artifact_path,
                client_only=client_only,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                "allowed_pids": sorted(allowed),
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.screenshot",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def ui_ocr(
        self,
        session_id: str,
        hwnd: int,
        *,
        allow_child_pids: list[int] | None = None,
        backend: str = "auto",
        language: str = "en-US",
        client_only: bool = False,
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        """OCR a PID-bounded hwnd via screenshot + Windows OCR / tesseract."""
        directory = self.settings.artifact_root.expanduser().resolve() / "ui" / session_id
        directory.mkdir(parents=True, exist_ok=True)
        artifact_path = directory / f"ocr-{uuid4().hex}.bmp"

        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            result = ocr_hwnd(
                hwnd,
                allowed,
                artifact_path,
                backend=backend,
                language=language,
                client_only=client_only,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                "allowed_pids": sorted(allowed),
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.ocr",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )

    def _ui_call(
        self,
        session_id: str,
        *,
        capability: str,
        allow_child_pids: list[int] | None,
        action: Callable[[JsonObject], JsonObject],
        finalize: Callable[[JsonObject, JsonObject], JsonObject] | None = None,
        include_same_image_children: bool = False,
        ensure_running_for_interact: bool = True,
    ) -> Result[JsonObject]:
        if os.name != "nt":
            return _failure(
                XdbgRpcError(
                    "capability_unavailable",
                    f"{capability} requires Windows",
                    details={"capability": capability},
                ),
                session_id=session_id,
            )
        _INTERACT = {
            "ui.click",
            "ui.click_at",
            "ui.window.close",
            "ui.text.set",
            "ui.key",
            "ui.invoke",
            "ui.drive_to_event",
            "ui.drive_to_breakpoint",
        }
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                if "debug.state" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide debug.state",
                        details={"capability": "debug.state"},
                    )
                state = runtime.worker.request("debug.state", {})
                self._observe_debuggee_state(session_id, state)
                annotated = self._annotate_debuggee_pids(session_id, dict(state))
                debuggee_pid = annotated.get("debuggee_pid")
                debugger_pid = annotated.get("debugger_pid")
                if not isinstance(debuggee_pid, int) or debuggee_pid <= 0:
                    raise XdbgRpcError(
                        "invalid_state",
                        "no active debuggee; refuse UI automation",
                        details={
                            "process_id": annotated.get("process_id"),
                            "debuggee_pid": debuggee_pid,
                            "capability": capability,
                        },
                    )
                # Interact needs a live message pump; resume when paused.
                # Keep the wait short: PostMessage clicks only need the pump alive,
                # not a long running-state barrier (old 15s wait dominated UI latency).
                if (
                    ensure_running_for_interact
                    and capability in _INTERACT
                    and annotated.get("state") == "paused"
                    and "debug.resume" in runtime.worker.capabilities
                ):
                    runtime.worker.request("debug.resume", {}, timeout=5.0)
                    dynamic = cast(DynamicWorker, runtime.worker)
                    try:
                        running_state = dynamic.wait_for_state({"running"}, timeout=2.0)
                        self._observe_debuggee_state(session_id, running_state)
                        annotated = self._annotate_debuggee_pids(session_id, dict(running_state))
                        debuggee_pid = annotated.get("debuggee_pid") or debuggee_pid
                        debugger_pid = annotated.get("debugger_pid") or debugger_pid
                    except XdbgRpcError as exc:
                        # Still paused (e.g. immediate rebreak) — continue; click uses PostMessage.
                        if exc.code not in {"timeout", "wait_timeout", "debug_state_timeout"}:
                            raise XdbgRpcError(
                                "resume_failed",
                                f"failed to resume debuggee before {capability}: {exc}",
                                details={"capability": capability, "cause": exc.code},
                            ) from exc
                        state = runtime.worker.request("debug.state", {})
                        self._observe_debuggee_state(session_id, state)
                        annotated = self._annotate_debuggee_pids(session_id, dict(state))
                        debuggee_pid = annotated.get("debuggee_pid") or debuggee_pid
                        debugger_pid = annotated.get("debugger_pid") or debugger_pid
                try:
                    allowed, blocked = resolve_allowed_ui_pids(
                        debuggee_pid=int(debuggee_pid),
                        debugger_pid=(debugger_pid if isinstance(debugger_pid, int) else None),
                        allow_child_pids=allow_child_pids or (),
                        include_same_image_children=include_same_image_children,
                    )
                except UiPidBoundaryError as exc:
                    raise XdbgRpcError(exc.code, exc.message, details=dict(exc.details)) from exc
                ctx: JsonObject = {
                    "debuggee_pid": debuggee_pid,
                    "debugger_pid": debugger_pid,
                    "allowed": allowed,
                    "blocked": blocked,
                    "include_same_image_children": include_same_image_children,
                }
                try:
                    payload = action(ctx)
                except UiPidBoundaryError as exc:
                    details = dict(exc.details)
                    details.setdefault("debuggee_pid", debuggee_pid)
                    details.setdefault("allowed_pids", sorted(allowed))
                    raise XdbgRpcError(exc.code, exc.message, details=details) from exc
                if finalize is not None:
                    payload = finalize(payload, ctx)
                return _success(
                    payload,
                    session_id=session_id,
                    backend=BackendKind.X64DBG.value,
                    capability=capability,
                )
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def dynamic_events(
        self,
        session_id: str,
        *,
        limit: int = DEFAULT_DEBUG_EVENT_BATCH,
        timeout: float = 10.0,
    ) -> Result[JsonObject]:
        if type(limit) is not int or not 1 <= limit <= MAX_DEBUG_EVENT_BATCH:
            return _failure(
                ValueError(f"limit must be between 1 and {MAX_DEBUG_EVENT_BATCH}"),
                session_id=session_id,
            )
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not isfinite(timeout)
            or not 0 < timeout <= 30.0
        ):
            return _failure(
                ValueError("timeout must be greater than 0 and at most 30 seconds"),
                session_id=session_id,
            )
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                if "events.read" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide events.read",
                        details={"capability": "events.read"},
                    )
                cursor = runtime.event_cursor
                drain_cursor = runtime.drain_cursor
                event_log = runtime.event_log
                if cursor is None or drain_cursor is None or event_log is None:
                    raise XdbgRpcError(
                        "rpc_protocol_error",
                        "dynamic runtime has no durable event log",
                    )
                dynamic = cast(DynamicWorker, runtime.worker)
                # Catch up durable log from the native ring (short polls).
                drain_native_into_log(
                    dynamic,
                    drain_cursor,
                    event_log,
                    timeout=0.05,
                    max_rounds=64,
                )
                served = event_log.read_after(cursor.value, limit=limit)
                if not served.batch.events and not served.unrecovered_gap:
                    # Long-poll once for new native events, then serve from log.
                    drain_native_into_log(
                        dynamic,
                        drain_cursor,
                        event_log,
                        timeout=float(timeout),
                        max_rounds=1,
                    )
                    served = event_log.read_after(cursor.value, limit=limit)
                batch = served.batch
                try:
                    cursor.advance(batch)
                except DebugEventProtocolError as exc:
                    raise XdbgRpcError(
                        "rpc_protocol_error",
                        f"x64dbg event cursor is inconsistent: {exc}",
                    ) from exc
                self._consume_workflow_batch_locked(
                    session_id,
                    runtime,
                    batch,
                    # ``timeout`` bounds the native events.read long-poll.  A UI
                    # burst peek may intentionally use 50 ms, but consuming the
                    # resulting breakpoint event can require a bounded
                    # ensure-paused transition.  Reusing the peek timeout made
                    # that transition fail reliably under full-suite load.
                    timeout=max(5.0, float(timeout)),
                )
                if batch.dropped > 0 or served.unrecovered_gap:
                    runtime.snapshot_resync_required = True
                workflow_id = self._require_workflow(session_id).id
                payload = batch.to_dict()
                payload["durable_log"] = True
                payload["replayed_from_store"] = bool(batch.events) and batch.dropped == 0
                payload["unrecovered_gap"] = served.unrecovered_gap
            result = _success(
                payload,
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
                workflow_id=workflow_id,
            )
            if result.ok and result.data:
                events = result.data.get("events") or []
                # Timeline mirror remains opt-in; durable sqlite log is always on.
                if bool(getattr(self.settings, "persist_debug_events", False)):
                    for event in events[:_DEBUG_EVENT_BUDGET_PER_BATCH]:
                        if not isinstance(event, dict):
                            continue
                        _timeline_append(
                            self,
                            session_id,
                            "debug.event",
                            str(event.get("kind") or "event"),
                            kind=event.get("kind"),
                            data=event.get("data") if isinstance(event.get("data"), dict) else {},
                        )
            return result
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def dynamic_wait(
        self,
        session_id: str,
        state: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if state not in {"idle", "running", "paused"}:
            return _failure(
                ValueError("state must be idle, running, or paused"),
                session_id=session_id,
            )
        return self._dynamic_request(
            session_id,
            "debug.state",
            wait_for={state},
            timeout=timeout,
        )

    def dynamic_launch(
        self,
        session_id: str,
        *,
        arguments: str = "",
        working_directory: str | None = None,
        timeout: float = 30.0,
        pass_system_breakpoint: bool = False,
    ) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)
        params: JsonObject = {"path": str(session.binary)}
        if arguments:
            params["arguments"] = arguments
        if working_directory is not None:
            params["working_directory"] = working_directory
        launched = self._dynamic_request(
            session_id,
            "debug.launch",
            params,
            wait_for={"paused"},
            timeout=timeout,
        )
        if not launched.ok or not pass_system_breakpoint:
            if launched.ok and launched.data is not None:
                data = dict(launched.data)
                data["pass_system_breakpoint"] = False
                return _success(data, session_id=session_id, backend=BackendKind.X64DBG.value)
            return launched
        # First pause is typically the system/entry breakpoint; resume once so
        # unpack workflows can continue toward UI/OEP without manual stepping.
        resumed = self._dynamic_request(
            session_id,
            "debug.resume",
            wait_for={"paused", "running"},
            timeout=timeout,
        )
        if not resumed.ok or resumed.data is None:
            return resumed
        data = dict(resumed.data)
        data["pass_system_breakpoint"] = True
        data["note"] = (
            "Resumed once after initial pause (system/entry breakpoint); "
            "not a guarantee that packer anti-debug or TLS was skipped."
        )
        return _success(data, session_id=session_id, backend=BackendKind.X64DBG.value)

    def dynamic_attach(
        self,
        session_id: str,
        pid: int,
        *,
        timeout: float = 30.0,
        pause_after_attach: bool = False,
    ) -> Result[JsonObject]:
        """Attach to a live process.

        By default accepts either paused or running after attach (GUI-friendly).
        Set ``pause_after_attach=True`` only when the caller needs a stopped target.
        """
        if type(pid) is not int or pid <= 0:
            return _failure(ValueError("pid must be a positive integer"), session_id=session_id)
        if not is_pid_alive(pid):
            return _failure(
                XdbgRpcError(
                    "not_found",
                    "target pid is not alive",
                    details={"pid": pid},
                ),
                session_id=session_id,
            )
        wait_for = {"paused"} if pause_after_attach else {"paused", "running"}
        result = self._dynamic_request(
            session_id,
            "debug.attach",
            {"pid": pid},
            wait_for=wait_for,
            timeout=timeout,
        )
        if not result.ok or result.data is None:
            return result
        if pause_after_attach:
            state = result.data.get("state") if isinstance(result.data, dict) else None
            if isinstance(state, dict) and state.get("state") == "running":
                paused = self.dynamic_pause(session_id, timeout=min(15.0, timeout))
                if not paused.ok:
                    return paused
                result = _success(
                    {"submitted": result.data.get("submitted"), "state": paused.data},
                    session_id=session_id,
                    backend=BackendKind.X64DBG.value,
                )
        # Attach UX: surface child-window hints without granting UI rights.
        annotated: JsonObject = (
            dict(result.data) if isinstance(result.data, dict) else {"state": result.data}
        )
        try:
            from headless_re_mcp.core.process_tree import probe_child_window_candidates

            debuggee = pid
            state_obj = annotated.get("state")
            if isinstance(state_obj, dict):
                proc = state_obj.get("process_id") or state_obj.get("debuggee_pid")
                if isinstance(proc, int) and proc > 0:
                    debuggee = proc
            children = probe_child_window_candidates(debuggee, list_windows_fn=None)
            if children:
                annotated["child_windows_hint"] = "windows_on_child_pids"
                annotated["suggested_child_pids"] = [int(c["pid"]) for c in children]
                annotated["child_candidates"] = children
        except Exception:
            pass
        return _success(
            annotated,
            session_id=session_id,
            backend=BackendKind.X64DBG.value,
        )

    def dynamic_stop(
        self,
        session_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "debug.stop",
            wait_for={"idle"},
            timeout=timeout,
        )

    def dynamic_pause(
        self,
        session_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "debug.pause",
            wait_for={"paused"},
            timeout=timeout,
        )

    def dynamic_resume(
        self,
        session_id: str,
        *,
        wait_for_pause: bool = False,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "debug.resume",
            wait_for={"paused", "idle"} if wait_for_pause else None,
            timeout=timeout,
        )

    def dynamic_step_into(
        self,
        session_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "debug.step_into",
            wait_for={"paused", "idle"},
            timeout=timeout,
        )

    def dynamic_step_over(
        self,
        session_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "debug.step_over",
            wait_for={"paused", "idle"},
            timeout=timeout,
        )

    def dynamic_registers_read(self, session_id: str) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "registers.read")

    def dynamic_register_write(
        self,
        session_id: str,
        name: str,
        value: int,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "registers.write",
            {"name": name, "value": value},
        )

    def dynamic_memory_read(
        self,
        session_id: str,
        address: int,
        size: int,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "memory.read",
            {"address": address, "size": size},
        )

    def dynamic_memory_write(
        self,
        session_id: str,
        address: int,
        data: str,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "memory.write",
            {"address": address, "data": data},
        )

    def memory_regions(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Return a paused-only page of VirtualQuery-style memory regions."""
        if type(offset) is not int or offset < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="offset must be a non-negative integer",
                ),
            )
        params: JsonObject = {"offset": offset}
        if limit is not None:
            if type(limit) is not int or limit <= 0:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="limit must be a positive integer",
                    ),
                )
            params["limit"] = limit
        return self._dynamic_request(
            session_id,
            "memory.regions",
            params,
            timeout=timeout,
        )

    def memory_protect_query(
        self,
        session_id: str,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Return the memory region containing ``address`` (paused-only)."""
        if type(address) is not int or address < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="address must be a non-negative integer",
                ),
            )
        return self._dynamic_request(
            session_id,
            "memory.protect.query",
            {"address": address},
            timeout=timeout,
        )

    def memory_protection(
        self,
        session_id: str,
        address: int,
        *,
        rights: str | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Query or set page rights (alias of protect.query + optional SetPageRights)."""
        if type(address) is not int or address < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="address must be a non-negative integer",
                ),
            )
        params: JsonObject = {"address": address}
        if rights is not None:
            if not isinstance(rights, str) or not rights:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="rights must be a non-empty string",
                    ),
                )
            params["rights"] = rights
        return self._dynamic_request(
            session_id,
            "memory.protection",
            params,
            timeout=timeout,
        )

    def threads_list(self, session_id: str, *, timeout: float = 30.0) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "threads.list", timeout=timeout)

    def threads_current(self, session_id: str, *, timeout: float = 30.0) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "threads.current", timeout=timeout)

    def threads_context_read(
        self,
        session_id: str,
        tid: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(tid) is not int or tid <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="tid must be a positive integer"),
            )
        return self._dynamic_request(
            session_id,
            "threads.context.read",
            {"tid": tid},
            timeout=timeout,
        )

    def threads_context_write(
        self,
        session_id: str,
        tid: int,
        name: str,
        value: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(tid) is not int or tid <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="tid must be a positive integer"),
            )
        return self._dynamic_request(
            session_id,
            "threads.context.write",
            {"tid": tid, "name": name, "value": value},
            timeout=timeout,
        )

    def stack_read(
        self,
        session_id: str,
        *,
        address: int | None = None,
        count: int = 32,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(count) is not int or not 1 <= count <= 256:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="count must be 1..256"),
            )
        params: JsonObject = {"count": count}
        if address is not None:
            if type(address) is not int or address < 0:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="address must be a non-negative integer",
                    ),
                )
            params["address"] = address
        return self._dynamic_request(session_id, "stack.read", params, timeout=timeout)

    def stack_trace(
        self,
        session_id: str,
        *,
        limit: int = 256,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(limit) is not int or not 1 <= limit <= 256:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="limit must be 1..256"),
            )
        return self._dynamic_request(
            session_id,
            "stack.trace",
            {"limit": limit},
            timeout=timeout,
        )

    def disassembly_read(
        self,
        session_id: str,
        address: int,
        *,
        count: int = 32,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(address) is not int or address < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="address must be a non-negative integer",
                ),
            )
        if type(count) is not int or not 1 <= count <= 256:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="count must be 1..256"),
            )
        return self._dynamic_request(
            session_id,
            "disassembly.read",
            {"address": address, "count": count},
            timeout=timeout,
        )

    def symbols_list(
        self,
        session_id: str,
        module_base: int,
        *,
        limit: int = 256,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(module_base) is not int or module_base <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="module_base must be a positive integer",
                ),
            )
        if type(limit) is not int or not 1 <= limit <= 4096:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="limit must be 1..4096"),
            )
        return self._dynamic_request(
            session_id,
            "symbols.list",
            {"module_base": module_base, "limit": limit},
            timeout=timeout,
        )

    def symbols_resolve(
        self,
        session_id: str,
        expression: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if not isinstance(expression, str) or not expression:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="expression must be a non-empty string",
                ),
            )
        return self._dynamic_request(
            session_id,
            "symbols.resolve",
            {"expression": expression},
            timeout=timeout,
        )

    def modules_dump(
        self,
        session_id: str,
        base: int,
        *,
        size: int | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Dump one loaded module image range into a session artifact (paused-only)."""
        if type(base) is not int or base <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="base must be a positive integer"),
            )
        if size is not None and (type(size) is not int or size <= 0):
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="size must be a positive integer"),
            )
        if size is not None and size > _MAX_MODULE_DUMP_BYTES:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="dump_too_large",
                    message="requested dump exceeds the configured maximum",
                    details={
                        "size": size,
                        "max_dump_bytes": _MAX_MODULE_DUMP_BYTES,
                    },
                ),
            )
        output_path: Path | None = None
        try:
            if not session_id or Path(session_id).name != session_id:
                raise ValueError("invalid session id for artifact path")
            directory = self.settings.artifact_root.expanduser().resolve() / "dump" / session_id
            directory.mkdir(parents=True, exist_ok=True)
            output_path = directory / f"dumped-module-{base:x}-{uuid4().hex}.bin"
            params: JsonObject = {
                "base": base,
                "output_path": str(output_path),
            }
            if size is not None:
                params["size"] = size
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                self._require_snapshot_fresh_locked(runtime, operation="modules.dump")
                if "modules.dump" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide modules.dump",
                        details={"capability": "modules.dump"},
                    )
                if "modules.list" in runtime.worker.capabilities:
                    before = runtime.worker.request("modules.list", timeout=min(timeout, 30.0))
                    if not _module_base_present(before, base):
                        raise XdbgRpcError(
                            "module_not_found",
                            "module is not loaded at the requested base (pre-dump)",
                            details={"base": base, "race": "pre_dump"},
                            retryable=True,
                        )
                dumped = runtime.worker.request(
                    "modules.dump",
                    params,
                    timeout=min(timeout, 30.0),
                )
                if "modules.list" in runtime.worker.capabilities:
                    after = runtime.worker.request("modules.list", timeout=min(timeout, 30.0))
                    if not _module_base_present(after, base):
                        with suppress(OSError):
                            output_path.unlink(missing_ok=True)
                        raise XdbgRpcError(
                            "module_unloaded_during_dump",
                            "module disappeared while dumping; re-read modules.list",
                            details={"base": base, "race": "post_dump"},
                            retryable=True,
                        )
            data = dict(dumped)
            resolved = Path(str(data.get("output_path", output_path)))
            if not resolved.is_file():
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="artifact_missing",
                        message="modules.dump did not produce the expected artifact file",
                        details={"output_path": str(resolved)},
                    ),
                )
            data["output_path"] = str(resolved)
            data["sha256"] = file_sha256(resolved)
            data["artifact_kind"] = "module_dump"
            data["stage_label"] = STAGE_DUMPED
            data["stage_note"] = (
                "dumped only; UI-visible debuggee does not upgrade to iat-rebuilt/runnable"
            )
            path = data.get("output_path")
            sha = data.get("sha256")
            if isinstance(path, str) and isinstance(sha, str):
                art = self.repository.register_artifact(
                    session_id=session_id,
                    kind=str(data.get("artifact_kind") or "module_dump"),
                    path=path,
                    sha256=sha,
                    source="modules.dump",
                )
                data["artifact_id"] = art["id"]
                _timeline_append(
                    self,
                    session_id,
                    "artifact.registered",
                    "module dump registered",
                    artifact_id=art["id"],
                )
            return _success(data, session_id=session_id, backend=BackendKind.X64DBG.value)
        except XdbgRpcError as exc:
            if output_path is not None:
                with suppress(OSError):
                    output_path.unlink(missing_ok=True)
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            if output_path is not None:
                with suppress(OSError):
                    output_path.unlink(missing_ok=True)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def pe_headers_runtime(
        self,
        session_id: str,
        base: int,
        *,
        save_artifact: bool = True,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Read paused-only runtime PE headers; optionally preserve a header artifact."""
        if type(base) is not int or base <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="base must be a positive integer"),
            )
        try:
            params: JsonObject = {"base": base}
            header_path: Path | None = None
            if save_artifact:
                if not session_id or Path(session_id).name != session_id:
                    raise ValueError("invalid session id for artifact path")
                directory = self.settings.artifact_root.expanduser().resolve() / "dump" / session_id
                directory.mkdir(parents=True, exist_ok=True)
                header_path = directory / f"pe-headers-{base:x}-{uuid4().hex}.bin"
                params["output_path"] = str(header_path)
            result = self._dynamic_request(
                session_id,
                "pe.headers.runtime",
                params,
                timeout=timeout,
            )
            if result.ok and result.data is not None and header_path is not None:
                data = dict(result.data)
                if header_path.is_file():
                    data["header_artifact"] = str(header_path)
                    data["header_sha256"] = file_sha256(header_path)
                return Result[JsonObject](ok=True, data=data, meta=result.meta)
            if (
                not result.ok
                and result.error is not None
                and result.error.code in {"method_not_found", "capability_unavailable"}
            ):
                # Fallback: memory.read + Python parser (pre-rebuild native binary).
                read = self.dynamic_memory_read(session_id, base, 0x1000)
                if not read.ok or read.data is None:
                    return result
                hex_data = str(read.data.get("data", ""))
                try:
                    image = bytes.fromhex(hex_data)
                    headers = parse_runtime_headers(image)
                except (ValueError, PeRebuildError) as exc:
                    return Result[JsonObject](
                        ok=False,
                        error=RpcError(
                            code="invalid_pe",
                            message=str(exc),
                        ),
                        meta=read.meta,
                    )
                headers["base"] = base
                headers["source"] = "memory.read_fallback"
                if save_artifact and header_path is not None:
                    header_end = int(headers.get("header_bytes", min(len(image), 0x1000)))
                    _atomic_write_bytes(header_path, image[:header_end])
                    headers["header_artifact"] = str(header_path)
                    headers["header_sha256"] = file_sha256(header_path)
                return _success(headers, session_id=session_id, backend=BackendKind.X64DBG.value)
            return result
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def imports_scan(
        self,
        session_id: str,
        module_base: int,
        *,
        search_start: int | None = None,
        search_size: int | None = None,
        max_candidates: int = 8,
        mode: str = "all",
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Scan for candidate IAT ranges; never auto-selects a single winner."""
        if type(module_base) is not int or module_base <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="module_base must be a positive integer",
                ),
            )
        if mode not in {"all", "consecutive", "sparse", "call_site"}:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="mode must be consecutive|sparse|call_site|all",
                ),
            )
        params: JsonObject = {
            "module_base": module_base,
            "max_candidates": max_candidates,
            "mode": mode,
        }
        if search_start is not None:
            params["search_start"] = search_start
        if search_size is not None:
            params["search_size"] = search_size
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                self._require_snapshot_fresh_locked(runtime, operation="imports.scan")
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        return self._dynamic_request(
            session_id,
            "imports.scan",
            params,
            timeout=timeout,
        )

    def imports_read(
        self,
        session_id: str,
        iat_va: int,
        size: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Read one caller-confirmed IAT range and resolve thunks against exports."""
        if type(iat_va) is not int or iat_va <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="iat_va must be a positive integer"),
            )
        if type(size) is not int or size <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="size must be a positive integer"),
            )
        return self._dynamic_request(
            session_id,
            "imports.read",
            {"iat_va": iat_va, "size": size},
            timeout=timeout,
        )

    def unpack_dump_module(
        self,
        session_id: str,
        base: int,
        *,
        size: int | None = None,
        save_headers: bool = True,
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Dump a module by runtime size and optionally preserve PE headers."""
        blocked = self._guard_unpack_active(session_id, stage="dump_module")
        if blocked is not None:
            return blocked
        dumped = self.modules_dump(session_id, base, size=size, timeout=timeout)
        if not dumped.ok or dumped.data is None:
            return dumped
        blocked = self._guard_unpack_active(session_id, stage="dump_module_headers")
        if blocked is not None:
            # Dump file may already exist; retain it, do not advance phase.
            payload = dict(dumped.data)
            payload["claims_universal_unpack"] = False
            payload["aborted_after_dump"] = True
            payload["partial_artifacts_retained"] = True
            payload["safe_rollback"] = False
            return Result[JsonObject](
                ok=False,
                error=blocked.error,
                data=payload,
                meta=blocked.meta,
            )
        payload = dict(dumped.data)
        payload["claims_universal_unpack"] = False
        if save_headers:
            headers = self.pe_headers_runtime(
                session_id,
                base,
                save_artifact=True,
                timeout=timeout,
            )
            payload["headers"] = headers.data if headers.ok else None
            payload["headers_ok"] = headers.ok
            if not headers.ok and headers.error is not None:
                payload["headers_error"] = headers.error.model_dump()
        blocked = self._guard_unpack_active(session_id, stage="dump_module_advance")
        if blocked is not None:
            payload["aborted_before_phase_advance"] = True
            payload["partial_artifacts_retained"] = True
            payload["safe_rollback"] = False
            return Result[JsonObject](
                ok=False,
                error=blocked.error,
                data=payload,
                meta=blocked.meta,
            )
        output_path = str(payload.get("output_path", "") or "")
        output_sha = str(payload.get("sha256", "") or "")
        if output_path and output_sha:
            self._advance_unpack_after_dump(
                session_id,
                path=output_path,
                sha256=output_sha,
            )
        return _success(payload, session_id=session_id, backend="unpack")

    def unpack_stub_coupling(
        self,
        session_id: str,
        dump_path: str,
        *,
        iat_va: int | None = None,
        iat_size: int | None = None,
        module_base: int | None = None,
    ) -> Result[JsonObject]:
        """Analyze a dump for E8→VMP stub coupling vs FF15/FF25 API sites (MCP-facing)."""
        try:
            blocked = self._guard_unpack_active(session_id, stage="stub_coupling")
            if blocked is not None:
                return blocked
            path = Path(dump_path).expanduser().resolve(strict=True)
            artifact_root = self.settings.artifact_root.expanduser().resolve()
            if artifact_root not in path.parents and path.parent != artifact_root:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="dump_path must be inside the session artifact root",
                        details={"dump_path": str(path), "artifact_root": str(artifact_root)},
                    ),
                )
            coupling = analyze_dump_stub_coupling(
                path,
                iat_va=iat_va,
                iat_size=iat_size,
                image_base=module_base,
            )
            analysis_gate = None
            pause = None
            if coupling.get("ok"):
                still = coupling.get("still_vm_stub_count")
                still_i = int(still) if isinstance(still, int) else None
                # Layout-less gate from stub stats alone for recoverability hint.
                fake_layout = {
                    "api_count": int(coupling.get("api_call_site_count") or 0),
                    "layout": "fragmented",
                    "ime_dominated": False,
                    "rebuild_allowed": False,
                    "rebuild_block_reason": "stub_coupling_only",
                }
                analysis_gate = gate_iat_rebuild(
                    fake_layout,
                    still_vm_stub_count=still_i,
                    min_api=0,
                )
                pause = assess_pause_quality(
                    ui_visible=None,
                    layout="fragmented",
                    rebuild_allowed=False,
                    recoverability=str(analysis_gate.get("recoverability") or ""),
                    still_vm_stub_count=still_i,
                    api_call_site_count=int(coupling.get("api_call_site_count") or 0),
                    code_nonzero_ratio=(
                        float(coupling["code_nonzero_ratio"])
                        if isinstance(coupling.get("code_nonzero_ratio"), (int, float))
                        else None
                    ),
                )
            payload: JsonObject = {
                "stub_coupling": coupling,
                "rebuild_gate_hint": analysis_gate,
                "pause_quality": pause,
                "stage_label": STAGE_DUMPED,
                "claims_universal_unpack": False,
                "note": (
                    "E8→VMP dominance implies vm_coupled_dump_only; "
                    "IAT rebuild alone cannot produce runnable PE"
                ),
            }
            return _success(payload, session_id=session_id, backend="unpack")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def unpack_iat_scan(
        self,
        session_id: str,
        module_base: int,
        *,
        search_start: int | None = None,
        search_size: int | None = None,
        max_candidates: int = 8,
        mode: str = "all",
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """MCP-facing IAT candidate scan; caller must confirm before rebuild."""
        blocked = self._guard_unpack_active(session_id, stage="iat_scan")
        if blocked is not None:
            return blocked
        scanned = self.imports_scan(
            session_id,
            module_base,
            search_start=search_start,
            search_size=search_size,
            max_candidates=max(max_candidates * 3, 24),
            mode=mode,
            timeout=timeout,
        )
        if not scanned.ok or scanned.data is None:
            return scanned
        data = dict(scanned.data)
        raw_candidates = data.get("candidates")
        if not isinstance(raw_candidates, list):
            raw_candidates = []
        # Ask native for a wider pool then rank/dedupe locally.
        ranked = rank_iat_candidates(
            raw_candidates,
            module_base=module_base,
            module_size=int(data["module_size"])
            if isinstance(data.get("module_size"), int)
            else None,
            max_candidates=max_candidates,
        )
        data["raw_candidates"] = raw_candidates
        data["candidates"] = ranked["candidates"]
        data["candidate_count"] = ranked["candidate_count"]
        data["raw_candidate_count"] = ranked["raw_candidate_count"]
        data["best"] = ranked.get("best")
        data["confirmed"] = False
        data["claims_universal_unpack"] = False
        data["blind_selection"] = False
        data["next"] = (
            "Caller must confirm one candidate via unpack.iat.validate "
            "(iat_va, size, optional oep_rva) before rebuild. "
            "IME/high-RVA noise is down-ranked; half-sparse layouts need validate."
        )
        return _success(data, session_id=session_id, backend="unpack")

    def unpack_iat_validate(
        self,
        session_id: str,
        *,
        iat_va: int,
        size: int,
        oep_rva: int | None = None,
        module_base: int | None = None,
        dump_path: str | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Validate a caller-confirmed IAT range and optionally record OEP RVA."""
        blocked = self._guard_unpack_active(session_id, stage="iat_validate")
        if blocked is not None:
            return blocked
        read = self.imports_read(session_id, iat_va, size, timeout=timeout)
        if not read.ok or read.data is None:
            return read
        data = dict(read.data)
        entries = data.get("entries")
        if not isinstance(entries, list):
            entries = []
        pointer_size = (
            8
            if any(
                isinstance(item, dict) and int(item.get("value") or 0) > 0xFFFFFFFF
                for item in entries[:8]
            )
            else 4
        )
        analysis = analyze_import_entries(entries, pointer_size=pointer_size)
        stub_coupling: JsonObject | None = None
        still_vm_stub_count: int | None = None
        if dump_path:
            dump = Path(dump_path).expanduser().resolve()
            artifact_root = self.settings.artifact_root.expanduser().resolve()
            if artifact_root not in dump.parents and dump.parent != artifact_root:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="dump_path must be inside the session artifact root",
                        details={"dump_path": str(dump), "artifact_root": str(artifact_root)},
                    ),
                )
            if not dump.is_file():
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="dump_path does not exist",
                        details={"dump_path": str(dump)},
                    ),
                )
            stub_coupling = analyze_dump_stub_coupling(
                dump,
                iat_va=iat_va,
                iat_size=size,
                image_base=module_base,
            )
            if stub_coupling.get("ok") and isinstance(
                stub_coupling.get("still_vm_stub_count"), int
            ):
                still_vm_stub_count = int(stub_coupling["still_vm_stub_count"])
        gate = gate_iat_rebuild(analysis, still_vm_stub_count=still_vm_stub_count)
        code_nonzero_ratio = None
        if isinstance(stub_coupling, dict) and isinstance(
            stub_coupling.get("code_nonzero_ratio"), (int, float)
        ):
            code_nonzero_ratio = float(stub_coupling["code_nonzero_ratio"])
        pause = assess_pause_quality(
            ui_visible=None,
            layout=str(analysis.get("layout") or ""),
            rebuild_allowed=bool(gate.get("rebuild_allowed")),
            recoverability=str(gate.get("recoverability") or ""),
            still_vm_stub_count=still_vm_stub_count,
            api_call_site_count=(
                int(stub_coupling["api_call_site_count"])
                if isinstance(stub_coupling, dict)
                and isinstance(stub_coupling.get("api_call_site_count"), int)
                else None
            ),
            resolved_ratio=float(analysis.get("resolved_ratio") or 0.0),
            code_nonzero_ratio=code_nonzero_ratio,
        )
        # Empty/encrypted CODE means pause is not IAT-ready even if layout looks dense.
        if code_nonzero_ratio is not None and code_nonzero_ratio < 0.05:
            gate = dict(gate)
            gate["rebuild_allowed"] = False
            gate["reasons"] = list(gate.get("reasons") or []) + [
                f"code_not_decrypted:nonzero_ratio={code_nonzero_ratio:.4f}"
            ]
            if gate.get("recoverability") == "iat_recoverable":
                gate["recoverability"] = "iat_insufficient"
        stage_gate = gate_stage_upgrade(
            current_stage=STAGE_DUMPED,
            target_stage=STAGE_IAT_REBUILT,
            rebuild_allowed=bool(gate.get("rebuild_allowed")),
            pause_iat_ready=bool(pause.get("iat_ready")),
        )
        resolved = int(analysis.get("api_count") or 0)
        total = int(analysis.get("slot_count") or 0)
        confidence = float(analysis.get("resolved_ratio") or 0.0)
        confirmed = bool(gate.get("rebuild_allowed")) and bool(pause.get("iat_ready"))
        data.update(
            {
                "confirmed": confirmed,
                "oep_rva": oep_rva,
                "module_base": module_base,
                "null_count": analysis.get("null_count"),
                "unresolved_count": analysis.get("unresolved_count"),
                "ordinal_hint_count": 0,
                "confidence": confidence,
                "layout": analysis.get("layout"),
                "layout_analysis": analysis,
                "rebuild_gate": gate,
                "recoverability": gate.get("recoverability"),
                "stub_coupling": stub_coupling,
                "pause_quality": pause,
                "stage_label": STAGE_IAT_REBUILT if confirmed else STAGE_DUMPED,
                "stage_upgrade_gate": stage_gate,
                "forwarded_exports_detected": False,
                "unfixed": [
                    "forwarded exports are not expanded",
                    "caller must still run unpack.iat.rebuild / unpack.pe.rebuild",
                    "UI visible != IAT ready; confirmed requires rebuild+pause gates",
                    *[str(r) for r in (gate.get("reasons") or [])],
                    *[str(r) for r in (pause.get("reasons") or [])],
                ],
                "claims_universal_unpack": False,
                "resolved_count": resolved,
                "slot_count": total,
            }
        )
        if not confirmed:
            data["warnings"] = [
                "rebuild_gate blocked this range; refuse confirmed=true",
            ]
            data["unfixed"] = [
                *data["unfixed"],
                "IAT range not confirmed; rebuild would be speculative",
            ]
        return _success(data, session_id=session_id, backend="unpack")

    def unpack_iat_rebuild(
        self,
        session_id: str,
        dump_path: str,
        *,
        iat_va: int,
        size: int,
        oep_rva: int | None = None,
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Rebuild import tables on a dumped PE using a confirmed IAT range."""
        try:
            blocked = self._guard_unpack_active(session_id, stage="iat_rebuild")
            if blocked is not None:
                return blocked
            path = Path(dump_path).expanduser().resolve(strict=True)
            artifact_root = self.settings.artifact_root.expanduser().resolve()
            if artifact_root not in path.parents and path.parent != artifact_root:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="dump_path must be inside the session artifact root",
                        details={"dump_path": str(path), "artifact_root": str(artifact_root)},
                    ),
                )
            read = self.imports_read(session_id, iat_va, size, timeout=timeout)
            if not read.ok or read.data is None:
                return read
            blocked = self._guard_unpack_active(session_id, stage="iat_rebuild_write")
            if blocked is not None:
                return blocked
            entries = read.data.get("entries")
            if not isinstance(entries, list):
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(code="invalid_iat", message="imports.read returned no entries"),
                )
            analysis = analyze_import_entries(entries)
            stub_coupling = analyze_dump_stub_coupling(
                path,
                iat_va=iat_va,
                iat_size=size,
            )
            still_vm_stub_count = (
                int(stub_coupling["still_vm_stub_count"])
                if stub_coupling.get("ok")
                and isinstance(stub_coupling.get("still_vm_stub_count"), int)
                else None
            )
            gate = gate_iat_rebuild(analysis, still_vm_stub_count=still_vm_stub_count)
            code_ratio = stub_coupling.get("code_nonzero_ratio")
            if isinstance(code_ratio, (int, float)) and float(code_ratio) < 0.05:
                gate = dict(gate)
                gate["rebuild_allowed"] = False
                gate["reasons"] = list(gate.get("reasons") or []) + [
                    f"code_not_decrypted:nonzero_ratio={float(code_ratio):.4f}"
                ]
                if gate.get("recoverability") == "iat_recoverable":
                    gate["recoverability"] = "iat_insufficient"
            if not gate.get("rebuild_allowed"):
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="iat_rebuild_blocked",
                        message="IAT rebuild gate refused this range",
                        details={
                            "layout_analysis": analysis,
                            "rebuild_gate": gate,
                            "stub_coupling": stub_coupling,
                            "recoverability": gate.get("recoverability"),
                        },
                    ),
                )
            raw = path.read_bytes()
            # If dump looks like a pure memory image, remap first.
            try:
                pe_bytes, remap_report = remap_dump_to_file(raw, entry_point_rva=oep_rva)
            except PeRebuildError:
                pe_bytes = raw
                remap_report = None
            rebuilt, report = rebuild_imports(pe_bytes, entries)
            blocked = self._guard_unpack_active(session_id, stage="iat_rebuild_advance")
            if blocked is not None:
                return blocked
            out_dir = artifact_root / "unpack" / session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"iat-rebuilt-{uuid4().hex}.exe"
            sha = write_rebuilt_pe(out_path, rebuilt)
            payload: JsonObject = {
                "input_path": str(path),
                "output_path": str(out_path),
                "sha256": sha,
                "iat_va": iat_va,
                "size": size,
                "oep_rva": oep_rva,
                "report": report.to_dict(),
                "rebuild_gate": gate,
                "stub_coupling": stub_coupling,
                "recoverability": gate.get("recoverability"),
                "stage_label": STAGE_IAT_REBUILT,
                "artifact_kind": "iat_rebuilt",
                "claims_universal_unpack": False,
            }
            if remap_report is not None:
                payload["remap_report"] = remap_report.to_dict()
            try:
                verified = scan_pe(out_path)
                payload["pe_verify"] = {
                    "ok": True,
                    "architecture": verified.architecture,
                    "entry_point_rva": verified.pe.entry_point_rva,
                    "section_count": len(verified.pe.sections),
                    "import_function_count": verified.pe.imports.function_count,
                }
            except PeFormatError as exc:
                payload["pe_verify"] = {"ok": False, "error": str(exc)}
                report.unfixed.append(f"built-in PE parse failed: {exc}")
                payload["report"] = report.to_dict()
            self._advance_unpack_after_imports_rebuilt(
                session_id,
                path=str(out_path),
                sha256=sha,
                kind="iat_rebuilt",
            )
            return _success(payload, session_id=session_id, backend="unpack")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def unpack_pe_rebuild(
        self,
        session_id: str,
        dump_path: str,
        *,
        entry_point_rva: int | None = None,
        iat_va: int | None = None,
        iat_size: int | None = None,
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Remap a runtime dump to file layout and optionally rebuild imports."""
        try:
            blocked = self._guard_unpack_active(session_id, stage="pe_rebuild")
            if blocked is not None:
                return blocked
            path = Path(dump_path).expanduser().resolve(strict=True)
            artifact_root = self.settings.artifact_root.expanduser().resolve()
            if artifact_root not in path.parents and path.parent != artifact_root:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="dump_path must be inside the session artifact root",
                    ),
                )
            raw = path.read_bytes()
            rebuilt, report = remap_dump_to_file(raw, entry_point_rva=entry_point_rva)
            import_report = None
            if iat_va is not None and iat_size is not None:
                blocked = self._guard_unpack_active(session_id, stage="pe_rebuild_iat")
                if blocked is not None:
                    return blocked
                read = self.imports_read(session_id, iat_va, iat_size, timeout=timeout)
                if not read.ok or read.data is None:
                    return read
                entries = read.data.get("entries")
                if not isinstance(entries, list):
                    return Result[JsonObject](
                        ok=False,
                        error=RpcError(
                            code="invalid_iat",
                            message="imports.read returned no entries",
                        ),
                    )
                rebuilt, import_report = rebuild_imports(rebuilt, entries)
            blocked = self._guard_unpack_active(session_id, stage="pe_rebuild_write")
            if blocked is not None:
                return blocked
            out_dir = artifact_root / "unpack" / session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"pe-rebuilt-{uuid4().hex}.exe"
            sha = write_rebuilt_pe(out_path, rebuilt)
            payload: JsonObject = {
                "input_path": str(path),
                "output_path": str(out_path),
                "sha256": sha,
                "entry_point_rva": entry_point_rva,
                "report": report.to_dict(),
                "claims_universal_unpack": False,
            }
            if import_report is not None:
                payload["import_report"] = import_report.to_dict()
            # Structural verify with built-in parser.
            try:
                verified = scan_pe(out_path)
                payload["pe_verify"] = {
                    "ok": True,
                    "architecture": verified.architecture,
                    "entry_point_rva": verified.pe.entry_point_rva,
                    "section_count": len(verified.pe.sections),
                    "import_function_count": verified.pe.imports.function_count,
                }
            except PeFormatError as exc:
                payload["pe_verify"] = {"ok": False, "error": str(exc)}
                report.unfixed.append(f"built-in PE parse failed: {exc}")
                payload["report"] = report.to_dict()
            if import_report is not None:
                blocked = self._guard_unpack_active(session_id, stage="pe_rebuild_advance")
                if blocked is not None:
                    payload["aborted_before_phase_advance"] = True
                    payload["partial_artifacts_retained"] = True
                    payload["safe_rollback"] = False
                    return Result[JsonObject](
                        ok=False,
                        error=blocked.error,
                        data=payload,
                        meta=blocked.meta,
                    )
                self._advance_unpack_after_imports_rebuilt(
                    session_id,
                    path=str(out_path),
                    sha256=sha,
                    kind="pe_rebuilt",
                )
            return _success(payload, session_id=session_id, backend="unpack")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def unpack_verify(
        self,
        session_id: str,
        path: str,
        *,
        use_die: bool = True,
        open_ida: bool = False,
        baseline_session_id: str | None = None,
        timeout: float = 60.0,
        expect_window_title: str | None = None,
        expect_window_class: str | None = None,
        ui_pid: int | None = None,
    ) -> Result[JsonObject]:
        """Re-parse a rebuilt PE with built-in parser, optional DIE, optional IDA compare.

        Optional UI gates (``expect_window_title`` / ``expect_window_class``) check a
        live process via Win32 enumeration when ``ui_pid`` is set or the session has
        an attached debuggee PID. Gates never claim universal unpack success.
        """
        try:
            target = Path(path).expanduser().resolve(strict=True)
            bounded_timeout = _detection_timeout(timeout)
            pe_report = scan_pe(target)
            payload: JsonObject = {
                "path": str(target),
                "sha256": pe_report.sha256,
                "architecture": pe_report.architecture,
                "pe": {
                    "entry_point_rva": pe_report.pe.entry_point_rva,
                    "section_count": len(pe_report.pe.sections),
                    "import_function_count": pe_report.pe.imports.function_count,
                    "dotnet": pe_report.pe.dotnet,
                },
                "claims_universal_unpack": False,
                "unfixed": [],
            }
            if use_die and self.settings.diec is not None:
                try:
                    die_result = self._die_scanner(
                        self.settings.diec,
                        target,
                        mode=ScanMode.NORMAL,
                        timeout=bounded_timeout,
                    )
                    payload["die"] = {
                        "status": "completed",
                        "version": die_result.source.version,
                        "finding_count": len(die_result.findings),
                        "findings": [
                            {
                                "category": finding.category.value
                                if hasattr(finding.category, "value")
                                else str(finding.category),
                                "name": finding.name,
                                "summary": finding.summary,
                            }
                            for finding in die_result.findings[:32]
                        ],
                    }
                except DieScanError as exc:
                    payload["die"] = {"status": "failed", "error": str(exc)}
                    payload["unfixed"].append(f"DIE rescan failed: {exc}")
            elif use_die:
                payload["die"] = {"status": "unavailable"}
                payload["unfixed"].append("DIE not configured")

            ida_compare: JsonObject | None = None
            if open_ida:
                child = self.create_session(str(target))
                if child.ok and child.data is not None:
                    child_id = str(child.data["session"]["id"])
                    opened = self.open_static(child_id)
                    ida_compare = {
                        "session_id": child_id,
                        "static_open_ok": opened.ok,
                    }
                    if baseline_session_id:
                        try:
                            base_funcs = self.static_functions(baseline_session_id)
                            new_funcs = self.static_functions(child_id) if opened.ok else None
                            ida_compare["baseline_functions"] = (
                                base_funcs.data if base_funcs.ok else None
                            )
                            ida_compare["rebuilt_functions"] = (
                                new_funcs.data if new_funcs and new_funcs.ok else None
                            )
                        except Exception as exc:  # noqa: BLE001 - compare is best-effort
                            ida_compare["compare_error"] = str(exc)
                            payload["unfixed"].append("IDA function compare incomplete")
                else:
                    ida_compare = {
                        "static_open_ok": False,
                        "error": child.error.model_dump() if child.error else None,
                    }
                    payload["unfixed"].append("IDA reopen failed")
            payload["ida"] = ida_compare
            ida_ok = bool(
                open_ida and isinstance(ida_compare, dict) and ida_compare.get("static_open_ok")
            )

            if expect_window_title is not None or expect_window_class is not None:
                gate_pid = ui_pid
                if gate_pid is None:
                    try:
                        runtime = self._runtime(session_id, BackendKind.X64DBG)
                        gate_pid = int(getattr(runtime.worker, "pid", 0) or 0) or None
                        # Prefer debuggee pid from last state if available.
                        state = getattr(runtime.worker, "last_state", None)
                        if isinstance(state, dict) and isinstance(state.get("pid"), int):
                            gate_pid = int(state["pid"])
                    except Exception:  # noqa: BLE001 - UI gate is best-effort
                        gate_pid = None
                ui_gate: JsonObject = {
                    "expect_window_title": expect_window_title,
                    "expect_window_class": expect_window_class,
                    "pid": gate_pid,
                    "matched": False,
                    "checked": False,
                }
                if gate_pid is None or type(gate_pid) is not int or gate_pid <= 0:
                    ui_gate["status"] = "skipped_no_pid"
                    payload["unfixed"].append("UI window gate skipped: no pid")
                else:
                    try:
                        windows = list_process_windows(gate_pid)
                        ui_gate["checked"] = True
                        ui_gate["window_count"] = len(windows)
                        matched = False
                        for window in windows:
                            title = str(window.get("title") or "")
                            class_name = str(window.get("class_name") or "")
                            title_ok = (
                                expect_window_title is None
                                or expect_window_title.casefold() in title.casefold()
                            )
                            class_ok = (
                                expect_window_class is None
                                or class_name == expect_window_class
                            )
                            if title_ok and class_ok:
                                matched = True
                                ui_gate["match"] = {
                                    "title": title,
                                    "class_name": class_name,
                                    "hwnd": window.get("hwnd"),
                                }
                                break
                        ui_gate["matched"] = matched
                        ui_gate["status"] = "matched" if matched else "not_matched"
                        if not matched:
                            payload["unfixed"].append("UI window title/class gate not matched")
                    except Exception as exc:  # noqa: BLE001
                        ui_gate["status"] = "error"
                        ui_gate["error"] = str(exc)
                        payload["unfixed"].append(f"UI window gate failed: {exc}")
                payload["ui_gate"] = ui_gate

            pe_ok = True
            pe_verify = payload.get("pe")
            if not isinstance(pe_verify, dict):
                pe_ok = False
            ui_matched = None
            ui_gate_payload = payload.get("ui_gate")
            if isinstance(ui_gate_payload, dict):
                ui_matched = bool(ui_gate_payload.get("matched"))
            runnable_gate = gate_stage_upgrade(
                current_stage=STAGE_IAT_REBUILT,
                target_stage=STAGE_RUNNABLE,
                rebuild_allowed=True,
                pe_verify_ok=pe_ok,
                ui_gate_matched=ui_matched,
            )
            artifact_kind = resolve_artifact_kind_for_stage(
                target_stage=STAGE_RUNNABLE,
                preferred_kind="runnable_pe",
                upgrade_gate=runnable_gate,
            )
            payload["stage_label"] = (
                STAGE_RUNNABLE if runnable_gate.get("allowed") else STAGE_IAT_REBUILT
            )
            payload["stage_upgrade_gate"] = runnable_gate
            payload["artifact_kind"] = artifact_kind
            if not runnable_gate.get("allowed"):
                payload["unfixed"].append(
                    "stage stays iat-rebuilt/verified; runnable requires UI+PE gates"
                )

            self._advance_unpack_after_verify(
                session_id,
                path=str(target),
                sha256=str(payload["sha256"]),
                open_ida=open_ida,
                ida_ok=ida_ok,
            )
            return _success(payload, session_id=session_id, backend="unpack")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def unpack_plan(
        self,
        session_id: str,
        *,
        mode: ScanMode | str = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: float = 30.0,
        force_route: str | None = None,
    ) -> Result[JsonObject]:
        """Build a non-authoritative unpack plan without side effects."""
        try:
            classified = self.packer_classify(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=timeout,
            )
            if not classified.ok or classified.data is None:
                return classified
            candidates = classified.data.get("candidates")
            if not isinstance(candidates, list):
                candidates = []
            session = self.registry.get(session_id)
            pe_report = scan_pe(session.binary)
            pe_vm_like = pe_suggests_vm_protector(
                finding_ids=tuple(item.id for item in pe_report.findings),
                section_names=tuple(section.name for section in pe_report.pe.sections),
            )
            recommendation = recommend_unpack_route(
                candidates,
                pe_dotnet=pe_report.pe.dotnet,
                pe_vm_like=pe_vm_like,
                force_route=force_route,
            )
            plan = build_unpack_plan(
                candidates,
                pe_dotnet=pe_report.pe.dotnet,
                pe_vm_like=pe_vm_like,
                force_route=force_route,
                recommendation=recommendation,
            )
            return _success(
                {
                    "plan": plan,
                    "recommendation": recommendation.to_dict(),
                    "pe_vm_like": pe_vm_like,
                    "force_route": force_route,
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def unpack_start(
        self,
        session_id: str,
        *,
        mode: ScanMode | str = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: float = 120.0,
        open_ida: bool = False,
        execute_upx: bool = True,
        replace: bool = False,
        force_route: str | None = None,
    ) -> Result[JsonObject]:
        """Start an unpack orchestration session from the current detection plan.

        Refuses to silently overwrite a still-active unpack session unless
        ``replace=True``. Terminal phases ``failed`` / ``cancelled`` /
        ``reanalyzed`` may be restarted without the flag.
        """
        try:
            if type(replace) is not bool:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(code="invalid_params", message="replace must be a boolean"),
                )
            existing = self._unpack_owner.get(session_id)
            if existing is not None:
                checked = check_timeout(existing)
                if checked is not existing:
                    self._store_unpack_session(checked)
                    existing = checked
                # failed/cancelled/reanalyzed are restartable; verified and in-flight are not.
                restartable = {
                    UnpackPhase.FAILED,
                    UnpackPhase.CANCELLED,
                    UnpackPhase.REANALYZED,
                }
                if existing.phase not in restartable and not replace:
                    return Result[JsonObject](
                        ok=False,
                        error=RpcError(
                            code="unpack_already_active",
                            message=(
                                "unpack session already active; pass replace=True to "
                                "explicitly start a new orchestration"
                            ),
                            details={
                                "phase": existing.phase.value,
                                "route": existing.route,
                                "replace_required": True,
                            },
                        ),
                        meta={"unpack": existing.to_dict()},
                    )
            planned = self.unpack_plan(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=min(timeout, 60.0),
                force_route=force_route,
            )
            if not planned.ok or planned.data is None:
                return planned
            plan = planned.data["plan"]
            assert isinstance(plan, dict)
            session = self.registry.get(session_id)
            route = str(plan.get("route", "none"))
            state = create_unpack_session(
                session_id,
                route=route,
                plan=plan,
                timeout_seconds=timeout,
                input_sha256=session.sha256,
            )
            state = add_artifact(
                state,
                kind="input_binary",
                path=str(session.binary),
                sha256=session.sha256,
                phase=UnpackPhase.DETECTED,
            )
            bounded_probe: JsonObject | None = None

            if route == "upx" and execute_upx:
                state = self._run_upx_orchestration(
                    state,
                    session_id,
                    timeout=timeout,
                    open_ida=open_ida,
                )
            elif route == "dotnet":
                # Hand off to M6: run inspect only; never auto-deobfuscate or claim success.
                inspect = self.dotnet_inspect(session_id, require_verified=False)
                if not inspect.ok or inspect.data is None:
                    code = (
                        inspect.error.code if inspect.error is not None else "dotnet_inspect_failed"
                    )
                    state = fail_unpack_session(
                        state,
                        code=str(code),
                        message=(
                            inspect.error.message
                            if inspect.error is not None
                            else "dotnet.inspect failed on .NET unpack route"
                        ),
                        details={"route": route, "plan": plan},
                        retryable=True,
                    )
                    bounded_probe = {
                        "route": "dotnet",
                        "dotnet_inspect_ok": False,
                        "claims_universal_unpack": False,
                    }
                else:
                    kind = str(inspect.data.get("kind") or "")
                    verified = kind in {"pure_managed", "mixed_mode"}
                    state = append_timeline(
                        state,
                        event="routed_m6",
                        message=(
                            ".NET route handed to M6 after inspect; optional "
                            "dotnet.deobfuscate/verify next. No automatic deobfuscation."
                        ),
                        input_sha256=session.sha256,
                        details={
                            "route": route,
                            "clr_kind": kind,
                            "clr_verified": verified,
                            "next": (
                                ["dotnet.deobfuscate", "dotnet.verify"]
                                if verified
                                else ["dotnet.inspect", "dotnet.verify"]
                            ),
                        },
                    )
                    bounded_probe = {
                        "route": "dotnet",
                        "dotnet_inspect": inspect.data,
                        "clr_kind": kind,
                        "clr_verified": verified,
                        "next": (
                            ["dotnet.deobfuscate", "dotnet.verify"]
                            if verified
                            else ["dotnet.inspect", "dotnet.verify"]
                        ),
                        "claims_universal_unpack": False,
                    }
            elif route in {"generic_dynamic", "bounded_dynamic"}:
                state = transition(
                    state,
                    UnpackPhase.RUNNING,
                    event="awaiting_runtime",
                    message=(
                        "Native/VM route entered running phase; gather OEP observations "
                        "then call unpack.confirm_oep (heuristics are not authoritative)."
                    ),
                    input_sha256=session.sha256,
                    details={"route": route},
                )
                state, bounded_probe = self._bounded_runtime_probe(
                    state,
                    session_id,
                    route=route,
                )
            else:
                state = append_timeline(
                    state,
                    event="no_packer_route",
                    message="No packer route; prefer static analysis.",
                    input_sha256=session.sha256,
                )
                bounded_probe = None

            self._store_unpack_session(state)
            payload: JsonObject = {
                "unpack": state.to_dict(),
                "claims_universal_unpack": False,
            }
            if bounded_probe is not None:
                payload["bounded_probe"] = bounded_probe
            return _success(payload, session_id=session_id, backend="unpack")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def unpack_status(self, session_id: str) -> Result[JsonObject]:
        """Return the current unpack orchestration state for a session."""
        try:
            self.registry.get(session_id)
            state = self._unpack_owner.get(session_id)
            if state is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="unpack_not_started",
                        message="no unpack session; call unpack.plan / unpack.start first",
                        details={"session_id": session_id},
                    ),
                )
            checked = check_timeout(state)
            if checked is not state:
                self._store_unpack_session(checked)
                state = checked
            return _success(
                {"unpack": state.to_dict(), "claims_universal_unpack": False},
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def unpack_cancel(
        self,
        session_id: str,
        *,
        reason: str = "cancelled by caller",
    ) -> Result[JsonObject]:
        """Cancel an active unpack session without modifying the original input.

        Cancel is not a rollback: dumps and other artifacts are retained, and the
        original input binary is left untouched. If a dynamic backend is open,
        a best-effort pause is attempted.
        """
        try:
            self.registry.get(session_id)
            state = self._unpack_owner.get(session_id)
            if state is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="unpack_not_started",
                        message="no unpack session to cancel",
                        details={"session_id": session_id},
                    ),
                )
            debuggee_paused_attempted = False
            dynamic_open = self._runtime_owner.get(session_id, BackendKind.X64DBG) is not None
            if dynamic_open:
                debuggee_paused_attempted = True
                with suppress(Exception):
                    self.dynamic_pause(session_id)
            state = cancel_unpack_session(
                state,
                reason=reason,
                debuggee_paused_attempted=debuggee_paused_attempted,
            )
            self._store_unpack_session(state)
            return _success(
                {
                    "unpack": state.to_dict(),
                    "original_input_preserved": True,
                    "debuggee_paused_attempted": debuggee_paused_attempted,
                    "artifacts_retained": True,
                    "safe_rollback": False,
                    "note": "cancel does not undo dumps or restore prior memory/file state",
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def unpack_artifacts(self, session_id: str) -> Result[JsonObject]:
        """List artifacts produced by the current unpack session."""
        try:
            self.registry.get(session_id)
            state = self._unpack_owner.get(session_id)
            if state is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="unpack_not_started",
                        message="no unpack session; no artifacts ledger",
                        details={"session_id": session_id},
                    ),
                )
            directory = self._unpack_session_dir(session_id)
            return _success(
                {
                    "artifacts": [item.to_dict() for item in state.artifacts],
                    "count": len(state.artifacts),
                    "timeline_path": str(directory / "timeline.jsonl"),
                    "state_path": str(directory / "state.json"),
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def unpack_score_oep(
        self,
        session_id: str,
        *,
        module_base: int,
        module_size: int,
        observations: list[JsonObject] | None = None,
        stub_rva_ranges: list[tuple[int, int]] | None = None,
        max_candidates: int = 8,
        imports_resolved_hint: bool = False,
        previous_regions: list[JsonObject] | None = None,
    ) -> Result[JsonObject]:
        """Score OEP candidates from observations; never auto-confirms.

        When ``observations`` is empty/None, snapshots are collected from the
        dynamic backend (registers.read + memory.regions). Missing dynamic
        backend yields a clear error — never a fake success.
        """
        try:
            self.registry.get(session_id)
            blocked = self._guard_unpack_active(session_id, stage="score_oep")
            if blocked is not None:
                return blocked
            state = self._unpack_owner.get(session_id)

            collected_note: str | None = None
            auto_collected = False
            effective_stub = list(stub_rva_ranges or ())
            effective_observations = list(observations or [])
            entry_point_rva: int | None = None

            if not effective_observations:
                auto_collected = True
                collected = self._collect_oep_observations_from_runtime(
                    session_id,
                    module_base=module_base,
                    module_size=module_size,
                    stub_rva_ranges=effective_stub,
                    imports_resolved_hint=imports_resolved_hint,
                    previous_regions=previous_regions,
                )
                if not collected.ok:
                    return collected
                assert collected.data is not None
                effective_observations = list(collected.data.get("observations") or [])
                stub_from_runtime = collected.data.get("stub_rva_ranges") or []
                if not effective_stub and stub_from_runtime:
                    effective_stub = [(int(start), int(size)) for start, size in stub_from_runtime]
                entry_raw = collected.data.get("entry_point_rva")
                if type(entry_raw) is int:
                    entry_point_rva = entry_raw
                collected_note = str(
                    collected.data.get("note")
                    or "observations auto-collected from runtime snapshots"
                )

            candidates = score_oep_candidates(
                module_base=module_base,
                module_size=module_size,
                observations=effective_observations,
                stub_rva_ranges=effective_stub or (),
                max_candidates=max_candidates,
            )
            if state is not None and state.phase not in {
                UnpackPhase.FAILED,
                UnpackPhase.CANCELLED,
                UnpackPhase.REANALYZED,
            }:
                from dataclasses import replace as _replace

                if state.phase == UnpackPhase.RUNNING:
                    state = transition(
                        state,
                        UnpackPhase.OEP_CANDIDATE,
                        event="oep_candidates_scored",
                        message=(
                            f"scored {len(candidates)} OEP candidate(s); "
                            "none are authoritative until unpack.confirm_oep"
                        ),
                        details={
                            "candidate_count": len(candidates),
                            "auto_collected": auto_collected,
                            "observation_count": len(effective_observations),
                        },
                    )
                else:
                    state = append_timeline(
                        state,
                        event="oep_candidates_scored",
                        message=f"scored {len(candidates)} OEP candidate(s)",
                        details={
                            "candidate_count": len(candidates),
                            "auto_collected": auto_collected,
                            "observation_count": len(effective_observations),
                        },
                    )
                state = _replace(
                    state,
                    oep_candidates=tuple(candidates),
                    module_base=module_base,
                )
                self._store_unpack_session(state)
            payload: JsonObject = {
                "candidates": candidates,
                "candidate_count": len(candidates),
                "observations": effective_observations,
                "observation_count": len(effective_observations),
                "auto_collected": auto_collected,
                "authoritative": False,
                "blind_selection": False,
                "claims_universal_unpack": False,
                "unpack": state.to_dict() if state is not None else None,
            }
            if collected_note is not None:
                payload["note"] = collected_note
            if entry_point_rva is not None:
                payload["entry_point_rva"] = entry_point_rva
            if effective_stub:
                payload["stub_rva_ranges"] = [
                    {"rva": start, "size": size} for start, size in effective_stub
                ]
            return _success(
                payload,
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def _collect_oep_observations_from_runtime(
        self,
        session_id: str,
        *,
        module_base: int,
        module_size: int,
        stub_rva_ranges: list[tuple[int, int]],
        imports_resolved_hint: bool,
        previous_regions: list[JsonObject] | None,
    ) -> Result[JsonObject]:
        """Gather RIP + memory regions (+ optional PE stub hints) for OEP scoring."""
        registers = self.dynamic_registers_read(session_id)
        if not registers.ok or registers.data is None:
            if registers.error is not None and registers.error.code == "backend_unavailable":
                return registers
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code=registers.error.code if registers.error else "backend_unavailable",
                    message=(
                        registers.error.message
                        if registers.error
                        else "dynamic registers.read unavailable for OEP observation"
                    ),
                    details={
                        "session_id": session_id,
                        "step": "registers.read",
                        **(registers.error.details if registers.error else {}),
                    },
                    retryable=bool(registers.error.retryable) if registers.error else False,
                ),
                meta=registers.meta,
            )

        regions_result = self.memory_regions(
            session_id,
            offset=0,
            limit=_OEP_REGION_SNAPSHOT_LIMIT,
        )
        if not regions_result.ok or regions_result.data is None:
            if (
                regions_result.error is not None
                and regions_result.error.code == "backend_unavailable"
            ):
                return regions_result
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code=(
                        regions_result.error.code if regions_result.error else "backend_unavailable"
                    ),
                    message=(
                        regions_result.error.message
                        if regions_result.error
                        else "dynamic memory.regions unavailable for OEP observation"
                    ),
                    details={
                        "session_id": session_id,
                        "step": "memory.regions",
                        **(regions_result.error.details if regions_result.error else {}),
                    },
                    retryable=(
                        bool(regions_result.error.retryable) if regions_result.error else False
                    ),
                ),
                meta=regions_result.meta,
            )

        regs = registers.data.get("registers")
        rip: int | None = None
        if isinstance(regs, dict):
            for name in ("rip", "eip"):
                value = regs.get(name)
                if type(value) is int:
                    rip = value
                    break

        regions_raw = regions_result.data.get("regions")
        regions: list[JsonObject] = (
            [dict(item) for item in regions_raw if isinstance(item, dict)]
            if isinstance(regions_raw, list)
            else []
        )

        effective_stub = list(stub_rva_ranges)
        entry_point_rva: int | None = None
        pe = self.pe_headers_runtime(session_id, module_base, save_artifact=False)
        if pe.ok and pe.data is not None:
            entry_raw = pe.data.get("entry_point_rva")
            if type(entry_raw) is int and entry_raw >= 0:
                entry_point_rva = entry_raw
            if not effective_stub:
                sections = pe.data.get("sections")
                if isinstance(sections, list):
                    effective_stub = stub_rva_ranges_from_sections(
                        [item for item in sections if isinstance(item, dict)]
                    )

        cached_previous = previous_regions
        if cached_previous is None:
            cached_previous = self._unpack_owner.get_protection_snapshot(session_id)

        observations = collect_oep_observations(
            module_base=module_base,
            module_size=module_size,
            rip=rip,
            regions=regions,
            previous_regions=cached_previous,
            stub_rva_ranges=effective_stub,
            entry_point_rva=entry_point_rva,
            imports_resolved_hint=imports_resolved_hint,
        )

        self._unpack_owner.put_protection_snapshot(
            session_id,
            [
                {
                    "base": item.get("base"),
                    "size": item.get("size"),
                    "protect": item.get("protect"),
                    "protect_name": item.get("protect_name"),
                }
                for item in regions
                if isinstance(item.get("base"), int)
            ],
        )

        note = "observations auto-collected from runtime snapshots"
        if not observations:
            note = (
                "runtime snapshots collected but yielded no OEP observations "
                "(need RIP in module code and/or protect diffs vs prior snapshot)"
            )
        return _success(
            {
                "observations": observations,
                "stub_rva_ranges": effective_stub,
                "entry_point_rva": entry_point_rva,
                "rip": rip,
                "region_count": len(regions),
                "note": note,
                "authoritative": False,
            },
            session_id=session_id,
            backend="unpack",
        )

    def unpack_confirm_oep(
        self,
        session_id: str,
        *,
        oep_rva: int,
        candidate_id: str | None = None,
        iat_va: int | None = None,
        iat_size: int | None = None,
        module_base: int | None = None,
        auto_dump: bool = False,
        dump_timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Caller-confirmed OEP (and optional IAT); never accepts heuristic alone as final.

        When ``auto_dump`` is True and ``module_base`` (or session module_base) is set,
        also runs ``unpack.dump_module`` to advance the session into ``dumped``.
        """
        try:
            if type(oep_rva) is not int or oep_rva < 0:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="oep_rva must be a non-negative integer",
                    ),
                )
            if type(auto_dump) is not bool:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(code="invalid_params", message="auto_dump must be a boolean"),
                )
            state = self._unpack_owner.get(session_id)
            if state is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="unpack_not_started",
                        message="no unpack session; call unpack.start first",
                    ),
                )
            checked = check_timeout(state)
            if checked is not state:
                self._store_unpack_session(checked)
                state = checked
            if (
                state.phase == UnpackPhase.FAILED
                and state.failure is not None
                and state.failure.code == "unpack_timeout"
            ):
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="unpack_timeout",
                        message=state.failure.message,
                        details=state.failure.details,
                    ),
                )
            from dataclasses import replace as _replace

            if state.phase == UnpackPhase.RUNNING:
                state = transition(
                    state,
                    UnpackPhase.OEP_CANDIDATE,
                    event="oep_confirmed",
                    message="caller confirmed OEP RVA",
                    details={
                        "oep_rva": oep_rva,
                        "candidate_id": candidate_id,
                        "confirmed_by": "caller",
                    },
                )
            elif state.phase == UnpackPhase.OEP_CANDIDATE:
                state = append_timeline(
                    state,
                    event="oep_confirmed",
                    message="caller confirmed OEP RVA",
                    details={
                        "oep_rva": oep_rva,
                        "candidate_id": candidate_id,
                        "confirmed_by": "caller",
                    },
                )
            else:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_phase",
                        message=(
                            f"confirm_oep requires running/oep_candidate phase, "
                            f"got {state.phase.value}"
                        ),
                        details={"phase": state.phase.value},
                    ),
                )
            resolved_base = module_base if module_base is not None else state.module_base
            state = _replace(
                state,
                confirmed_oep_rva=oep_rva,
                confirmed_iat_va=iat_va,
                confirmed_iat_size=iat_size,
                module_base=resolved_base,
            )
            self._store_unpack_session(state)

            dump_result: JsonObject | None = None
            if auto_dump:
                blocked = self._guard_unpack_active(session_id, stage="confirm_oep_auto_dump")
                if blocked is not None:
                    return blocked
                if resolved_base is None or type(resolved_base) is not int or resolved_base <= 0:
                    return Result[JsonObject](
                        ok=False,
                        error=RpcError(
                            code="invalid_params",
                            message="auto_dump requires module_base on confirm or session",
                            details={"unpack": state.to_dict()},
                        ),
                    )
                dumped = self.unpack_dump_module(
                    session_id,
                    resolved_base,
                    timeout=dump_timeout,
                )
                dump_result = dumped.data if dumped.ok else None
                if not dumped.ok:
                    return Result[JsonObject](
                        ok=False,
                        error=dumped.error
                        or RpcError(
                            code="dump_failed",
                            message="auto_dump failed after OEP confirm",
                        ),
                        meta={"unpack": self._unpack_owner.get(session_id)},
                    )
                state = self._unpack_owner.get(session_id) or state

            return _success(
                {
                    "unpack": state.to_dict(),
                    "confirmed_oep_rva": oep_rva,
                    "role": "confirmed",
                    "auto_dump": auto_dump,
                    "dump": dump_result,
                    "next": (
                        ["unpack.iat.scan", "unpack.pe.rebuild", "unpack.verify"]
                        if auto_dump
                        else ["unpack.dump_module", "unpack.iat.scan", "unpack.pe.rebuild"]
                    ),
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="unpack",
            )
        except UnpackSessionError as exc:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_phase", message=str(exc)),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

    def _bounded_runtime_probe(
        self,
        state: UnpackSessionState,
        session_id: str,
        *,
        route: str,
    ) -> tuple[UnpackSessionState, JsonObject]:
        """Best-effort bounded probe for native/VM routes without claiming unpack success.

        If a dynamic backend is already open: list modules, remember a module base,
        and optionally score OEP candidates from live observations. Never dumps or
        confirms OEP automatically.
        """
        from dataclasses import replace as _replace

        probe: JsonObject = {
            "route": route,
            "dynamic_open": False,
            "module_base": None,
            "oep_scored": False,
            "candidate_count": 0,
            "claims_universal_unpack": False,
            "note": (
                "bounded probe only; caller must confirm_oep then dump/rebuild; "
                "does not open a new debugger session"
            ),
        }
        dynamic_open = self._runtime_owner.get(session_id, BackendKind.X64DBG) is not None
        probe["dynamic_open"] = dynamic_open
        if not dynamic_open:
            state = append_timeline(
                state,
                event="bounded_probe_skipped",
                message="dynamic backend not open; open_dynamic+pause before score_oep/dump",
                details={"route": route},
            )
            return state, probe

        modules = self.dynamic_modules(session_id)
        if not modules.ok or modules.data is None:
            state = append_timeline(
                state,
                event="bounded_probe_modules_failed",
                message="modules.list failed during bounded probe",
                details={
                    "error": modules.error.model_dump() if modules.error else None,
                },
            )
            probe["modules_error"] = modules.error.model_dump() if modules.error else None
            return state, probe

        module_list = modules.data.get("modules")
        if not isinstance(module_list, list) or not module_list:
            state = append_timeline(
                state,
                event="bounded_probe_no_modules",
                message="no modules returned for bounded probe",
            )
            return state, probe

        first = module_list[0]
        if not isinstance(first, dict):
            return state, probe
        base = first.get("base")
        size = first.get("size")
        if type(base) is not int or base <= 0:
            return state, probe
        probe["module_base"] = base
        probe["module_size"] = size if type(size) is int else None
        probe["module_name"] = first.get("name")
        state = _replace(state, module_base=base)
        state = append_timeline(
            state,
            event="bounded_probe_modules_listed",
            message="recorded candidate module base for later dump/OEP scoring",
            details={"module_base": base, "module_name": first.get("name")},
        )

        # Optional OEP score when paused; failures stay observable.
        if type(size) is int and size > 0:
            scored = self.unpack_score_oep(
                session_id,
                module_base=base,
                module_size=size,
                observations=None,
            )
            if scored.ok and scored.data is not None:
                probe["oep_scored"] = True
                probe["candidate_count"] = int(scored.data.get("candidate_count") or 0)
                refreshed = self._unpack_owner.get(session_id)
                if refreshed is not None:
                    state = refreshed
            else:
                probe["oep_score_error"] = scored.error.model_dump() if scored.error else None
                state = append_timeline(
                    state,
                    event="bounded_probe_oep_score_deferred",
                    message=(
                        "OEP auto-score unavailable (likely not paused); "
                        "caller may retry unpack.score_oep after pause"
                    ),
                    details=probe.get("oep_score_error"),
                )
        return state, probe

    def _run_upx_orchestration(
        self,
        state: UnpackSessionState,
        session_id: str,
        *,
        timeout: float,
        open_ida: bool,
    ) -> UnpackSessionState:
        tested = self.unpack_upx_test(session_id, timeout=timeout)
        if not tested.ok:
            return fail_unpack_session(
                state,
                code="upx_test_failed",
                message="official UPX test failed; not claiming unpack success",
                details=tested.error.model_dump() if tested.error else {},
                retryable=True,
            )
        state = append_timeline(
            state,
            event="upx_test_ok",
            message="official upx -t succeeded",
            details=tested.data or {},
        )
        self._store_unpack_session(state)
        checked, code = ensure_unpack_active(state, stage="upx_unpack")
        if code is not None:
            self._store_unpack_session(checked)
            return checked
        state = checked
        unpacked = self.unpack_upx_unpack(
            session_id,
            timeout=timeout,
            open_ida=open_ida,
        )
        if not unpacked.ok or unpacked.data is None:
            return fail_unpack_session(
                state,
                code="upx_unpack_failed",
                message="official UPX unpack failed; not claiming success",
                details=unpacked.error.model_dump() if unpacked.error else {},
                retryable=True,
            )
        output_path = str(unpacked.data.get("output_path", ""))
        output_sha = None
        if output_path:
            output_sha = file_sha256(Path(output_path))
            state = add_artifact(
                state,
                kind="upx_unpacked",
                path=output_path,
                sha256=output_sha,
                phase=UnpackPhase.VERIFIED,
            )
        state = transition(
            state,
            UnpackPhase.VERIFIED,
            event="upx_unpacked",
            message="official UPX unpack produced an artifact",
            output_sha256=output_sha,
            details={
                "comparison": unpacked.data.get("comparison"),
                "die_rescan": unpacked.data.get("die_rescan"),
            },
        )
        reanalyze = unpacked.data.get("reanalyze")
        if open_ida and isinstance(reanalyze, dict) and reanalyze.get("static_open_ok"):
            state = transition(
                state,
                UnpackPhase.REANALYZED,
                event="ida_reopened",
                message="unpacked artifact opened in IDA idalib",
                output_sha256=output_sha,
                details={"reanalyze": reanalyze},
            )
        return state

    def _unpack_session_dir(self, session_id: str) -> Path:
        if not session_id or Path(session_id).name != session_id:
            raise ValueError("invalid session id for unpack artifact path")
        return (
            self.settings.artifact_root.expanduser().resolve() / "unpack" / session_id / "session"
        )

    def _store_unpack_session(self, state: UnpackSessionState) -> None:
        self._unpack_owner.put(state.session_id, state)

        def write(directory: Path) -> None:
            write_timeline_jsonl(state, directory / "timeline.jsonl")
            persist_state_snapshot(state, directory / "state.json")

        self.repository.persist_unpack_state(
            state.session_id,
            write=write,
        )

    def _guard_unpack_active(
        self,
        session_id: str,
        *,
        stage: str,
    ) -> Result[JsonObject] | None:
        """Block new unpack work when session is timed out / cancelled / terminal.

        Returns an error ``Result`` to propagate, or ``None`` when work may proceed
        (including when no unpack session exists yet).
        """
        state = self._unpack_owner.get(session_id)
        if state is None:
            return None
        checked, code = ensure_unpack_active(state, stage=stage)
        if checked is not state:
            self._store_unpack_session(checked)
            state = checked
        elif code is not None and state.phase in {
            UnpackPhase.FAILED,
            UnpackPhase.CANCELLED,
            UnpackPhase.REANALYZED,
        }:
            # Already terminal; refresh store is a no-op but keeps API uniform.
            self._store_unpack_session(state)
        if code is None:
            return None
        message = (
            state.failure.message
            if state.failure is not None and code == "unpack_timeout"
            else f"unpack session cannot continue ({state.phase.value}) at {stage}"
        )
        details: JsonObject = {"phase": state.phase.value, "stage": stage}
        if state.failure is not None:
            details["failure"] = state.failure.to_dict()
        return Result[JsonObject](
            ok=False,
            error=RpcError(code=code, message=message, details=details),
            meta={"unpack": state.to_dict()},
        )

    def _advance_unpack_after_dump(
        self,
        session_id: str,
        *,
        path: str,
        sha256: str,
    ) -> None:
        """Advance session to dumped when a dump artifact is produced."""
        state = self._unpack_owner.get(session_id)
        if state is None:
            return
        try:
            state = check_timeout(state)
            if state.phase == UnpackPhase.FAILED:
                self._store_unpack_session(state)
                return
            state = note_dump_success(
                state,
                output_path=path,
                sha256=sha256,
                module_base=state.module_base,
            )
            self._store_unpack_session(state)
        except UnpackSessionError:
            return

    def _advance_unpack_after_imports_rebuilt(
        self,
        session_id: str,
        *,
        path: str,
        sha256: str,
        kind: str,
    ) -> None:
        """Advance session to imports_rebuilt after IAT/PE rebuild."""
        state = self._unpack_owner.get(session_id)
        if state is None:
            return
        try:
            state = check_timeout(state)
            if state.phase == UnpackPhase.FAILED:
                self._store_unpack_session(state)
                return
            state = note_imports_rebuilt(
                state,
                output_path=path,
                sha256=sha256,
                kind=kind,
            )
            self._store_unpack_session(state)
        except UnpackSessionError:
            return

    def _advance_unpack_after_verify(
        self,
        session_id: str,
        *,
        path: str,
        sha256: str,
        open_ida: bool,
        ida_ok: bool,
    ) -> None:
        """Advance session to verified / reanalyzed after unpack.verify."""
        state = self._unpack_owner.get(session_id)
        if state is None:
            return
        try:
            state = check_timeout(state)
            if state.phase == UnpackPhase.FAILED:
                self._store_unpack_session(state)
                return
            state = note_verified(
                state,
                path=path,
                sha256=sha256,
                reanalyzed=bool(open_ida and ida_ok),
            )
            self._store_unpack_session(state)
        except UnpackSessionError:
            return

    def dynamic_modules(self, session_id: str) -> Result[JsonObject]:
        result = self._dynamic_request(session_id, "modules.list")
        if result.ok:
            try:
                runtime = self._runtime(session_id, BackendKind.X64DBG)
                with runtime.lock:
                    runtime.snapshot_resync_required = False
            except Exception:  # noqa: BLE001 - clearing the flag is best-effort
                pass
        return result

    def module_catalog(self, session_id: str) -> Result[JsonObject]:
        try:
            runtime, module_result, _ = self._runtime_module_snapshot(session_id)
            catalog = RuntimeModuleCatalog.from_result(module_result)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                runtime.snapshot_resync_required = False
            return _success(
                catalog.to_dict(),
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
                snapshot="current",
            )
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def module_resolve(
        self,
        session_id: str,
        selector: ModuleSelector,
    ) -> Result[JsonObject]:
        return self._explicit_module_operation(session_id, selector, source=None)

    def sync_module_preferred_to_runtime(
        self,
        session_id: str,
        selector: ModuleSelector,
        address: int,
    ) -> Result[JsonObject]:
        return self._explicit_module_operation(
            session_id,
            selector,
            source="preferred",
            address=address,
        )

    def sync_module_runtime_to_preferred(
        self,
        session_id: str,
        selector: ModuleSelector,
        address: int,
    ) -> Result[JsonObject]:
        return self._explicit_module_operation(
            session_id,
            selector,
            source="runtime",
            address=address,
        )

    def dynamic_breakpoints(self, session_id: str) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "breakpoints.list")

    def dynamic_breakpoint_set(
        self,
        session_id: str,
        address: int,
        *,
        address_space: str = "runtime",
    ) -> Result[JsonObject]:
        """Set a software breakpoint, rebasing static/RVA coordinates when asked."""
        try:
            target = self._runtime_breakpoint_address(session_id, address, address_space)
        except IdaWorkerError as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.IDA.value)
        except XdbgRpcError as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)
        return self._dynamic_request(
            session_id,
            "breakpoints.set",
            {"address": target},
        )

    def _runtime_breakpoint_address(
        self,
        session_id: str,
        address: int,
        address_space: str,
    ) -> int:
        """Translate a caller coordinate into the live runtime VA."""
        normalized = (address_space or "runtime").strip().casefold()
        if normalized == "runtime":
            return address
        if normalized not in {"static", "rva"}:
            raise ValueError("address_space must be one of: runtime, static, rva")
        mapping = self._main_module_mapping(session_id)
        static_address = (
            address if normalized == "static" else mapping.static.from_rva(address)
        )
        return int(mapping.translate("static", static_address)["runtime"]["address"])

    def dynamic_breakpoint_remove(
        self,
        session_id: str,
        address: int,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "breakpoints.remove",
            {"address": address},
        )

    def breakpoints_hardware_set(
        self,
        session_id: str,
        address: int,
        *,
        bp_type: str = "x",
        size: int = 1,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(address) is not int or address < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="address must be a non-negative integer",
                ),
            )
        if bp_type not in {"r", "w", "x", "rw", "access", "write", "execute"}:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="type must be r|w|x"),
            )
        if size not in {1, 2, 4, 8}:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="size must be 1|2|4|8"),
            )
        return self._dynamic_request(
            session_id,
            "breakpoints.hardware.set",
            {"address": address, "type": bp_type, "size": size},
            timeout=timeout,
        )

    def breakpoints_hardware_remove(
        self,
        session_id: str,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "breakpoints.hardware.remove",
            {"address": address},
            timeout=timeout,
        )

    def breakpoints_hardware_list(
        self,
        session_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "breakpoints.hardware.list", timeout=timeout)

    def breakpoints_memory_set(
        self,
        session_id: str,
        address: int,
        *,
        bp_type: str = "a",
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if bp_type not in {"a", "r", "w", "x", "access", "read", "write", "execute", "rwx"}:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="type must be a|r|w|x"),
            )
        return self._dynamic_request(
            session_id,
            "breakpoints.memory.set",
            {"address": address, "type": bp_type},
            timeout=timeout,
        )

    def breakpoints_memory_remove(
        self,
        session_id: str,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "breakpoints.memory.remove",
            {"address": address},
            timeout=timeout,
        )

    def breakpoints_memory_list(
        self,
        session_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "breakpoints.memory.list", timeout=timeout)

    def breakpoints_condition_set(
        self,
        session_id: str,
        address: int,
        expression: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if not isinstance(expression, str) or not expression or len(expression) > 512:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="expression must be a non-empty string up to 512 bytes",
                ),
            )
        if any(ch in expression for ch in ';|&\n\r"\\'):
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="expression contains unsupported characters",
                ),
            )
        return self._dynamic_request(
            session_id,
            "breakpoints.condition.set",
            {"address": address, "expression": expression},
            timeout=timeout,
        )

    def breakpoints_condition_get(
        self,
        session_id: str,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "breakpoints.condition.get",
            {"address": address},
            timeout=timeout,
        )

    def patches_list(self, session_id: str, *, timeout: float = 30.0) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "patches.list", timeout=timeout)

    def patches_apply(
        self,
        session_id: str,
        address: int,
        data: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if not isinstance(data, str) or not data:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="data must be non-empty hex"),
            )
        return self._dynamic_request(
            session_id,
            "patches.apply",
            {"address": address, "data": data},
            timeout=timeout,
        )

    def patches_restore(
        self,
        session_id: str,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "patches.restore",
            {"address": address},
            timeout=timeout,
        )

    def trace_start(
        self,
        session_id: str,
        path: str,
        *,
        max_events: int = 10_000,
        timeout_ms: int = 60_000,
        max_file_bytes: int = 16 * 1024 * 1024,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if not isinstance(path, str) or not path:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="path must be a non-empty string"),
            )
        if type(max_events) is not int or not 1 <= max_events <= 1_000_000:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="max_events out of range"),
            )
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 3_600_000:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="timeout_ms out of range"),
            )
        if type(max_file_bytes) is not int or not 1 <= max_file_bytes <= 256 * 1024 * 1024:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="max_file_bytes out of range"),
            )
        state: _TraceArtifactState | None = None
        runtime: _BackendRuntime | None = None
        state_registered = False
        try:
            output_path = self._new_trace_artifact_path(session_id)
            free_bytes = shutil.disk_usage(output_path.parent).free
            if free_bytes < max_file_bytes:
                raise XdbgRpcError(
                    "insufficient_disk_space",
                    "available disk space is smaller than the requested trace quota",
                    details={
                        "available_disk_bytes": free_bytes,
                        "required_disk_bytes": max_file_bytes,
                        "artifact_directory": str(output_path.parent),
                    },
                    retryable=True,
                )
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            state = _TraceArtifactState(
                session_id=session_id,
                path=output_path,
                requested_path=path,
                max_events=max_events,
                timeout_ms=timeout_ms,
                max_file_bytes=max_file_bytes,
                started_monotonic=monotonic(),
            )
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                if "trace.start" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide trace.start",
                        details={"capability": "trace.start"},
                    )
                existing = self._trace_owner.put_if_inactive(
                    session_id,
                    state,
                    is_active=lambda item: item.active,
                )
                if existing is not None:
                    raise XdbgRpcError(
                        "already_tracing",
                        "stop or finalize the active session trace before starting another",
                        details={"path": str(existing.path)},
                    )
                state_registered = True
                native = runtime.worker.request(
                    "trace.start",
                    {
                        # Caller paths are never trusted as output destinations.  Every
                        # run trace is placed in this session's artifact subtree.
                        "path": str(output_path),
                        "max_events": max_events,
                        "timeout_ms": timeout_ms,
                        "max_file_bytes": max_file_bytes,
                    },
                    timeout=min(timeout, 30.0),
                )
                data = self._validate_trace_status(state, native, require_recording=True)
                if not output_path.is_file():
                    raise XdbgRpcError(
                        "artifact_missing",
                        "trace.start did not create the session-owned trace artifact",
                        details={"path": str(output_path)},
                    )
                state.last_status = dict(data)
            return _success(
                self._trace_result_payload(state, data),
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except XdbgRpcError as exc:
            stopped_safely = True
            if runtime is not None and state is not None and state_registered:
                stopped_safely = self._stop_trace_after_failure(runtime, state)
                self._finalize_trace_artifact(state, terminal_reason="start_failed")
                self._attach_trace_artifact_details(exc, state)
            if exc.code in _FATAL_WORKER_ERRORS or not stopped_safely:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            if runtime is not None and state is not None and state_registered:
                self._stop_trace_after_failure(runtime, state)
                self._finalize_trace_artifact(state, terminal_reason="start_failed")
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def trace_stop(self, session_id: str, *, timeout: float = 30.0) -> Result[JsonObject]:
        state: _TraceArtifactState | None = None
        runtime: _BackendRuntime | None = None
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            state = self._trace_owner.get(session_id)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                if "trace.stop" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide trace.stop",
                        details={"capability": "trace.stop"},
                    )
                native = runtime.worker.request("trace.stop", timeout=min(timeout, 30.0))
                if state is None:
                    return _success(
                        dict(native),
                        session_id=session_id,
                        backend=BackendKind.X64DBG.value,
                    )
                data = self._validate_trace_status(state, native, require_recording=False)
                if data["recording"] is True:
                    raise XdbgRpcError(
                        "trace_stop_failed",
                        "x64dbg still reports trace recording after trace.stop",
                        details={"path": str(state.path)},
                    )
                state.last_status = dict(data)
                state.active = False
            self._finalize_trace_artifact(
                state,
                terminal_reason=str(data.get("stop_reason") or "cancelled"),
            )
            return _success(
                self._trace_result_payload(state, data),
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except XdbgRpcError as exc:
            # An uncertain stop is unsafe: terminate the analyzer to close the
            # trace handle, then retain and register the bounded partial file.
            if runtime is not None:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            if state is not None:
                state.active = False
                self._finalize_trace_artifact(state, terminal_reason="stop_failed")
                self._attach_trace_artifact_details(exc, state)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            if runtime is not None:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            if state is not None:
                state.active = False
                self._finalize_trace_artifact(state, terminal_reason="stop_failed")
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def trace_status(self, session_id: str, *, timeout: float = 30.0) -> Result[JsonObject]:
        state: _TraceArtifactState | None = None
        runtime: _BackendRuntime | None = None
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            state = self._trace_owner.get(session_id)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                if "trace.status" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide trace.status",
                        details={"capability": "trace.status"},
                    )
                native = runtime.worker.request("trace.status", timeout=min(timeout, 30.0))
                if state is None:
                    return _success(
                        dict(native),
                        session_id=session_id,
                        backend=BackendKind.X64DBG.value,
                    )
                data = self._validate_trace_status(state, native)
                elapsed_ms = int((monotonic() - state.started_monotonic) * 1000)
                actual_size = state.path.stat().st_size if state.path.is_file() else 0
                if data["recording"] is True and (
                    elapsed_ms >= state.timeout_ms
                    or int(data["events_written"]) >= state.max_events
                    or actual_size >= state.max_file_bytes
                ):
                    # Defense in depth for an older/misbehaving native adapter.
                    # A current adapter normally returns terminal here itself.
                    stopped = runtime.worker.request("trace.stop", timeout=min(timeout, 30.0))
                    data = self._validate_trace_status(
                        state,
                        stopped,
                        require_recording=False,
                    )
                    if data["recording"] is True:
                        raise XdbgRpcError(
                            "trace_quota_enforcement_failed",
                            "trace remained active after a service-side quota stop",
                            details={"path": str(state.path)},
                        )
                    if elapsed_ms >= state.timeout_ms and data.get("stop_reason") in {
                        "none",
                        "cancelled",
                        "stopped",
                    }:
                        data["stop_reason"] = "timeout"
                        data["quota_stopped"] = True
                state.last_status = dict(data)
                state.active = bool(data["recording"])
            if not state.active:
                self._finalize_trace_artifact(
                    state,
                    terminal_reason=str(data.get("stop_reason") or "stopped"),
                )
            return _success(
                self._trace_result_payload(state, data),
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except XdbgRpcError as exc:
            if (
                state is not None
                and not state.active
                and state.artifact_id is not None
                and isinstance(state.last_status, dict)
            ):
                # Trace already finalized; do not tear down the debug session on a
                # stale status poll after the debuggee/trace ended.
                return _success(
                    self._trace_result_payload(state, state.last_status),
                    session_id=session_id,
                    backend=BackendKind.X64DBG.value,
                )
            if runtime is not None and (
                exc.code in _FATAL_WORKER_ERRORS
                or (state is not None and state.active)
                or exc.code in {"trace_quota_violation", "trace_quota_enforcement_failed"}
            ):
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            if state is not None and not state.active:
                self._finalize_trace_artifact(state, terminal_reason="status_failed")
                self._attach_trace_artifact_details(exc, state)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            if (
                state is not None
                and not state.active
                and state.artifact_id is not None
                and isinstance(state.last_status, dict)
            ):
                return _success(
                    self._trace_result_payload(state, state.last_status),
                    session_id=session_id,
                    backend=BackendKind.X64DBG.value,
                )
            if runtime is not None:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            if state is not None:
                state.active = False
                self._finalize_trace_artifact(state, terminal_reason="status_failed")
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def _new_trace_artifact_path(self, session_id: str) -> Path:
        if not session_id or Path(session_id).name != session_id:
            raise ValueError("invalid session id for trace artifact path")
        session = self.registry.get(session_id)
        directory = self.settings.artifact_root.expanduser().resolve() / "trace" / session_id
        directory.mkdir(parents=True, exist_ok=True)
        suffix = ".trace64" if session.architecture == Architecture.X64 else ".trace32"
        output = (directory / f"run-{uuid4().hex}{suffix}").resolve()
        if output.parent != directory:
            raise ValueError("trace artifact escaped the session artifact directory")
        return output

    def _validate_trace_status(
        self,
        state: _TraceArtifactState,
        payload: JsonObject,
        *,
        require_recording: bool | None = None,
    ) -> JsonObject:
        if not isinstance(payload, dict):
            raise XdbgRpcError("rpc_protocol_error", "x64dbg returned a non-object trace status")
        data = dict(payload)
        if type(data.get("recording")) is not bool:
            raise XdbgRpcError("rpc_protocol_error", "trace status has no boolean recording field")
        if require_recording is True and data["recording"] is not True:
            raise XdbgRpcError("trace_start_failed", "x64dbg did not enter trace recording state")
        if require_recording is False and data["recording"] is not False:
            raise XdbgRpcError("trace_stop_failed", "x64dbg did not leave trace recording state")
        returned_path = data.get("path")
        try:
            resolved_path = Path(str(returned_path)).resolve()
        except (OSError, ValueError, TypeError) as exc:
            raise XdbgRpcError(
                "rpc_protocol_error", "trace status returned an invalid artifact path"
            ) from exc
        if resolved_path != state.path:
            raise XdbgRpcError(
                "rpc_protocol_error",
                "x64dbg trace path does not match the session-owned artifact",
                details={"expected": str(state.path), "actual": str(returned_path)},
            )
        expected = {
            "max_events": state.max_events,
            "timeout_ms": state.timeout_ms,
            "max_file_bytes": state.max_file_bytes,
        }
        for key, value in expected.items():
            # After stop/finalize, some adapters omit the original quota fields.
            if data.get(key) is None:
                data[key] = value
            if type(data.get(key)) is not int or data[key] != value:
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    f"trace status returned an invalid {key}",
                    details={"expected": value, "actual": data.get(key)},
                )
        for key in ("events_written", "file_bytes", "elapsed_ms"):
            # Native trace.start historically omits counters until the first sample.
            if data.get(key) is None:
                data[key] = 0
            if type(data.get(key)) is not int or int(data[key]) < 0:
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    f"trace status returned an invalid {key}",
                )
        if not isinstance(data.get("stop_reason"), str) or not data["stop_reason"]:
            data["stop_reason"] = "none"
        actual_size = state.path.stat().st_size if state.path.is_file() else 0
        if (
            int(data["events_written"]) > state.max_events
            or max(int(data["file_bytes"]), actual_size) > state.max_file_bytes
        ):
            raise XdbgRpcError(
                "trace_quota_violation",
                "trace artifact exceeded a hard quota; analyzer will be terminated",
                details={
                    "events_written": data["events_written"],
                    "max_events": state.max_events,
                    "file_bytes": max(int(data["file_bytes"]), actual_size),
                    "max_file_bytes": state.max_file_bytes,
                    "path": str(state.path),
                },
            )
        return data

    def _stop_trace_after_failure(
        self,
        runtime: _BackendRuntime,
        state: _TraceArtifactState,
    ) -> bool:
        try:
            with runtime.lock:
                if "trace.stop" not in runtime.worker.capabilities:
                    return False
                stopped = runtime.worker.request("trace.stop", timeout=5.0)
                if not isinstance(stopped, dict) or stopped.get("recording") is not False:
                    return False
                state.last_status = dict(stopped)
            state.active = False
            return True
        except BaseException:
            return False

    def _finalize_trace_artifact(
        self,
        state: _TraceArtifactState,
        *,
        terminal_reason: str,
    ) -> None:
        with self._lock:
            if state.artifact_id is not None:
                state.active = False
                state.terminal_reason = terminal_reason
                return
            state.active = False
            state.terminal_reason = terminal_reason
            expected_root = (
                self.settings.artifact_root.expanduser().resolve() / "trace" / state.session_id
            )
            if state.path.parent != expected_root:
                state.artifact_error = "trace artifact is outside its session-owned root"
                return
            try:
                if not state.path.is_file():
                    state.artifact_error = "trace artifact file is missing"
                    return
                size = state.path.stat().st_size
                if size > state.max_file_bytes:
                    # The native writer should make this unreachable. Truncate only
                    # after the worker/file handle is closed and mark the artifact as
                    # partial so an over-quota file is never retained or advertised.
                    with state.path.open("r+b") as stream:
                        stream.truncate(state.max_file_bytes)
                    size = state.max_file_bytes
                    state.artifact_truncated = True
                    state.terminal_reason = "quota_violation"
                digest = file_sha256(state.path)
                artifact = self.repository.register_artifact(
                    session_id=state.session_id,
                    kind="run_trace_partial" if state.artifact_truncated else "run_trace",
                    path=state.path,
                    sha256=digest,
                    source="trace",
                    size=size,
                )
                state.artifact_id = str(artifact["id"])
                state.artifact_sha256 = digest
                state.artifact_size = size
                state.artifact_error = None
            except (OSError, ValueError, TypeError, KeyError) as exc:
                state.artifact_error = str(exc)

    def _trace_result_payload(
        self,
        state: _TraceArtifactState,
        native: JsonObject,
    ) -> JsonObject:
        data = dict(native)
        data.update(
            {
                "path": str(state.path),
                "artifact_path": str(state.path),
                "requested_path": state.requested_path,
                "artifact_pending": state.active,
                "artifact_registered": state.artifact_id is not None,
                "artifact_id": state.artifact_id,
                "artifact_sha256": state.artifact_sha256,
                "artifact_size": state.artifact_size,
                "artifact_truncated": state.artifact_truncated,
                "artifact_error": state.artifact_error,
                "terminal_reason": state.terminal_reason,
                "session_owned": True,
            }
        )
        return data

    def _attach_trace_artifact_details(
        self,
        error: XdbgRpcError,
        state: _TraceArtifactState,
    ) -> None:
        error.details.update(
            {
                "artifact_path": str(state.path),
                "artifact_id": state.artifact_id,
                "artifact_sha256": state.artifact_sha256,
                "artifact_size": state.artifact_size,
                "artifact_truncated": state.artifact_truncated,
                "artifact_error": state.artifact_error,
            }
        )

    def _finalize_trace_after_worker_loss(
        self,
        session_id: str,
        *,
        reason: str,
    ) -> None:
        state = self._trace_owner.get(session_id)
        if state is None or state.artifact_id is not None:
            return
        state.active = False
        state.last_status = {
            **state.last_status,
            "recording": False,
            "stop_reason": reason,
            "failed": reason not in {"session_closed", "target_exited"},
        }
        self._finalize_trace_artifact(state, terminal_reason=reason)

    def sync_static_to_runtime(
        self,
        session_id: str,
        address: int,
    ) -> Result[JsonObject]:
        return self._sync_address(session_id, "static", address)

    def sync_runtime_to_static(
        self,
        session_id: str,
        address: int,
    ) -> Result[JsonObject]:
        return self._sync_address(session_id, "runtime", address)

    def resolve_runtime_address(
        self,
        session_id: str,
        address: int,
        *,
        source: str = "static",
    ) -> Result[JsonObject]:
        """Resolve a static VA, module RVA, or runtime VA to the live runtime VA.

        The payload always carries a top-level ``runtime_address`` so a caller can
        act on one field instead of repeating rebase math per coordinate system.
        """
        try:
            if isinstance(address, bool) or type(address) is not int or address < 0:
                raise ValueError("address must be a non-negative integer")
            normalized = (source or "static").strip().casefold()
            if normalized not in {"static", "rva", "runtime"}:
                raise ValueError("source must be one of: static, rva, runtime")
            mapping = self._main_module_mapping(session_id)
            if normalized == "rva":
                data = mapping.translate("static", mapping.static.from_rva(address))
            elif normalized == "runtime":
                data = mapping.translate("runtime", address)
            else:
                data = mapping.translate("static", address)
            payload: JsonObject = {
                **data,
                "requested": {"address": address, "source": normalized},
                "runtime_address": data["runtime"]["address"],
                "static_address": data["static"]["address"],
            }
            return _success(
                payload,
                session_id=session_id,
                source_backend=BackendKind.IDA.value,
                target_backend=BackendKind.X64DBG.value,
            )
        except IdaWorkerError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.IDA)
            return _failure(exc, session_id=session_id, backend=BackendKind.IDA.value)
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def analyze_function_dynamic(
        self,
        session_id: str,
        address: int,
        *,
        address_space: str = "static",
        timeout: float = 30.0,
        decompile: bool = True,
    ) -> Result[JsonObject]:
        """Decompile one function, arm it at runtime, resume, and report the stop.

        Static decompilation is best-effort context and never blocks the dynamic
        half. Arming failures fail closed, and the reply reports the observed
        instruction pointer so a caller can tell "stopped on my breakpoint" apart
        from "stopped somewhere else".
        """
        try:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
                raise ValueError("timeout must be a number")
            if not 0 < float(timeout) <= _MAX_WORKFLOW_TIMEOUT:
                raise ValueError(f"timeout must be > 0 and <= {_MAX_WORKFLOW_TIMEOUT}")

            resolved = self.resolve_runtime_address(
                session_id,
                address,
                source=address_space,
            )
            if not resolved.ok or resolved.data is None:
                return resolved
            coordinates = resolved.data
            runtime_address = int(coordinates["runtime_address"])
            static_address = int(coordinates["static_address"])

            static_section: JsonObject = {"decompiled": bool(decompile)}
            if decompile:
                decompiled = self.static_decompile(session_id, address=static_address)
                if decompiled.ok and decompiled.data is not None:
                    static_section["decompilation"] = decompiled.data
                else:
                    static_section["decompiled"] = False
                    static_section["error"] = (
                        decompiled.error.model_dump(mode="json")
                        if decompiled.error is not None
                        else "decompilation unavailable"
                    )

            armed = self.dynamic_breakpoint_set(session_id, runtime_address)
            if not armed.ok:
                return armed

            resumed = self.dynamic_resume(
                session_id,
                wait_for_pause=True,
                timeout=float(timeout),
            )
            execution: JsonObject = {"resumed": bool(resumed.ok)}
            if resumed.ok and resumed.data is not None:
                execution["state"] = resumed.data.get("state")
            elif resumed.error is not None:
                execution["error"] = resumed.error.model_dump(mode="json")

            registers: JsonObject | None = None
            if resumed.ok:
                register_result = self.dynamic_registers_read(session_id)
                if register_result.ok and register_result.data is not None:
                    registers = register_result.data

            pointer = _instruction_pointer(registers)
            execution["instruction_pointer"] = pointer
            execution["stopped_at_breakpoint"] = (
                None if pointer is None else pointer == runtime_address
            )

            return _success(
                {
                    "function": {
                        "static_address": static_address,
                        "runtime_address": runtime_address,
                        "rva": coordinates.get("rva"),
                        "rebase_delta": coordinates.get("rebase_delta"),
                        "module": coordinates.get("module"),
                    },
                    "static": static_section,
                    "breakpoint": {"address": runtime_address, "armed": True},
                    "execution": execution,
                    "registers": registers,
                },
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def trace_api_arguments(
        self,
        session_id: str,
        expression: str | None = None,
        *,
        address: int | None = None,
        max_hits: int = 4,
        argument_count: int = 4,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Break on an API and capture its integer arguments on each hit.

        x64 arguments come from the Microsoft register convention and x86
        arguments are read off the stack above the return address. The breakpoint
        is always removed again, and a stop at another address ends the trace
        rather than mislabelling someone else's break as a hit.
        """
        try:
            if (expression is None) == (address is None):
                raise ValueError("provide exactly one of expression or address")
            if isinstance(max_hits, bool) or type(max_hits) is not int or not 1 <= max_hits <= 64:
                raise ValueError("max_hits must be 1..64")
            if (
                isinstance(argument_count, bool)
                or type(argument_count) is not int
                or not 0 <= argument_count <= len(_X64_ARGUMENT_REGISTERS)
            ):
                raise ValueError(
                    f"argument_count must be 0..{len(_X64_ARGUMENT_REGISTERS)}"
                )
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
                raise ValueError("timeout must be a number")
            if not 0 < float(timeout) <= _MAX_WORKFLOW_TIMEOUT:
                raise ValueError(f"timeout must be > 0 and <= {_MAX_WORKFLOW_TIMEOUT}")

            architecture = self.registry.get(session_id).architecture
            decodes_registers = architecture == Architecture.X64
            resolution: JsonObject | None = None
            target_address = address
            if expression is not None:
                resolved = self.symbols_resolve(
                    session_id,
                    expression,
                    timeout=float(timeout),
                )
                if not resolved.ok or resolved.data is None:
                    return resolved
                resolution = resolved.data
                candidate = resolution.get("address")
                if not isinstance(candidate, int) or isinstance(candidate, bool):
                    raise ValueError("symbol resolution did not return an address")
                target_address = candidate
            if target_address is None:
                raise ValueError("unable to determine a trace address")

            armed = self.dynamic_breakpoint_set(session_id, target_address)
            if not armed.ok:
                return armed

            hits: list[JsonObject] = []
            stopped_elsewhere = False
            try:
                for sequence in range(int(max_hits)):
                    resumed = self.dynamic_resume(
                        session_id,
                        wait_for_pause=True,
                        timeout=float(timeout),
                    )
                    if not resumed.ok:
                        break
                    register_result = self.dynamic_registers_read(session_id)
                    registers = register_result.data if register_result.ok else None
                    pointer = _instruction_pointer(registers)
                    if pointer is not None and pointer != target_address:
                        stopped_elsewhere = True
                        break
                    if decodes_registers:
                        arguments = _register_arguments(registers, int(argument_count))
                    else:
                        stack = self.stack_read(
                            session_id,
                            count=int(argument_count) + 1,
                            timeout=float(timeout),
                        )
                        arguments = _stack_arguments(
                            stack.data if stack.ok else None,
                            int(argument_count),
                        )
                    hits.append(
                        {
                            "sequence": sequence,
                            "instruction_pointer": pointer,
                            "arguments": arguments,
                        }
                    )
            finally:
                self.dynamic_breakpoint_remove(session_id, target_address)

            return _success(
                {
                    "target": {
                        "expression": expression,
                        "address": target_address,
                        "resolution": resolution,
                    },
                    "architecture": architecture.value,
                    "convention": (
                        "microsoft_x64_integer_registers"
                        if decodes_registers
                        else "x86_stack_arguments"
                    ),
                    "hits": hits,
                    "hit_count": len(hits),
                    "max_hits": int(max_hits),
                    "truncated": len(hits) >= int(max_hits),
                    "stopped_elsewhere": stopped_elsewhere,
                },
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def _explicit_module_operation(
        self,
        session_id: str,
        selector: ModuleSelector,
        *,
        source: Literal["preferred", "runtime"] | None,
        address: int | None = None,
    ) -> Result[JsonObject]:
        try:
            runtime, module_result, runtime_metadata = self._runtime_module_snapshot(session_id)
            mapping = build_rebased_module_mapping(
                module_result,
                runtime_metadata,
                selector,
            )
            if source is None:
                data = mapping.to_dict()
            else:
                if address is None:
                    raise ValueError("address is required for module translation")
                data = mapping.translate(source, address)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
            return _success(
                data,
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
                snapshot="current",
            )
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def _runtime_module_snapshot(
        self,
        session_id: str,
    ) -> tuple[_BackendRuntime, JsonObject, JsonObject]:
        runtime = self._runtime(session_id, BackendKind.X64DBG)
        with runtime.lock:
            self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
            if "modules.list" not in runtime.worker.capabilities:
                raise XdbgRpcError(
                    "capability_unavailable",
                    "backend does not provide modules.list",
                    details={"capability": "modules.list"},
                )
            modules = runtime.worker.request("modules.list", timeout=30.0)
            metadata = runtime.worker.metadata
            runtime.snapshot_resync_required = False
        return runtime, modules, metadata

    def _require_snapshot_fresh_locked(
        self,
        runtime: _BackendRuntime,
        *,
        operation: str,
    ) -> None:
        if runtime.snapshot_resync_required:
            raise XdbgRpcError(
                "event_gap_resync_required",
                "debug events were dropped; re-read modules.list/state before continuing",
                details={
                    "operation": operation,
                    "next": ["modules.list", "dynamic.state"],
                },
                retryable=True,
            )

    def _main_module_mapping(self, session_id: str) -> ModuleMapping:
        """Build the IDA<->x64dbg mapping for the session main module."""
        session = self.registry.get(session_id)
        static_runtime = self._runtime(session_id, BackendKind.IDA)
        dynamic_runtime = self._runtime(session_id, BackendKind.X64DBG)
        with static_runtime.lock, dynamic_runtime.lock:
            self._require_current_runtime(session_id, BackendKind.IDA, static_runtime)
            self._require_current_runtime(session_id, BackendKind.X64DBG, dynamic_runtime)
            if "modules.list" not in dynamic_runtime.worker.capabilities:
                raise XdbgRpcError(
                    "capability_unavailable",
                    "backend does not provide modules.list",
                    details={"capability": "modules.list"},
                )
            runtime_modules = dynamic_runtime.worker.request(
                "modules.list",
                timeout=30.0,
            )
            return build_main_module_mapping(
                session,
                static_runtime.worker.metadata,
                runtime_modules,
                dynamic_runtime.worker.metadata,
            )

    def _sync_address(
        self,
        session_id: str,
        source: Literal["static", "runtime"],
        address: int,
    ) -> Result[JsonObject]:
        try:
            data = self._main_module_mapping(session_id).translate(source, address)
            return _success(
                data,
                session_id=session_id,
                source_backend=(
                    BackendKind.IDA.value if source == "static" else BackendKind.X64DBG.value
                ),
                target_backend=(
                    BackendKind.X64DBG.value if source == "static" else BackendKind.IDA.value
                ),
            )
        except IdaWorkerError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.IDA)
            return _failure(exc, session_id=session_id, backend=BackendKind.IDA.value)
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def _workflow_request(
        self,
        session_id: str,
        action: Callable[[_BackendRuntime], JsonObject],
    ) -> Result[JsonObject]:
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                data = action(runtime)
            return _success(
                data,
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def _require_event_cursor(self, runtime: _BackendRuntime) -> DebugEventCursor:
        cursor = runtime.event_cursor
        if cursor is None:
            raise XdbgRpcError(
                "rpc_protocol_error",
                "dynamic runtime has no event cursor",
            )
        return cursor

    def _require_workflow(self, session_id: str) -> WorkflowRuntime:
        workflow = self._workflow_owner.get(session_id)
        if workflow is None:
            raise XdbgRpcError(
                "rpc_protocol_error",
                "dynamic runtime has no workflow state",
            )
        return workflow

    def _require_mutable_workflow(self, session_id: str) -> WorkflowRuntime:
        workflow = self._require_workflow(session_id)
        if workflow.status == WorkflowRunStatus.FAILED:
            raise WorkflowInvariantError(
                "workflow is failed; call workflow.reset before modifying it"
            )
        return workflow

    def _execute_workflow_transition_locked(
        self,
        session_id: str,
        runtime: _BackendRuntime,
        workflow: WorkflowRuntime,
        transition: WorkflowTransition,
        *,
        timeout: float,
        status: WorkflowRunStatus | None = None,
    ) -> WorkflowRuntime:
        try:
            execution = execute_workflow_transition(
                transition,
                _ServiceWorkflowPort(self, session_id, runtime),
                timeout=timeout,
            )
        except WorkflowExecutionError as exc:
            self._record_workflow_failure_locked(session_id, workflow, exc)
            raise exc.cause from exc
        resolved_status = status or _workflow_status_for_state(execution.state)
        updated = advance_workflow_runtime(
            workflow,
            execution.state,
            status=resolved_status,
            operations=1 + execution.operation_count,
        )
        self._workflow_owner.put(session_id, updated)
        return updated

    def _record_workflow_failure_locked(
        self,
        session_id: str,
        workflow: WorkflowRuntime,
        error: WorkflowExecutionError,
    ) -> WorkflowRuntime:
        code, details, retryable = _workflow_failure(error.cause)
        failed = fail_workflow_runtime(
            workflow,
            code=code,
            message=str(error.cause),
            details=details,
            retryable=retryable,
            state=error.execution.state,
            operations=1 + error.execution.operation_count,
        )
        self._workflow_owner.put(session_id, failed)
        return failed

    def _consume_workflow_batch_locked(
        self,
        session_id: str,
        runtime: _BackendRuntime,
        batch: DebugEventBatch,
        *,
        timeout: float,
    ) -> None:
        workflow = self._require_workflow(session_id)
        if workflow.status == WorkflowRunStatus.FAILED:
            return
        if workflow.state.lifecycle.cursor != batch.cursor:
            raise XdbgRpcError(
                "rpc_protocol_error",
                "workflow and dynamic event cursors diverged",
                details={
                    "workflow_cursor": workflow.state.lifecycle.cursor,
                    "event_cursor": batch.cursor,
                },
            )
        try:
            transition = consume_workflow_events(workflow.state, batch)
        except BaseException as exc:
            code, details, retryable = _workflow_failure(exc)
            self._workflow_owner.put(
                session_id,
                fail_workflow_runtime(
                    workflow,
                    code=code,
                    message=str(exc),
                    details=details,
                    retryable=retryable,
                ),
            )
            raise
        self._execute_workflow_transition_locked(
            session_id,
            runtime,
            workflow,
            transition,
            timeout=timeout,
        )

    def _workflow_navigate(
        self,
        session_id: str,
        pattern: EventPattern,
        *,
        timeout: float,
        event_budget: int,
    ) -> Result[JsonObject]:
        validated = _workflow_timeout(timeout)
        if isinstance(validated, ValueError):
            return _failure(validated, session_id=session_id)
        if type(event_budget) is not int or not 1 <= event_budget <= _MAX_WORKFLOW_EVENT_BUDGET:
            return _failure(
                ValueError(f"event_budget must be between 1 and {_MAX_WORKFLOW_EVENT_BUDGET}"),
                session_id=session_id,
            )

        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_mutable_workflow(session_id)
            return self._navigate_locked(
                session_id,
                runtime,
                workflow,
                pattern,
                timeout=validated,
                event_budget=event_budget,
            )

        return self._workflow_request(session_id, action)

    def _navigate_locked(
        self,
        session_id: str,
        runtime: _BackendRuntime,
        workflow: WorkflowRuntime,
        pattern: EventPattern,
        *,
        timeout: float,
        event_budget: int,
    ) -> JsonObject:
        if "events.read" not in runtime.worker.capabilities:
            raise XdbgRpcError(
                "capability_unavailable",
                "backend does not provide events.read",
                details={"capability": "events.read"},
            )
        started = start_workflow_navigation(
            workflow.state,
            pattern,
            event_budget=event_budget,
        )
        workflow = self._execute_workflow_transition_locked(
            session_id,
            runtime,
            workflow,
            started,
            timeout=timeout,
            status=WorkflowRunStatus.ACTIVE,
        )
        deadline = monotonic() + timeout
        dynamic = cast(DynamicWorker, runtime.worker)
        cursor = self._require_event_cursor(runtime)

        while True:
            navigation = workflow.state.navigation
            if navigation is None or navigation.status != NavigationStatus.WAITING:
                return {"workflow": workflow.to_dict()}
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = timeout_workflow_navigation(workflow.state)
                workflow = self._execute_workflow_transition_locked(
                    session_id,
                    runtime,
                    workflow,
                    timed_out,
                    timeout=min(5.0, max(0.1, timeout)),
                    status=WorkflowRunStatus.IDLE,
                )
                return {"workflow": workflow.to_dict()}

            available_budget = navigation.event_budget - navigation.observed_events
            limit = min(MAX_DEBUG_EVENT_BATCH, max(1, available_budget))
            batch = dynamic.read_events(
                cursor.value,
                limit=limit,
                timeout=min(5.0, max(0.1, remaining)),
            )
            try:
                cursor.advance(batch)
            except DebugEventProtocolError as exc:
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    f"x64dbg event cursor is inconsistent: {exc}",
                ) from exc
            self._consume_workflow_batch_locked(
                session_id,
                runtime,
                batch,
                timeout=min(remaining, 30.0),
            )
            workflow = self._require_workflow(session_id)
            if not batch.events and not batch.has_more:
                sleep(min(0.05, max(0.0, deadline - monotonic())))

    def _workflow_state_locked(
        self,
        session_id: str,
        runtime: _BackendRuntime,
        *,
        timeout: float,
    ) -> JsonObject:
        self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
        self._require_workflow_capability(runtime, "debug.state")
        state = runtime.worker.request(
            "debug.state",
            timeout=min(timeout, 30.0),
        )
        self._observe_debuggee_state(session_id, state)
        return state

    def _workflow_resume_locked(
        self,
        session_id: str,
        runtime: _BackendRuntime,
        *,
        timeout: float,
    ) -> None:
        state = self._workflow_state_locked(
            session_id,
            runtime,
            timeout=timeout,
        )
        if state.get("state") == "running":
            return
        if state.get("state") != "paused":
            raise XdbgRpcError(
                "not_debugging",
                "workflow navigation requires an active debuggee",
            )
        self._require_workflow_capability(runtime, "debug.resume")
        submitted = runtime.worker.request(
            "debug.resume",
            timeout=min(timeout, 30.0),
        )
        self._observe_debuggee_state(session_id, submitted)

    def _workflow_ensure_paused_locked(
        self,
        session_id: str,
        runtime: _BackendRuntime,
        *,
        timeout: float,
    ) -> None:
        state = self._workflow_state_locked(
            session_id,
            runtime,
            timeout=timeout,
        )
        if state.get("state") in {"idle", "paused"}:
            return
        self._require_workflow_capability(runtime, "debug.pause")
        submitted = runtime.worker.request(
            "debug.pause",
            timeout=min(timeout, 30.0),
        )
        dynamic = cast(DynamicWorker, runtime.worker)
        paused = dynamic.wait_for_state(
            {"paused"},
            timeout=timeout,
        )
        self._observe_debuggee_state(session_id, paused)
        if submitted.get("debugging") is not True:
            raise XdbgRpcError(
                "not_debugging",
                "debuggee stopped while workflow was pausing it",
            )

    def _workflow_apply_breakpoint_locked(
        self,
        session_id: str,
        runtime: _BackendRuntime,
        operation: BreakpointOperation,
        *,
        timeout: float,
    ) -> None:
        state = self._workflow_state_locked(
            session_id,
            runtime,
            timeout=timeout,
        )
        if state.get("state") == "idle":
            if operation.kind == BreakpointOperationKind.REMOVE:
                return
            raise XdbgRpcError(
                "not_debugging",
                "cannot set a workflow breakpoint without an active debuggee",
            )
        if state.get("state") == "running":
            self._workflow_ensure_paused_locked(
                session_id,
                runtime,
                timeout=timeout,
            )
        method = (
            "breakpoints.remove"
            if operation.kind == BreakpointOperationKind.REMOVE
            else "breakpoints.set"
        )
        self._require_workflow_capability(runtime, method)
        try:
            runtime.worker.request(
                method,
                {"address": operation.address},
                timeout=min(timeout, 30.0),
            )
        except XdbgRpcError as exc:
            if (
                operation.kind != BreakpointOperationKind.REMOVE
                or exc.code != "debugger_command_failed"
            ):
                raise
            self._require_workflow_capability(runtime, "breakpoints.list")
            listed = runtime.worker.request(
                "breakpoints.list",
                timeout=min(timeout, 30.0),
            )
            breakpoints = listed.get("breakpoints")
            if not isinstance(breakpoints, list):
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    "x64dbg returned an invalid breakpoint list",
                ) from exc
            for breakpoint in breakpoints:
                if not isinstance(breakpoint, dict):
                    raise XdbgRpcError(
                        "rpc_protocol_error",
                        "x64dbg returned an invalid breakpoint entry",
                    ) from exc
                address = breakpoint.get("address")
                if type(address) is not int:
                    raise XdbgRpcError(
                        "rpc_protocol_error",
                        "x64dbg returned a breakpoint without a valid address",
                    ) from exc
                if address == operation.address:
                    raise

    def _workflow_resolve_module_locked(
        self,
        session_id: str,
        runtime: _BackendRuntime,
        selector: ModuleSelector,
        *,
        timeout: float,
    ) -> RebasedModuleMapping:
        self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
        self._require_workflow_capability(runtime, "modules.list")
        modules = runtime.worker.request(
            "modules.list",
            timeout=min(timeout, 30.0),
        )
        return build_rebased_module_mapping(
            modules,
            runtime.worker.metadata,
            selector,
        )

    def _workflow_refresh_modules_locked(
        self,
        session_id: str,
        runtime: _BackendRuntime,
        selectors: Mapping[str, ModuleSelector],
        *,
        timeout: float,
    ) -> dict[str, RebasedModuleMapping | None]:
        self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
        self._require_workflow_capability(runtime, "modules.list")
        modules = runtime.worker.request(
            "modules.list",
            timeout=min(timeout, 30.0),
        )
        metadata = runtime.worker.metadata
        resolutions: dict[str, RebasedModuleMapping | None] = {}
        for key, selector in selectors.items():
            try:
                resolutions[key] = build_rebased_module_mapping(
                    modules,
                    metadata,
                    selector,
                )
            except AddressSyncError as exc:
                if exc.code != "module_not_found":
                    raise
                resolutions[key] = None
        return resolutions

    def _require_workflow_capability(
        self,
        runtime: _BackendRuntime,
        capability: str,
    ) -> None:
        if capability not in runtime.worker.capabilities:
            raise XdbgRpcError(
                "capability_unavailable",
                f"backend does not provide {capability}",
                details={"capability": capability},
            )

    @staticmethod
    def _absorb_redundant_run_control(
        dynamic: DynamicWorker,
        method: str,
        wait_for: set[str] | None,
        failure: XdbgRpcError,
        timeout: float,
    ) -> JsonObject:
        """Treat a pause the target already satisfied as success.

        The debugger checks whether the target is running and only then issues the
        command, so a breakpoint hit in that window makes it reject a pause that
        has effectively already happened. Reporting that as a failure would make a
        correct outcome look like a broken session.

        Only pause qualifies. A step or a resume is rejected while the target is
        paused, which is also its state before the command, so the state can never
        show the command ran; absorbing those would report a step that never
        happened as success whenever the event ring dropped the transition.
        """
        if failure.code != "debugger_command_failed" or method != "debug.pause":
            raise failure
        if not wait_for or "paused" not in wait_for:
            raise failure
        try:
            current = dynamic.request("debug.state", {}, timeout=min(timeout, 5.0))
        except BaseException:
            # The probe failing says nothing about the command; surface the real
            # reason the caller asked about rather than the reason we could not
            # check it.
            raise failure from None
        if str(current.get("state")) != "paused":
            raise failure
        return current

    def _dynamic_request(
        self,
        session_id: str,
        method: str,
        params: JsonObject | None = None,
        *,
        wait_for: set[str] | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                if method not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        f"backend does not provide {method}",
                        details={"capability": method},
                    )
                transition_event_kinds = _RUN_CONTROL_TRANSITION_EVENTS.get(
                    method,
                    frozenset(),
                )
                after_event_sequence: int | None = None
                dynamic = cast(DynamicWorker, runtime.worker)
                if wait_for is not None and transition_event_kinds:
                    if "events.read" not in runtime.worker.capabilities:
                        raise XdbgRpcError(
                            "capability_unavailable",
                            "backend cannot verify run-control transitions without events.read",
                            details={"capability": "events.read", "method": method},
                        )
                    marker = dynamic.read_events(
                        0,
                        limit=1,
                        timeout=min(timeout, 5.0),
                    )
                    after_event_sequence = marker.latest_sequence
                try:
                    submitted = runtime.worker.request(
                        method,
                        params,
                        timeout=min(timeout, 30.0),
                    )
                except XdbgRpcError as exc:
                    submitted = self._absorb_redundant_run_control(
                        dynamic, method, wait_for, exc, timeout
                    )
                state = submitted
                if wait_for is not None:
                    state = dynamic.wait_for_state(
                        wait_for,
                        timeout=timeout,
                        after_event_sequence=after_event_sequence,
                        transition_event_kinds=transition_event_kinds,
                    )
                if method.startswith("debug."):
                    self._observe_debuggee_state(session_id, state)
            data = state if wait_for is None else {"submitted": submitted, "state": state}
            return _success(
                data,
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def _runtime(self, session_id: str, kind: BackendKind) -> _BackendRuntime:
        session = self.registry.get(session_id)
        if session.state in {
            SessionState.OPENING,
            SessionState.CLOSING,
            SessionState.CLOSED,
            SessionState.FAILED,
        }:
            raise InvalidStateTransition(
                f"{kind.value} operation cannot run in {session.state.value} state"
            )
        runtime = self._runtime_owner.get(session_id, kind)
        if runtime is not None:
            return runtime
        if kind == BackendKind.IDA:
            raise IdaWorkerError("backend_unavailable", "IDA worker is not open")
        raise XdbgRpcError("backend_unavailable", "x64dbg worker is not open")

    def _require_current_runtime(
        self,
        session_id: str,
        kind: BackendKind,
        runtime: _BackendRuntime,
    ) -> None:
        if not self._runtime_owner.is_current(session_id, kind, runtime):
            raise InvalidStateTransition(f"session backend is closing: {session_id}")

    def _observe_debuggee_state(self, session_id: str, state: JsonObject) -> JsonObject:
        session = self.registry.get(session_id)
        handle = session.backends.get(BackendKind.X64DBG)
        debugger_pid = handle.pid if handle is not None else None
        return cast(
            JsonObject,
            self._debuggee_owner.observe(
                session_id,
                state,
                debugger_pid=debugger_pid,
            ),
        )

    def _annotate_debuggee_pids(
        self,
        session_id: str,
        state: JsonObject,
    ) -> JsonObject:
        """Attach debuggee/debugger PID fields without changing lifecycle state."""
        session = self.registry.get(session_id)
        handle = session.backends.get(BackendKind.X64DBG)
        process_id = state.get("process_id")
        snapshot = DebuggeeSnapshot(
            state=str(state.get("state") or "unknown"),
            debuggee_pid=(
                process_id if isinstance(process_id, int) and process_id > 0 else None
            ),
            debugger_pid=handle.pid if handle is not None else None,
        )
        return cast(JsonObject, DebuggeeStateOwner.annotate(state, snapshot))

    def _stop_event_drain(self, runtime: _BackendRuntime) -> None:
        pump = runtime.event_drain_pump
        runtime.event_drain_pump = None
        if pump is not None:
            with suppress(Exception):
                pump.stop()
        log = runtime.event_log
        runtime.event_log = None
        if log is not None:
            with suppress(Exception):
                log.close()

    def _fail_runtime(
        self,
        session_id: str,
        kind: BackendKind,
        *,
        failure: BaseException | None = None,
    ) -> None:
        runtime = self._runtime_owner.fail(session_id, kind)
        # Without this the backend keeps being reported as unhealthy for the life
        # of the process, with a checked_at that never advances.
        self._health.forget(session_id)
        if runtime is not None and kind == BackendKind.X64DBG:
            self._stop_event_drain(runtime)
            workflow = self._workflow_owner.get(session_id)
            if workflow is not None:
                if workflow.status != WorkflowRunStatus.FAILED:
                    code, details, retryable = _workflow_failure(
                        failure or RuntimeError("x64dbg runtime failed")
                    )
                    workflow = fail_workflow_runtime(
                        workflow,
                        code=code,
                        message=str(failure or "x64dbg runtime failed"),
                        details=details,
                        retryable=retryable,
                    )
                self._workflow_owner.put_terminal(session_id, workflow)
        if runtime is not None:
            runtime.worker.terminate()
            if kind == BackendKind.X64DBG:
                self._finalize_trace_after_worker_loss(
                    session_id,
                    reason="worker_failed",
                )
        with suppress(KeyError, InvalidStateTransition):
            self.registry.detach_backend(session_id, kind)
            self.registry.transition(session_id, SessionState.FAILED)


def _create_ida_worker(session: Session, settings: Settings) -> StaticWorker:
    return IdaWorkerClient(session.binary, settings)


def _create_xdbg_worker(session: Session, settings: Settings) -> DynamicWorker:
    executable = {
        Architecture.X86: settings.x64dbg_headless_x86,
        Architecture.X64: settings.x64dbg_headless_x64,
    }[session.architecture]
    if executable is None:
        variable = (
            "HEADLESS_RE_X64DBG_HEADLESS_X86"
            if session.architecture == Architecture.X86
            else "HEADLESS_RE_X64DBG_HEADLESS_X64"
        )
        raise XdbgRpcError(
            "backend_unavailable",
            f"x64dbg {session.architecture.value} headless executable is not configured",
            details={"environment_variable": variable},
        )
    return XdbgClient(
        executable,
        session.architecture,
        hidden_desktop=settings.hidden_desktop,
    )


_X64_ARGUMENT_REGISTERS = ("rcx", "rdx", "r8", "r9")


def _register_arguments(registers: JsonObject | None, count: int) -> list[JsonObject]:
    """Decode Microsoft x64 integer arguments from a registers payload."""
    if not isinstance(registers, dict) or count <= 0:
        return []
    nested = registers.get("registers")
    bank = nested if isinstance(nested, dict) else registers
    arguments: list[JsonObject] = []
    for index, name in enumerate(_X64_ARGUMENT_REGISTERS[:count]):
        value = bank.get(name)
        usable = isinstance(value, int) and not isinstance(value, bool)
        arguments.append(
            {
                "index": index,
                "source": name,
                "value": value if usable else None,
            }
        )
    return arguments


def _recover_backend_kinds(backends: list[str]) -> tuple[BackendKind, ...]:
    """Normalise caller backend names, rejecting anything unrecognised."""
    kinds: list[BackendKind] = []
    for raw in backends:
        name = str(raw).strip().casefold()
        if name in {"ida", "static"}:
            kind = BackendKind.IDA
        elif name in {"x64dbg", "dynamic"}:
            kind = BackendKind.X64DBG
        else:
            raise ValueError("backends entries must be one of: ida, static, x64dbg, dynamic")
        if kind not in kinds:
            kinds.append(kind)
    return tuple(kinds)


def _stack_arguments(payload: JsonObject | None, count: int) -> list[JsonObject]:
    """Decode x86 cdecl/stdcall arguments sitting above the return address.

    At a function entry the top of stack holds the return address, so argument i
    lives at slot i+1 of a stack.read starting from the stack pointer.
    """
    if not isinstance(payload, dict) or count <= 0:
        return []
    entries = payload.get("entries")
    if not isinstance(entries, list):
        return []
    raw_width = payload.get("pointer_size")
    width = raw_width if isinstance(raw_width, int) and raw_width > 0 else 4
    arguments: list[JsonObject] = []
    for index in range(count):
        slot = index + 1
        entry = entries[slot] if slot < len(entries) else None
        value = entry.get("value") if isinstance(entry, dict) else None
        usable = isinstance(value, int) and not isinstance(value, bool)
        arguments.append(
            {
                "index": index,
                "source": f"[esp+{slot * width:#x}]",
                "value": value if usable else None,
            }
        )
    return arguments


def _instruction_pointer(registers: JsonObject | None) -> int | None:
    """Read rip/eip/pc from a registers payload without assuming one shape."""
    if not isinstance(registers, dict):
        return None
    nested = registers.get("registers")
    bank = nested if isinstance(nested, dict) else registers
    for name in ("rip", "eip", "pc"):
        candidate = bank.get(name)
        if isinstance(candidate, int) and not isinstance(candidate, bool):
            return candidate
    return None


def _desktop_monitor_pids(state: JsonObject) -> tuple[frozenset[int], int | None]:
    """Resolve a bounded target process set for passive desktop monitoring."""
    value = state.get("process_id") or state.get("debuggee_pid")
    if type(value) is not int or value <= 0 or not is_pid_alive(value):
        return frozenset(), None
    from headless_re_mcp.core.process_tree import enumerate_direct_children

    allowed = {value}
    for child in enumerate_direct_children(value):
        if is_pid_alive(child):
            allowed.add(child)
    return frozenset(allowed), value


def _select_desktop_window(
    windows: list[JsonObject],
    requested_hwnd: int | None,
) -> JsonObject:
    if requested_hwnd is not None:
        if type(requested_hwnd) is not int or requested_hwnd <= 0:
            raise ValueError("hwnd must be a positive integer")
        for row in windows:
            if row.get("hwnd") == requested_hwnd:
                return row
        raise XdbgRpcError(
            "not_found",
            "requested hwnd is not on the authorized hidden desktop",
            details={"hwnd": requested_hwnd},
        )
    if not windows:
        raise XdbgRpcError(
            "not_found",
            "the debuggee has no capturable hidden-desktop window",
        )
    return max(
        windows,
        key=lambda row: (
            bool(row.get("visible")),
            not bool(row.get("minimized")),
            int(row.get("area") or 0),
            bool(row.get("title")),
        ),
    )


def _workflow_timeout(value: float) -> float | ValueError:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not isfinite(value)
        or not 0 < value <= _MAX_WORKFLOW_TIMEOUT
    ):
        return ValueError(
            f"timeout must be greater than 0 and at most {_MAX_WORKFLOW_TIMEOUT:g} seconds"
        )
    return float(value)


def _detection_timeout(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not isfinite(value)
        or not 0 < value <= 300.0
    ):
        raise ValueError("timeout must be greater than 0 and at most 300 seconds")
    return float(value)


def _workflow_status_for_state(state: WorkflowState) -> WorkflowRunStatus:
    navigation = state.navigation
    if navigation is not None and navigation.status == NavigationStatus.WAITING:
        return WorkflowRunStatus.ACTIVE
    return WorkflowRunStatus.IDLE


def _workflow_failure(
    exc: BaseException,
) -> tuple[str, JsonObject, bool]:
    if isinstance(exc, AddressSyncError):
        return exc.code, dict(exc.details), False
    if isinstance(exc, (IdaWorkerError, XdbgRpcError)):
        return exc.code, dict(exc.details), exc.retryable
    if isinstance(exc, TimeoutError):
        return "workflow_timeout", {}, True
    if isinstance(exc, (InvalidStateTransition, ValueError)):
        return "invalid_request", {}, False
    return "workflow_execution_failed", {"exception": type(exc).__name__}, False


def _module_base_present(modules_payload: object, base: int) -> bool:
    if not isinstance(modules_payload, dict):
        return False
    modules = modules_payload.get("modules")
    if not isinstance(modules, list):
        return False
    return any(isinstance(item, dict) and int(item.get("base", 0) or 0) == base for item in modules)


def _session_json(session: Session) -> JsonObject:
    value = session.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("session model did not serialize to an object")
    return value


def _session_artifact_roots(artifact_root: Path, session_id: str) -> tuple[Path, ...]:
    """Return owned artifact subtrees for one session (fail-closed ownership)."""
    if not session_id or Path(session_id).name != session_id:
        return ()
    root = artifact_root.expanduser().resolve()
    return (
        root / "dotnet" / session_id,
        root / "unpack" / session_id,
        root / "dump" / session_id,
        root / "detection" / session_id,
    )


def _session_owns_artifact_path(
    artifact_root: Path,
    session_id: str,
    target: Path,
) -> bool:
    """True when ``target`` resolves under a session-owned artifact directory."""
    resolved = target.expanduser().resolve()
    for owned_root in _session_artifact_roots(artifact_root, session_id):
        try:
            owned = owned_root.resolve()
        except OSError:
            continue
        if resolved == owned or owned in resolved.parents:
            return True
    return False


def _atomic_write_bytes(destination: Path, payload: bytes) -> None:
    """Write ``payload`` via a sibling temp file and ``os.replace``."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{destination.stem}-",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None and temporary.exists():
            with suppress(OSError):
                temporary.unlink()


def _write_die_artifact(
    artifact_root: Path,
    session_id: str,
    result: DieScanResult,
) -> str:
    """Persist bounded raw DIE JSON with an atomic rename under the artifact root."""
    if not session_id or Path(session_id).name != session_id:
        raise OSError("invalid session id for artifact path")
    directory = artifact_root.expanduser().resolve() / "detection" / session_id
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"die-{uuid4().hex}.json"
    payload = {
        "schema_version": 1,
        "tool": "diec",
        "path": str(result.path),
        "size": result.size,
        "mode": result.mode.value,
        "scanned_at": result.scanned_at.isoformat(),
        "returncode": result.returncode,
        "stderr": result.stderr,
        "raw_json": result.raw_json,
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 8 * 1024 * 1024:
        raise OSError("DIE artifact exceeds the 8 MiB persistence limit")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=".die-",
            suffix=".tmp",
            dir=directory,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            with suppress(OSError):
                temporary.unlink()
    return str(destination)


def _exeinfope_log_path(artifact_root: Path, session_id: str) -> Path:
    if not session_id or Path(session_id).name != session_id:
        raise OSError("invalid session id for artifact path")
    directory = artifact_root.expanduser().resolve() / "detection" / session_id
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"exeinfope-{uuid4().hex}.log"


def _write_exeinfope_artifact(
    artifact_root: Path,
    session_id: str,
    result: ExeinfopeScanResult,
) -> str:
    """Persist bounded raw Exeinfo PE log metadata under the artifact root."""
    if not session_id or Path(session_id).name != session_id:
        raise OSError("invalid session id for artifact path")
    directory = artifact_root.expanduser().resolve() / "detection" / session_id
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"exeinfope-{uuid4().hex}.json"
    payload = {
        "schema_version": 1,
        "tool": "exeinfope",
        "path": str(result.path),
        "size": result.size,
        "mode": result.mode.value,
        "scanned_at": result.scanned_at.isoformat(),
        "returncode": result.returncode,
        "stderr": result.stderr,
        "log_path": str(result.log_path),
        "raw_log": result.raw_log,
        "analyzer_windows": list(result.analyzer_windows),
        "claims_universal_unpack": False,
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 8 * 1024 * 1024:
        raise OSError("Exeinfo PE artifact exceeds the 8 MiB persistence limit")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=".exeinfope-",
            suffix=".tmp",
            dir=directory,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            with suppress(OSError):
                temporary.unlink()
    return str(destination)


def _ui_finalize_windows(payload: JsonObject, ctx: JsonObject) -> JsonObject:
    allowed = ctx["allowed"]
    windows = payload.get("windows")
    if not isinstance(windows, list):
        windows = []
    assert isinstance(allowed, frozenset)
    for window in windows:
        if not isinstance(window, dict):
            continue
        owner = window.get("pid")
        if owner not in allowed:
            raise UiPidBoundaryError(
                "permission_denied",
                "window enumeration escaped allowed PID set",
                pid=owner,
                allowed_pids=sorted(allowed),
            )
    payload["windows"] = windows
    payload["count"] = len(windows)
    if len(windows) == 0:
        debuggee_pid = ctx.get("debuggee_pid")
        if isinstance(debuggee_pid, int) and debuggee_pid > 0 and is_pid_alive(debuggee_pid):
            try:
                from headless_re_mcp.core.process_tree import probe_child_window_candidates

                children = probe_child_window_candidates(debuggee_pid, list_windows_fn=None)
            except Exception:
                children = []
            if children:
                payload["hint"] = "windows_on_child_pids"
                payload["child_candidates"] = children
                payload["suggested_child_pids"] = [int(c["pid"]) for c in children]
                payload["suggestion"] = (
                    "Pass allow_child_pids=suggested_child_pids or "
                    "include_same_image_children=true"
                )
    return payload
