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
from threading import Event, RLock
from time import monotonic, sleep
from typing import Any, Literal, Protocol, cast
from uuid import uuid4

from headless_re_mcp.backends.adb import AdbBackend
from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.backends.ida.client import IdaWorkerClient, IdaWorkerError
from headless_re_mcp.backends.proxy import ProxyBackend
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError
from headless_re_mcp.backends.x64dbg.stealth import (
    DEFAULT_PROFILE_ID,
    X64_FORBIDDEN_PROFILES,
    StealthError,
    apply_profile,
    canonical_profile_id,
    inspect_layout,
    layout_for_headless,
    profile_id_for_section,
    stealth_hint_profile,
    summarize_settings,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.addressing import (
    AddressSyncError,
    ModuleMapping,
    RebasedModuleMapping,
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
from headless_re_mcp.core.limits import (
    MAX_WORKFLOW_TIMEOUT,
)
from headless_re_mcp.core.models import (
    Architecture,
    BackendHandle,
    BackendKind,
    ModuleSelector,
    Result,
    RpcError,
    Session,
    SessionState,
    TargetKind,
    TargetMismatch,
)
from headless_re_mcp.core.readiness import readiness_report
from headless_re_mcp.core.repository import AnalysisRepository, SqliteAnalysisRepository
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.retention import (
    DEFAULT_MAX_TOTAL_BYTES,
    ArtifactRetention,
    UsageCache,
)
from headless_re_mcp.core.runtime_state import (
    BackendRuntimeOwner,
    BackendRuntimePhase,
    DebuggeeSnapshot,
    DebuggeeStateOwner,
    TraceStateOwner,
    UnpackStateOwner,
    WorkflowStateOwner,
)
from headless_re_mcp.core.service_apk import ApkAnalysisMixin
from headless_re_mcp.core.service_detect import DetectAnalysisMixin
from headless_re_mcp.core.service_device import DeviceAnalysisMixin
from headless_re_mcp.core.service_dotnet import DotnetAnalysisMixin
from headless_re_mcp.core.service_dynamic_inspect import DynamicInspectMixin
from headless_re_mcp.core.service_ext import (
    _DEBUG_EVENT_BUDGET_PER_BATCH,
    ExtAnalysisMixin,
    _timeline_append,
    note_session_closed,
    note_session_created,
)
from headless_re_mcp.core.service_frida import FridaDeviceMixin
from headless_re_mcp.core.service_jsre import JsReAnalysisMixin
from headless_re_mcp.core.service_proxy import ProxyAnalysisMixin
from headless_re_mcp.core.service_static import StaticAnalysisMixin
from headless_re_mcp.core.service_trace import (
    TraceMixin,
    _instruction_pointer,
    _TraceArtifactState,
)
from headless_re_mcp.core.service_ui import UiAutomationMixin
from headless_re_mcp.core.service_unpack import UnpackMixin
from headless_re_mcp.core.service_unpack_cli import UnpackCliMixin
from headless_re_mcp.core.service_web import WebAnalysisMixin
from headless_re_mcp.core.service_workflow import WorkflowAnalysisMixin
from headless_re_mcp.core.service_workspace import WorkspaceMixin
from headless_re_mcp.core.session import (
    InvalidStateTransition,
    SessionNotFound,
    SessionRegistry,
    hydrate_persisted_sessions,
)
from headless_re_mcp.core.windows import (
    is_pid_alive,
)
from headless_re_mcp.detection.die import DieScanResult, scan_with_die
from headless_re_mcp.detection.exeinfope import (
    ExeinfopeScanResult,
    scan_with_exeinfope,
)
from headless_re_mcp.doctor import run_doctor
from headless_re_mcp.dotnet.de4dot import run_de4dot
from headless_re_mcp.dotnet.net_reactor_slayer import (
    run_net_reactor_slayer,
)
from headless_re_mcp.platform_support import unsupported_on_platform_details
from headless_re_mcp.telemetry import telemetry_log_path
from headless_re_mcp.unpack.scylla import (
    run_scylla,
)
from headless_re_mcp.unpack.session import (
    UnpackSessionState,
)
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
    cancel_workflow_navigation,
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
    drain_lock: RLock = field(default_factory=RLock)
    consume_peek_cursor: int | None = None
    # Set when an event batch reports dropped>0; cleared by a fresh modules.list.
    snapshot_resync_required: bool = False
    navigation_cancel: Event = field(default_factory=Event)


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
# Consumer-side cursor bookkeeping must not map to rpc_protocol_error: that
# code is fatal and would tear down x64dbg and the debuggee it still owns.
_CONSUMER_CURSOR_ERROR = "event_cursor_inconsistent"
_MAX_WORKFLOW_EVENT_BUDGET = 100_000
_OEP_REGION_SNAPSHOT_LIMIT = 512
_RUN_CONTROL_TRANSITION_EVENTS: dict[str, frozenset[str]] = {
    "debug.resume": frozenset({"debug.resumed"}),
    "debug.step_into": frozenset({"debug.resumed", "debug.stepped"}),
    "debug.step_over": frozenset({"debug.resumed", "debug.stepped"}),
}


class AnalysisService(
    DynamicInspectMixin,
    UiAutomationMixin,
    TraceMixin,
    UnpackMixin,
    StaticAnalysisMixin,
    DetectAnalysisMixin,
    DotnetAnalysisMixin,
    UnpackCliMixin,
    WorkflowAnalysisMixin,
    ApkAnalysisMixin,
    DeviceAnalysisMixin,
    FridaDeviceMixin,
    JsReAnalysisMixin,
    WebAnalysisMixin,
    ProxyAnalysisMixin,
    WorkspaceMixin,
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
        hydrate_persisted_sessions(self.registry, self.repository)
        # Long-lived optional backends are owned here so concurrent tool calls
        # cannot each construct one. Both constructors are cheap and import
        # nothing: playwright and mitmproxy are only imported on first use.
        self._web_backend = WebBackend()
        self._proxy_backend = ProxyBackend()
        self._adb_backend = AdbBackend(getattr(self.settings, "adb", None))
        self._runtime_owner: BackendRuntimeOwner[_BackendRuntime] = BackendRuntimeOwner()
        self._workflow_owner: WorkflowStateOwner[WorkflowRuntime] = WorkflowStateOwner()
        self._unpack_owner: UnpackStateOwner[UnpackSessionState] = UnpackStateOwner()
        self._unpack_cancel_events: dict[str, Event] = {}
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
        self._retention = ArtifactRetention(
            max_total_bytes=int(
                getattr(self.settings, "artifact_max_total_bytes", DEFAULT_MAX_TOTAL_BYTES)
            )
        )
        self._artifact_usage = UsageCache()
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

    def create_session(self, binary: str, target: str | None = None) -> Result[JsonObject]:
        try:
            kind = TargetKind(target) if target else None
            session = self.registry.create(binary, target=kind)
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

    def list_sessions(self, offset: int = 0, limit: int | None = None) -> Result[JsonObject]:
        """Page the in-process session list.

        Closed sessions are already capped in the registry. Open ones are not,
        and session.list used to return every one of them. Measured at 3000
        open web sessions: 878 KiB. A page of 100 is 29 KiB. ``limit=None``
        keeps the unpaged reply for the web console, which is not the agent.
        """
        sessions = [_session_json(session) for session in self.registry.list()]
        total = len(sessions)
        start = max(0, int(offset))
        if limit is None:
            page = sessions[start:]
        else:
            cap = max(1, min(int(limit), 1000))
            page = sessions[start : start + cap]
        return _success(
            {
                "sessions": page,
                "count": len(page),
                "total": total,
                "offset": start,
                "has_more": start + len(page) < total,
            }
        )

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
        try:
            already_open = session_id in self._runtime_owner.active_session_ids(
                BackendKind.X64DBG
            )
            stealth = (
                {}
                if already_open
                else self._prepare_launch_stealth(session_id, stealth_profile=None)
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        stealth.pop("implicit_open", None)
        opened = self.services.runtime.open_dynamic(session_id)
        if opened.ok and opened.data is not None and stealth:
            data = dict(opened.data)
            data.update(stealth)
            return _success(
                data, session_id=session_id, backend=BackendKind.X64DBG.value
            )
        return opened

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
                    str(session.locator or session.binary or ""),
                    requested,
                )

            entries: list[JsonObject] = []
            for kind in requested:
                backend = self._runtime_owner.get(session_id, kind)
                if backend is not None and self._worker_is_alive(backend):
                    entries.append(self._restore_backend_transport(kind, backend))
                    continue
                if backend is not None:
                    # A worker can die without anything having called into it, so
                    # the runtime is still registered and reconnecting would say
                    # "kept" about a process that no longer exists. IDA makes this
                    # unmissable: its transport is the worker's own pipes, so there
                    # is nothing to rebuild and the caller would be told the
                    # session recovered right before the next call fails.
                    self._discard_dead_runtime(session_id, kind)
                entries.append(self._reopen_backend(session_id, kind))
            return self._recover_outcome(
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
    def _recover_outcome(payload: JsonObject, *, session_id: str) -> Result[JsonObject]:
        """Fail the envelope when any requested backend did not come back.

        Callers that only read ``ok`` used to treat a replacement with
        ``failed > 0`` as recovered and keep issuing calls against a dead id.
        """
        try:
            failed = int(payload.get("failed") or 0)
        except (TypeError, ValueError):
            failed = 0
        if failed <= 0:
            return _success(payload, session_id=session_id)
        return Result[JsonObject](
            ok=False,
            data=payload,
            error=RpcError(
                code="recovery_failed",
                message=f"recovery finished with {failed} failed backend(s)",
                details={"session_id": session_id, "failed": failed},
                retryable=True,
            ),
            meta={"session_id": session_id},
        )

    @staticmethod
    def _worker_is_alive(runtime: _BackendRuntime) -> bool:
        """Treat a worker that reports no exit code as running.

        A backend that does not expose ``exit_code`` cannot be judged dead, and
        inventing a death would tear down a session that is working.
        """
        return getattr(runtime.worker, "exit_code", None) is None

    def _discard_dead_runtime(self, session_id: str, kind: BackendKind) -> None:
        """Drop the registration of a worker whose process is gone.

        Unlike ``_fail_runtime`` this leaves the session state alone: recovery is
        about to open a replacement, and moving the session to FAILED here would
        make the very next open refuse to run.
        """
        runtime = self._runtime_owner.pop(session_id, kind)
        if runtime is None:
            return
        if kind == BackendKind.X64DBG:
            self._stop_event_drain(runtime)
        with suppress(BaseException):
            runtime.worker.terminate()
        if kind == BackendKind.X64DBG:
            self._workflow_owner.clear(session_id)
            self._finalize_trace_after_worker_loss(session_id, reason="worker_died")
        self._health.forget(session_id)
        with suppress(KeyError, InvalidStateTransition):
            self.registry.detach_backend(session_id, kind)

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
        # Snapshot facts first: close_session may trim the old id, and a
        # surviving IDA worker still holds the database lock until that close.
        knowledge = self.services.artifacts.list_knowledge(session_id, limit=500)
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
        self._rebind_recovered_knowledge(knowledge, replacement_id)
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
        return self._recover_outcome(
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

    def _rebind_recovered_knowledge(
        self,
        snapshot: JsonObject,
        replacement_id: str,
    ) -> None:
        """Replay facts onto the replacement id after a FAILED session rebuild."""
        entries = snapshot.get("entries")
        if not isinstance(entries, list):
            return
        for item in entries:
            if not isinstance(item, dict):
                continue
            kind = item.get("kind")
            key = item.get("key")
            value = item.get("value")
            if not isinstance(kind, str) or not isinstance(key, str):
                continue
            payload = value if isinstance(value, dict) else {}
            with suppress(BaseException):
                self.services.artifacts.record_knowledge(
                    session_id=replacement_id,
                    kind=kind,
                    key=key,
                    value=payload,
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
        opening_session = False
        try:
            # Claim under the lock, then let go of it. begin_open is itself the
            # atomic claim, so holding the service-wide lock across the launch
            # bought nothing and cost everything else its turn: an IDA worker has
            # 300 seconds to start, and every other session's open and close
            # waited behind it.
            with self._lock:
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

            launched: BackendWorker | None = None
            event_log: PersistentDebugEventLog | None = None
            drain_cursor: DebugEventCursor | None = None
            event_cursor: DebugEventCursor | None = None
            try:
                launched = factory(session, self.settings)
                if launched is None:
                    raise RuntimeError("backend factory returned no worker")
                if kind == BackendKind.X64DBG:
                    event_cursor = DebugEventCursor()
                    drain_cursor = DebugEventCursor()
                    log_dir = self.settings.artifact_root / "debug-events" / session_id
                    event_log = PersistentDebugEventLog(log_dir / "events.sqlite3")
            except BaseException as exc:
                self._abandon_open(
                    session_id, kind, opening_session=opening_session, cause=exc
                )
                self._release_partial_backend_open(launched, event_log)
                raise
            worker = launched

            with self._lock:
                runtime: _BackendRuntime | None = None
                try:
                    # Re-checked because the lock was released: a session that was
                    # already READY can be closed while its second backend starts,
                    # and registering into it would leak this worker.
                    current = self.registry.get(session_id)
                    if current.state in {SessionState.CLOSING, SessionState.CLOSED}:
                        raise InvalidStateTransition(
                            f"session was closed while {kind.value} was opening"
                        )
                    workflow = (
                        create_workflow_runtime() if kind == BackendKind.X64DBG else None
                    )
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
                            lock=runtime.drain_lock,
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
                    self.registry.update_metadata(
                        session_id,
                        {metadata_key: worker.metadata, "restored": False},
                    )
                    if opening_session:
                        current = self.registry.transition(session_id, SessionState.READY)
                    else:
                        current = self.registry.get(session_id)
                except BaseException as exc:
                    self._abandon_open(
                        session_id, kind, opening_session=opening_session, cause=exc
                    )
                    if runtime is not None:
                        self._stop_event_drain(runtime)
                    self._release_partial_backend_open(worker, event_log)
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

    def _abandon_open(
        self,
        session_id: str,
        kind: BackendKind,
        *,
        opening_session: bool,
        cause: BaseException | None = None,
    ) -> None:
        """Release a claim that will not become a runtime."""
        with self._lock:
            self._runtime_owner.fail(session_id, kind)
            if opening_session:
                # A refused PE open on an APK/web session is not a crashed
                # worker. FAILED would brick later tools on that session.
                target = (
                    SessionState.CREATED
                    if isinstance(cause, TargetMismatch)
                    else SessionState.FAILED
                )
                with suppress(KeyError, InvalidStateTransition):
                    self.registry.transition(session_id, target)

    @staticmethod
    def _release_partial_backend_open(
        worker: BackendWorker | None,
        event_log: PersistentDebugEventLog | None,
    ) -> None:
        """Tear down a worker/log that never became a registered runtime."""
        if event_log is not None:
            with suppress(BaseException):
                event_log.close()
        if worker is not None:
            with suppress(BaseException):
                worker.terminate()

    def close_session(self, session_id: str) -> Result[JsonObject]:
        return self.services.runtime.close_session(session_id)

    def _session_work_dir(self, kind: str, session_id: str) -> Path | None:
        if not session_id or Path(session_id).name != session_id:
            return None
        root = self.settings.artifact_root.expanduser().resolve()
        path = (root / kind / session_id).resolve()
        try:
            path.relative_to(root / kind)
        except ValueError:
            return None
        return path

    def _forget_session_work_dirs(self, session_id: str) -> None:
        """Drop session-keyed work trees that are not registered artifacts.

        jadx / apktool write under ``<root>/<kind>/<session_id>``. Those dirs
        must not be evicted by pruning the shared parent -- that deletes a
        still-open sibling session's output. Close is the moment they become
        reclaimable. Ghidra export JSON *is* registered, so only the headless
        project remnants go away here.
        """
        for kind in ("jadx", "apktool"):
            path = self._session_work_dir(kind, session_id)
            if path is not None and path.is_dir():
                with suppress(OSError):
                    shutil.rmtree(path)
        ghidra = self._session_work_dir("ghidra", session_id)
        if ghidra is not None and ghidra.is_dir():
            for child in ghidra.iterdir():
                if child.name.startswith("export_") and child.suffix == ".json":
                    continue
                if child.is_dir():
                    with suppress(OSError):
                        shutil.rmtree(child)
                else:
                    with suppress(OSError):
                        child.unlink()

    def _forget_session_debug_events(self, session_id: str) -> None:
        """Remove the per-session debug-event sqlite after its connection is closed."""
        path = self._session_work_dir("debug-events", session_id)
        if path is not None and path.is_dir():
            with suppress(OSError):
                shutil.rmtree(path)

    def _unpack_cancel_event(self, session_id: str) -> Event:
        """Return the session's unpack-cancel latch, creating one only while live.

        Creation is serialized with close's CLOSING transition under the
        service lock: an unpack operation racing a close used to re-insert an
        Event after close had cleared it, retaining one latch per closed
        session forever. An existing latch is still returned in terminal
        states so unpack.cancel can stop an in-flight orchestration after a
        backend failure.
        """
        with self._lock:
            event = self._unpack_cancel_events.get(session_id)
            if event is not None:
                return event
            self._require_session_live_for_unpack(session_id)
            event = Event()
            self._unpack_cancel_events[session_id] = event
            return event

    def _reset_unpack_cancel(self, session_id: str) -> Event:
        with self._lock:
            self._require_session_live_for_unpack(session_id)
            event = Event()
            self._unpack_cancel_events[session_id] = event
            return event

    def _require_session_live_for_unpack(self, session_id: str) -> None:
        session = self.registry.get(session_id)
        if session.state in {
            SessionState.CLOSING,
            SessionState.CLOSED,
            SessionState.FAILED,
        }:
            raise InvalidStateTransition(
                f"unpack operation cannot run in {session.state.value} state"
            )

    def _signal_unpack_cancel(self, session_id: str) -> None:
        self._unpack_cancel_event(session_id).set()

    def _clear_unpack_cancel(self, session_id: str) -> None:
        event = self._unpack_cancel_events.pop(session_id, None)
        if event is not None:
            event.set()

    def _close_session(self, session_id: str) -> Result[JsonObject]:
        result: Result[JsonObject]
        runtimes: list[tuple[BackendKind, Any]] = []
        session: Session | None = None
        web_backend = None
        proxy_backend = None
        apk_binary = None
        with self._lock:
            try:
                session = self.registry.get(session_id)
                if session.state == SessionState.CLOSED:
                    result = _success({"session": _session_json(session), "already_closed": True})
                    note_session_closed(self, session_id, result)
                    return result
                if session.state is SessionState.OPENING:
                    # Opening no longer holds the service-wide lock, so a close
                    # can arrive mid-launch instead of queueing behind it. Say
                    # what to do about it rather than leaving the caller with the
                    # state machine's "opening -> closing is not allowed".
                    raise InvalidStateTransition(
                        "session is still opening its first backend; "
                        "close it once that open returns"
                    )
                self.registry.transition(session_id, SessionState.CLOSING)
                runtimes = self._runtime_owner.pop_session(session_id)
                self._health.forget(session_id)
                self._workflow_owner.clear(session_id)
                self._unpack_owner.clear(session_id)
                self._clear_unpack_cancel(session_id)
                self._debuggee_owner.clear(session_id)
                web_backend = getattr(self, "_web_backend", None)
                proxy_backend = getattr(self, "_proxy_backend", None)
                if session.target is TargetKind.APK and session.binary is not None:
                    apk_binary = session.binary
            except BaseException as exc:
                result = _failure(exc, session_id=session_id)
                note_session_closed(self, session_id, result)
                return result

        # Browser/proxy teardown can block for tens of seconds. Doing it under
        # the service lock froze every other session; a throw after pop_session
        # also leaked the debugger workers. Both stay outside the lock and
        # cannot skip the worker-close loop below.
        if web_backend is not None:
            with suppress(BaseException):
                web_backend.close(session_id)
        if proxy_backend is not None:
            with suppress(BaseException):
                proxy_backend.stop(session_id)
        if apk_binary is not None:
            with suppress(BaseException):
                ApkClient.release(apk_binary)
        self._forget_session_work_dirs(session_id)

        close_errors: list[tuple[BackendKind, BaseException]] = []
        for kind, runtime in runtimes:
            if kind == BackendKind.X64DBG:
                self._stop_event_drain(runtime)
            with runtime.lock:
                try:
                    runtime.worker.close()
                except BaseException as exc:
                    close_errors.append((kind, exc))
                    # Terminate is already the fallback for a failed close, and
                    # it can throw in its own right: on Windows the worker's
                    # temporary userdir is often still held when it runs. Letting
                    # that escape stranded the session in CLOSING, which accepts
                    # only CLOSED or FAILED, after the runtime had already been
                    # popped and nothing held the worker any more.
                    with suppress(BaseException):
                        runtime.worker.terminate()
            if kind == BackendKind.X64DBG:
                self._finalize_trace_after_worker_loss(
                    session_id,
                    reason="session_closed" if not close_errors else "worker_close_failed",
                )

        # Cleared only now: the loop above is what finalises and registers a
        # trace whose worker went away, and it needs the state to do it.
        self._trace_owner.clear(session_id)
        # Drain/log must be closed first -- Windows will not unlink an open
        # sqlite file. The file is not an artifact, so GC never sees it.
        self._forget_session_debug_events(session_id)

        # A caller that closes sessions one at a time never reaches close_all, so
        # without this the sweep thread outlives every backend it existed for.
        if not self._runtime_owner.snapshot():
            self._health.stop()
        self._release_adb_forwards_if_idle()

        assert session is not None
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
        # Closing a session is the natural retention checkpoint: it is the moment
        # an analysis stops producing artifacts, and it is infrequent enough that
        # a throttled collection never lands on a hot path.
        self._retention.maybe_collect(self.repository)
        self._release_adb_forwards_if_idle()
        return result

    def record_artifact(self, **fields: Any) -> JsonObject:
        """Register an artifact and take a retention checkpoint.

        Session close was the only checkpoint, so a session held open for days --
        the normal shape of an unattended run -- never enforced the byte budget
        while it was the very thing filling the disk. Registration is the other
        moment the tree grows; the collector's own throttle keeps a burst of
        dumps from walking the artifact table once per file.
        """
        artifact = self.repository.register_artifact(**fields)
        size = artifact.get("size")
        self._retention.maybe_collect(
            self.repository, added_bytes=int(size) if isinstance(size, int) else 0
        )
        return artifact

    def session_health(self, session_id: str | None = None) -> Result[JsonObject]:
        """Report backend liveness and any connections the monitor rebuilt.

        Checking synchronously means the answer reflects the moment it was asked
        rather than the last background sweep, which matters when a caller is
        deciding whether to recover.
        """
        try:
            if session_id is not None:
                self.registry.get(session_id)
            self._health.check_once(repair=False)
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

    def backend_health_snapshot(self) -> list[JsonObject]:
        """Return the last sweep's view without provoking a new one.

        Passive on purpose: a readiness probe runs on a short interval and must
        never trigger the monitor's reconnect path, which can block on a worker.
        """
        return self._health.report()

    def readiness(self) -> Result[JsonObject]:
        """Report whether this process can accept new work, and which build it is."""
        try:
            live = [
                session
                for session in self.registry.list()
                if session.state not in {SessionState.CLOSED, SessionState.FAILED}
            ]
            return _success(
                readiness_report(
                    repository=self.repository,
                    artifact_root=self.settings.artifact_root,
                    open_sessions=len(live),
                    backends=self.backend_health_snapshot(),
                    telemetry_log=telemetry_log_path(),
                    # Cached: a probe runs on a short interval and must not walk
                    # the whole artifact tree every time.
                    disk=self._artifact_usage.get(self.settings.artifact_root).as_json(),
                    disk_budget_bytes=self._retention.max_total_bytes,
                )
            )
        except BaseException as exc:
            return _failure(exc)

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
        web_backend = getattr(self, "_web_backend", None)
        if web_backend is not None:
            web_backend.close_all()
        proxy_backend = getattr(self, "_proxy_backend", None)
        if proxy_backend is not None:
            proxy_backend.close_all()
        adb_backend = getattr(self, "_adb_backend", None)
        if adb_backend is not None:
            with suppress(BaseException):
                adb_backend.release_forwards()
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

    def _release_adb_forwards_if_idle(self) -> None:
        """Drop process-owned adb forwards once no Android session remains."""
        live = [
            session
            for session in self.registry.list()
            if session.target is TargetKind.APK
            and session.state
            not in {SessionState.CLOSED, SessionState.FAILED, SessionState.CLOSING}
        ]
        if live:
            return
        adb_backend = getattr(self, "_adb_backend", None)
        if adb_backend is None:
            return
        with suppress(BaseException):
            adb_backend.release_forwards()

    def dynamic_state(self, session_id: str) -> Result[JsonObject]:
        return self.services.dynamic.state(session_id)

    def _dynamic_state(self, session_id: str) -> Result[JsonObject]:
        result = self._dynamic_request(session_id, "debug.state")
        if not result.ok or result.data is None:
            return result
        annotated = self._observe_debuggee_state(session_id, dict(result.data))
        return Result[JsonObject](ok=True, data=annotated, error=None, meta=dict(result.meta))

    def dynamic_events(
        self,
        session_id: str,
        *,
        limit: int = DEFAULT_DEBUG_EVENT_BATCH,
        timeout: float = 10.0,
        advance_consume_cursor: bool = False,
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
        # The poll budget starts before the lock, not after: a 100 ms peek used
        # to queue indefinitely behind a 30-second run-control call that owned
        # the runtime, blocked on a wait the caller never asked to share.
        deadline = monotonic() + float(timeout)
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            if not runtime.lock.acquire(timeout=max(0.0, deadline - monotonic())):
                raise XdbgRpcError(
                    "timeout",
                    "dynamic.events timed out acquiring the runtime lock",
                    details={"timeout_seconds": float(timeout)},
                    retryable=True,
                )
            try:
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
                waiting = self._workflow_navigation_is_waiting(session_id)
                if waiting:
                    # Navigate owns the native ring while WAITING. Serving the
                    # durable log only avoids a second events.read that desyncs
                    # the cursor and used to fail the runtime. Consume advances a
                    # private peek mark; dynamic.events keeps reading from the
                    # navigate-owned cursor so a peek still sees the same page.
                    if advance_consume_cursor:
                        peek_at = (
                            runtime.consume_peek_cursor
                            if runtime.consume_peek_cursor is not None
                            else cursor.value
                        )
                        served = event_log.read_after(peek_at, limit=limit)
                        runtime.consume_peek_cursor = served.batch.next_cursor
                    else:
                        served = event_log.read_after(cursor.value, limit=limit)
                else:
                    runtime.consume_peek_cursor = None
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
                        # Long-poll once for new native events, then serve from
                        # the log.  Only the wall-clock remainder is spent here;
                        # the lock wait above already consumed part of the budget.
                        poll_remaining = deadline - monotonic()
                        if poll_remaining > 0:
                            drain_native_into_log(
                                dynamic,
                                drain_cursor,
                                event_log,
                                timeout=poll_remaining,
                                max_rounds=1,
                            )
                            served = event_log.read_after(cursor.value, limit=limit)
                batch = served.batch
                if not waiting:
                    try:
                        cursor.advance(batch)
                    except DebugEventProtocolError as exc:
                        raise XdbgRpcError(
                            _CONSUMER_CURSOR_ERROR,
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
            finally:
                runtime.lock.release()
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

    def _stealth_layouts(self) -> dict[Architecture, Any]:
        return {
            Architecture.X86: layout_for_headless(
                self.settings.x64dbg_headless_x86, Architecture.X86
            ),
            Architecture.X64: layout_for_headless(
                self.settings.x64dbg_headless_x64, Architecture.X64
            ),
        }

    def _live_stealth_sessions(self, architecture: Architecture) -> tuple[str, ...]:
        live: list[str] = []
        for session_id in self._runtime_owner.active_session_ids(BackendKind.X64DBG):
            try:
                session = self.registry.get(session_id)
            except SessionNotFound:
                continue
            if session.architecture is architecture:
                live.append(session_id)
        return tuple(live)

    def _require_arch_idle_for_stealth(self, architecture: Architecture) -> None:
        live = self._live_stealth_sessions(architecture)
        if live:
            raise StealthError(
                "debugger_already_open",
                (
                    f"cannot change the {architecture.value} ScyllaHide profile "
                    "while a debugger for that architecture is open"
                ),
                details={
                    "architecture": architecture.value,
                    "live_sessions": list(live),
                },
            )

    def dynamic_stealth_status(self, session_id: str | None = None) -> Result[JsonObject]:
        try:
            layouts = self._stealth_layouts()
            payload = summarize_settings(
                enabled=bool(self.settings.x64dbg_stealth_enabled),
                default_profile=self.settings.x64dbg_stealth_profile,
                layouts=layouts,
            )
            payload["live_sessions"] = {
                Architecture.X86.value: list(self._live_stealth_sessions(Architecture.X86)),
                Architecture.X64.value: list(self._live_stealth_sessions(Architecture.X64)),
            }
            payload["ready"] = any(
                bool(item.get("plugin_present"))
                for item in payload["architectures"].values()
            )
            if session_id is not None:
                session = self.registry.get(session_id)
                payload["session_id"] = session_id
                payload["session_architecture"] = session.require_architecture().value
            return _success(payload, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def dynamic_stealth_set(
        self,
        profile: str,
        session_id: str | None = None,
    ) -> Result[JsonObject]:
        try:
            canonical = canonical_profile_id(profile)
            layouts = self._stealth_layouts()
            if session_id is not None:
                session = self.registry.get(session_id)
                targets: tuple[Architecture, ...] = (session.require_architecture(),)
            else:
                targets = tuple(
                    architecture
                    for architecture, layout in layouts.items()
                    if layout is not None
                )
            if not targets:
                raise StealthError(
                    "plugin_missing",
                    "no x64dbg headless executable is configured",
                )
            applied: list[JsonObject] = []
            for architecture in targets:
                if (
                    architecture is Architecture.X64
                    and canonical in X64_FORBIDDEN_PROFILES
                ):
                    if session_id is not None:
                        raise StealthError(
                            "invalid_params",
                            "armadillo is an x86-only ScyllaHide profile",
                            details={
                                "profile": canonical,
                                "architecture": architecture.value,
                            },
                        )
                    continue
                layout = layouts[architecture]
                if layout is None:
                    raise StealthError(
                        "plugin_missing",
                        f"x64dbg {architecture.value} headless executable is not configured",
                        details={"architecture": architecture.value},
                    )
                self._require_arch_idle_for_stealth(architecture)
                applied.append(
                    apply_profile(
                        layout,
                        canonical,
                        require_plugin=canonical != "off",
                    )
                )
            if not applied:
                raise StealthError(
                    "invalid_params",
                    "armadillo is an x86-only ScyllaHide profile",
                    details={"profile": canonical},
                )
            return _success(
                {
                    "profile": canonical,
                    "applied": applied,
                    "enabled": bool(self.settings.x64dbg_stealth_enabled),
                },
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def _cached_or_detected_stealth_profile(self, session_id: str) -> str | None:
        session = self.registry.get(session_id)
        cached = stealth_hint_profile(session.metadata)
        if cached is not None:
            return cached
        classified = self.packer_classify(
            session_id, use_die=True, use_exeinfope=False, timeout=30.0
        )
        if not classified.ok or classified.data is None:
            return None
        raw = classified.data.get("stealth_profile")
        if isinstance(raw, str) and raw.strip():
            try:
                return canonical_profile_id(raw)
            except StealthError:
                return None
        return None

    def _prepare_launch_stealth(
        self,
        session_id: str,
        *,
        stealth_profile: str | None,
    ) -> JsonObject:
        session = self.registry.get(session_id)
        architecture = session.require_architecture()
        layout = self._stealth_layouts()[architecture]
        enabled = bool(self.settings.x64dbg_stealth_enabled)
        explicit = stealth_profile is not None
        inspected = inspect_layout(layout)
        plugin_present = bool(inspected.get("plugin_present"))
        current = inspected.get("current_profile")
        if isinstance(current, str):
            current_id: str | None = current
        else:
            current_id = None
            section = inspected.get("current_section")
            if isinstance(section, str):
                current_id = profile_id_for_section(section)

        stealth_source = "default"
        if stealth_profile is not None:
            desired = canonical_profile_id(stealth_profile)
            stealth_source = "explicit"
        elif not enabled:
            desired = "off"
            stealth_source = "disabled"
        else:
            detected: str | None = None
            if plugin_present:
                detected = self._cached_or_detected_stealth_profile(session_id)
            if detected is not None:
                desired = detected
                stealth_source = "detection"
            elif current_id is not None:
                desired = current_id
                stealth_source = "current"
            else:
                try:
                    desired = canonical_profile_id(self.settings.x64dbg_stealth_profile)
                except StealthError:
                    desired = DEFAULT_PROFILE_ID

        session_open = session_id in self._runtime_owner.active_session_ids(
            BackendKind.X64DBG
        )
        payload: JsonObject = {
            "stealth_profile": desired,
            "stealth_applied": False,
            "stealth_ready": plugin_present,
            "stealth_enabled": enabled,
            "stealth_source": stealth_source,
            "implicit_open": not session_open,
        }

        if layout is None:
            if explicit:
                raise StealthError(
                    "plugin_missing",
                    f"x64dbg {architecture.value} headless executable is not configured",
                    details={"architecture": architecture.value},
                )
            return payload

        live = self._live_stealth_sessions(architecture)

        need_write = current_id != desired
        if explicit and desired != "off" and not plugin_present:
            raise StealthError(
                "plugin_missing",
                f"ScyllaHide plugin files are missing for {architecture.value}",
                details={
                    "architecture": architecture.value,
                    "plugins_dir": inspected.get("plugins_dir"),
                    "plugin": inspected.get("plugin"),
                    "hook_library": inspected.get("hook_library"),
                },
            )
        if not explicit and not plugin_present and enabled:
            return payload
        if need_write:
            if live:
                raise StealthError(
                    "debugger_already_open",
                    (
                        f"cannot change the {architecture.value} ScyllaHide profile "
                        "while a debugger for that architecture is open"
                    ),
                    details={
                        "architecture": architecture.value,
                        "live_sessions": list(live),
                        "requested_profile": desired,
                        "current_profile": current_id,
                    },
                )
            apply_profile(
                layout,
                desired,
                require_plugin=desired != "off" and (enabled or explicit),
            )
        payload["stealth_applied"] = bool(enabled and desired != "off" and plugin_present)
        payload["stealth_profile"] = desired
        return payload

    def dynamic_launch(
        self,
        session_id: str,
        *,
        arguments: str = "",
        working_directory: str | None = None,
        timeout: float = 30.0,
        pass_system_breakpoint: bool = False,
        stealth_profile: str | None = None,
    ) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            params: JsonObject = {"path": str(session.require_pe())}
            stealth = self._prepare_launch_stealth(
                session_id, stealth_profile=stealth_profile
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)
        if arguments:
            params["arguments"] = arguments
        if working_directory is not None:
            params["working_directory"] = working_directory
        if stealth.pop("implicit_open", False):
            opened = self.services.runtime.open_dynamic(session_id)
            if not opened.ok:
                return opened
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
                data.update(stealth)
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
        data.update(stealth)
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

    def dynamic_modules(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 256,
    ) -> Result[JsonObject]:
        if type(offset) is not int or offset < 0:
            return _failure(
                ValueError("offset must be a non-negative integer"),
                session_id=session_id,
            )
        if type(limit) is not int or not 1 <= limit <= 1024:
            return _failure(
                ValueError("limit must be between 1 and 1024"),
                session_id=session_id,
            )
        result = self._dynamic_request(
            session_id,
            "modules.list",
            {"offset": offset, "limit": limit},
        )
        if result.ok:
            try:
                runtime = self._runtime(session_id, BackendKind.X64DBG)
                with runtime.lock:
                    runtime.snapshot_resync_required = False
            except Exception:  # noqa: BLE001 - clearing the flag is best-effort
                pass
        return result

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
            if not 0 < float(timeout) <= MAX_WORKFLOW_TIMEOUT:
                raise ValueError(f"timeout must be > 0 and <= {MAX_WORKFLOW_TIMEOUT}")

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

            payload = {
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
            }
            if not resumed.ok:
                error = resumed.error or RpcError(
                    code="debugger_command_failed",
                    message="dynamic resume failed",
                    details={"session_id": session_id},
                )
                return Result[JsonObject](
                    ok=False,
                    data=payload,
                    error=error,
                    meta={
                        "session_id": session_id,
                        "backend": BackendKind.X64DBG.value,
                    },
                )
            return _success(
                payload,
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

    def _workflow_navigation_is_waiting(self, session_id: str) -> bool:
        workflow = self._workflow_owner.get(session_id)
        if workflow is None:
            return False
        navigation = workflow.state.navigation
        return navigation is not None and navigation.status == NavigationStatus.WAITING

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
                _CONSUMER_CURSOR_ERROR,
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
        runtime.navigation_cancel.clear()
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
            if runtime.navigation_cancel.is_set():
                cancelled = cancel_workflow_navigation(workflow.state)
                workflow = self._execute_workflow_transition_locked(
                    session_id,
                    runtime,
                    workflow,
                    cancelled,
                    timeout=min(5.0, max(0.1, timeout)),
                    status=WorkflowRunStatus.CANCELLED,
                )
                with suppress(Exception):
                    self._workflow_ensure_paused_locked(
                        session_id, runtime, timeout=min(5.0, max(0.1, timeout))
                    )
                return {"workflow": workflow.to_dict()}
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
            # Drop the session lock while waiting so workflow.cancel can run.
            runtime.lock.release()
            try:
                batch = dynamic.read_events(
                    cursor.value,
                    limit=limit,
                    timeout=min(5.0, max(0.1, remaining)),
                )
                if not batch.events and not batch.has_more:
                    sleep(min(0.05, max(0.0, deadline - monotonic())))
            finally:
                runtime.lock.acquire()
            workflow = self._require_workflow(session_id)
            # Cancel (or a terminal status) may have landed while the lock
            # was down. Consuming into a finished navigation raises.
            if runtime.navigation_cancel.is_set() or (
                workflow.state.navigation is None
                or workflow.state.navigation.status != NavigationStatus.WAITING
            ):
                continue
            try:
                cursor.advance(batch)
            except DebugEventProtocolError as exc:
                raise XdbgRpcError(
                    _CONSUMER_CURSOR_ERROR,
                    f"x64dbg event cursor is inconsistent: {exc}",
                ) from exc
            self._consume_workflow_batch_locked(
                session_id,
                runtime,
                batch,
                timeout=min(remaining, 30.0),
            )
            workflow = self._require_workflow(session_id)

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
        if session.target is not TargetKind.PE:
            session.require_pe()
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
    return IdaWorkerClient(session.require_pe(), settings)


def _create_xdbg_worker(session: Session, settings: Settings) -> DynamicWorker:
    session.require_pe()
    if os.name != "nt":
        raise XdbgRpcError(
            "unsupported_on_platform",
            "x64dbg headless RPC is available only on Windows",
            details=unsupported_on_platform_details("x64dbg"),
        )
    architecture = session.require_architecture()
    executable = {
        Architecture.X86: settings.x64dbg_headless_x86,
        Architecture.X64: settings.x64dbg_headless_x64,
    }[architecture]
    if executable is None:
        variable = (
            "HEADLESS_RE_X64DBG_HEADLESS_X86"
            if architecture == Architecture.X86
            else "HEADLESS_RE_X64DBG_HEADLESS_X64"
        )
        raise XdbgRpcError(
            "backend_unavailable",
            f"x64dbg {architecture.value} headless executable is not configured",
            details={"environment_variable": variable},
        )
    return XdbgClient(
        executable,
        architecture,
        hidden_desktop=settings.hidden_desktop,
    )


_X64_ARGUMENT_REGISTERS = ("rcx", "rdx", "r8", "r9")


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


def _workflow_timeout(value: float) -> float | ValueError:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not isfinite(value)
        or not 0 < value <= MAX_WORKFLOW_TIMEOUT
    ):
        return ValueError(
            f"timeout must be greater than 0 and at most {MAX_WORKFLOW_TIMEOUT:g} seconds"
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


def _session_json(session: Session) -> JsonObject:
    value = session.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("session model did not serialize to an object")
    return value


def _is_safe_session_segment(session_id: str) -> bool:
    """True only when ``session_id`` is one ordinary path component.

    ``Path(session_id).name != session_id`` alone is not enough: ``..`` passes
    it because ``Path("..").name == ".."``. Left unchecked in
    ``_session_artifact_roots`` that turned every owned root ``<cat>/<id>`` into
    ``<cat>/..`` -- i.e. the artifact root itself -- so a caller passing
    ``session_id=".."`` was judged to own every other session's artifacts.
    Reject the dot segments (and empties/separators) explicitly.
    """
    if not session_id or session_id in {".", ".."}:
        return False
    return Path(session_id).name == session_id


def _safe_expanduser(path: Path) -> Path:
    """``path.expanduser()`` that does not raise on an unresolvable ``~``.

    ``expanduser`` raises RuntimeError -- not OSError -- when the user in
    ``~someone/...`` cannot be resolved (a service account with no home, or a
    typo). Callers feed this caller-supplied paths and then ``.resolve()``; the
    raw path is returned so that resolve makes the decision: ``resolve(strict=
    True)`` answers ``file_not_found`` for the literal ``~someone`` directory,
    and a containment check answers ``invalid_params``. Either is a clean client
    error instead of the internal_error incident the bare RuntimeError became.
    """
    try:
        return path.expanduser()
    except RuntimeError:
        return path


def _session_artifact_roots(artifact_root: Path, session_id: str) -> tuple[Path, ...]:
    """Return owned artifact subtrees for one session (fail-closed ownership)."""
    if not _is_safe_session_segment(session_id):
        return ()
    root = artifact_root.expanduser().resolve()
    return (
        root / "dotnet" / session_id,
        root / "unpack" / session_id,
        root / "dump" / session_id,
        root / "detection" / session_id,
        root / "web" / session_id,
        root / "proxy" / session_id,
        root / "apktool" / session_id,
        root / "jadx" / session_id,
        root / "ghidra" / session_id,
        root / "trace" / session_id,
        root / "ui" / session_id,
        root / "reports" / session_id,
        root / "static" / session_id,
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


def _write_die_artifact(
    artifact_root: Path,
    session_id: str,
    result: DieScanResult,
) -> str:
    """Persist bounded raw DIE JSON with an atomic rename under the artifact root."""
    if not _is_safe_session_segment(session_id):
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
    if not _is_safe_session_segment(session_id):
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
    if not _is_safe_session_segment(session_id):
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


