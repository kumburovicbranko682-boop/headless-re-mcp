from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import UTC, datetime
from math import isfinite
from pathlib import Path
from time import monotonic
from typing import Any, cast
from uuid import uuid4

from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.backends.ghidra.client import GhidraClient, GhidraError
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.application_services import ApplicationServices
from headless_re_mcp.core.capabilities_catalog import describe_capability, list_capabilities
from headless_re_mcp.core.models import Result, RpcError, SessionState
from headless_re_mcp.core.repository import AnalysisRepository, SqliteAnalysisRepository
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.session import (
    InvalidStateTransition,
    SessionNotFound,
    SessionRegistry,
    file_sha256,
)
from headless_re_mcp.core.store.sqlite_store import KNOWLEDGE_VALUE_MAX_CHARS
from headless_re_mcp.core.ui_drive import drive_deadline, normalize_drive_steps, run_drive_step
from headless_re_mcp.core.windows import (
    UiPidBoundaryError,
    is_pid_alive,
    list_windows_for_pids,
    resolve_allowed_ui_pids,
)
from headless_re_mcp.platform_support import (
    is_windows_host,
    unsupported_on_platform_details,
)
from headless_re_mcp.reporting import render_markdown_report
from headless_re_mcp.workflows.navigation import EventPattern

JsonObject = dict[str, Any]
_TERMINAL_EVENT_KINDS = frozenset({"process.exited", "debug.stopped"})
_DEBUG_EVENT_BUDGET_PER_BATCH = 64
_REPORT_INLINE_MAX_BYTES = 64 * 1024


def _rpc_error(
    exc: R2Error | GhidraError | FridaError | WindbgError | UiPidBoundaryError,
) -> XdbgRpcError:
    """Translate a backend error to an RPC error, keeping the timeout signal.

    r2, ghidra, frida and windbg all raise a ``"timeout"`` code when a tool
    outruns its deadline (run_bounded, the cdb launcher, a frida call), and
    that is transient -- a second run usually clears it. None of those error
    classes carries a retryable flag and XdbgRpcError defaults it to False, so
    building the error inline dropped the signal and an unattended agent that
    retries on it treated every stall as permanent. Derive it from the code,
    exactly as the jsre/web/frida/de4dot/upx siblings already do. Every other
    code -- and every UiPidBoundaryError, a boundary/validation error that
    never times out -- stays non-retryable.
    """
    return XdbgRpcError(
        exc.code,
        exc.message,
        details=dict(exc.details),
        retryable=exc.code == "timeout",
    )


def _breakpoint_binding_address(workflow_data: Mapping[str, Any], intent_id: str) -> int:
    if not isinstance(intent_id, str) or not intent_id.strip():
        raise ValueError("breakpoint intent_id must not be blank")
    workflow = workflow_data.get("workflow")
    if not isinstance(workflow, Mapping):
        raise XdbgRpcError("invalid_state", "workflow status is missing workflow data")
    state = workflow.get("state")
    if not isinstance(state, Mapping):
        raise XdbgRpcError("invalid_state", "workflow status is missing workflow state")
    breakpoints = state.get("breakpoints")
    if not isinstance(breakpoints, Mapping):
        raise XdbgRpcError("invalid_state", "workflow status is missing breakpoint state")
    bindings = breakpoints.get("bindings")
    if not isinstance(bindings, list):
        raise XdbgRpcError("invalid_state", "workflow status has invalid breakpoint bindings")

    matching = [
        binding
        for binding in bindings
        if isinstance(binding, Mapping) and binding.get("intent_id") == intent_id
    ]
    if len(matching) != 1:
        raise XdbgRpcError(
            "invalid_state",
            "breakpoint intent does not have exactly one active binding",
            details={"intent_id": intent_id, "binding_count": len(matching)},
        )
    address = matching[0].get("address")
    if type(address) is not int or address <= 0:
        raise XdbgRpcError(
            "invalid_state",
            "breakpoint intent binding has an invalid address",
            details={"intent_id": intent_id, "address": address},
        )
    return address


def _ensure_repository(service: Any) -> AnalysisRepository:
    repository = getattr(service, "repository", None)
    if repository is None:
        repository = SqliteAnalysisRepository(service.settings.artifact_root)
        service.repository = repository
    return repository


def _record_artifact(service: Any, **fields: Any) -> JsonObject:
    """Register through the service so the retention checkpoint runs too."""
    recorder = getattr(service, "record_artifact", None)
    if callable(recorder):
        return cast(JsonObject, recorder(**fields))
    return _ensure_repository(service).register_artifact(**fields)


def _register_capture(
    service: Any,
    session_id: str,
    path: Path,
    *,
    kind: str,
    source: str,
    payload: JsonObject,
) -> JsonObject:
    """Register a file a capture wrote, and return its id alongside the payload.

    A bare path is a dead end in both directions: nothing on the tool surface
    opens one, so an agent cannot read back the screenshot or HAR it just asked
    for, and retention only collects what the repository knows about, so an
    unattended capture grows the artifact root with files nothing can reclaim.

    Registering must not fail the capture -- the file exists either way -- so a
    failure travels in the payload rather than as an exception.
    """
    if not path.is_file():
        return payload
    try:
        artifact = _record_artifact(
            service,
            session_id=session_id,
            kind=kind,
            path=path,
            sha256=file_sha256(path),
            source=source,
            size=path.stat().st_size,
        )
    except BaseException as exc:  # noqa: BLE001 - reported, never raised
        return {**payload, "artifact_error": str(exc)}
    return {**payload, "artifact_id": artifact["id"]}


def _timeline_append(
    service: Any,
    session_id: str,
    event: str,
    message: str,
    **details: object,
) -> None:
    _ensure_repository(service).append_timeline(
        session_id,
        event,
        message,
        **details,
    )


def _record_backend(service: Any, session_id: str, kind: str, **fields: object) -> None:
    _ensure_repository(service).record_backend(session_id, kind, **fields)


def _note_failed(action: str, exc: BaseException, result: Result[JsonObject]) -> None:
    """Say the bookkeeping failed, without making that the outcome.

    These run after the work they describe. An artifact root that disappeared
    under the service -- a disk cleanup, a scanner quarantine, a volume that
    came back unmounted -- makes the store unopenable, and the exception used to
    leave close_session, so a session that really had closed answered with a
    traceback instead of an envelope and stayed CLOSING for good.

    Swallowing it outright would be the opposite mistake: the session really did
    open or close, but nothing recorded it, and an unattended caller would keep
    working against an audit trail that quietly stopped. So it lands in ``meta``,
    where it neither changes the result nor goes unseen.
    """
    from headless_re_mcp.error_boundary import record_exception

    with suppress(BaseException):
        record_exception(exc, context=f"bookkeeping:{action}")
    with suppress(BaseException):
        result.meta["persisted"] = False
        result.meta["persist_error"] = f"{type(exc).__name__}: {exc}"[:200]


def note_session_created(service: Any, binary: str, result: Result[JsonObject]) -> None:
    try:
        _ensure_repository(service).note_session_created(binary, result)
    except BaseException as exc:  # noqa: BLE001 - reported in meta, never raised
        _note_failed("session.created", exc, result)


def note_session_closed(service: Any, session_id: str, result: Result[JsonObject]) -> None:
    try:
        session = service.registry.get(session_id)
    except (KeyError, RuntimeError):
        session = None
    try:
        _ensure_repository(service).note_session_closed(session_id, session, result)
    except BaseException as exc:  # noqa: BLE001 - reported in meta, never raised
        _note_failed("session.closed", exc, result)


class UiDriveMixin:
    """PID-bounded UI drive operations shared by the compatibility façade."""

    settings: Settings
    registry: SessionRegistry
    workflow_status: Callable[[str], Result[JsonObject]]
    create_session: Callable[[str], Result[JsonObject]]
    open_static: Callable[[str], Result[JsonObject]]

    def ui_drive_to_event(
        self,
        session_id: str,
        kind: str,
        *,
        fields: Mapping[str, Any] | None = None,
        steps: Sequence[Mapping[str, Any]] | None = None,
        timeout: float = 30.0,
        event_budget: int = 1024,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        accept_ui_goal: bool = True,
    ) -> Result[JsonObject]:
        return _ui_drive(
            self,
            session_id,
            kind=kind,
            fields=fields,
            steps=steps,
            timeout=timeout,
            event_budget=event_budget,
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            accept_ui_goal=accept_ui_goal,
            breakpoint_intent_id=None,
        )

    def ui_drive_to_breakpoint(
        self,
        session_id: str,
        intent_id: str,
        *,
        steps: Sequence[Mapping[str, Any]] | None = None,
        timeout: float = 30.0,
        event_budget: int = 1024,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        accept_ui_goal: bool = True,
    ) -> Result[JsonObject]:
        workflow = self.workflow_status(session_id)
        if not workflow.ok:
            return workflow
        try:
            binding_address = _breakpoint_binding_address(
                workflow.data or {},
                intent_id,
            )
        except BaseException as exc:
            return _failure(
                exc,
                session_id=session_id,
                capability="ui.drive_to_breakpoint",
            )
        return _ui_drive(
            self,
            session_id,
            kind="breakpoint.hit",
            fields={"intent_id": intent_id, "address": binding_address},
            steps=steps,
            timeout=timeout,
            event_budget=event_budget,
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            accept_ui_goal=accept_ui_goal,
            breakpoint_intent_id=intent_id,
            breakpoint_address=binding_address,
        )


class ExtAnalysisMixin(UiDriveMixin):
    """Optional backend and artifact operations with statically declared methods."""

    # Supplied by AnalysisService, which this mixes into.
    services: ApplicationServices

    def capabilities_search(
        self, backend: str | None = None, status: str | None = None
    ) -> Result[JsonObject]:
        items = list_capabilities(self.settings, backend=backend, status=status)
        return _success({"capabilities": items, "count": len(items)})

    def capabilities_describe(self, capability_id: str) -> Result[JsonObject]:
        item = describe_capability(capability_id, self.settings)
        if item is None:
            return Result(
                ok=False,
                error=RpcError(code="not_found", message="capability not found", details={"id": capability_id}),
            )
        return _success({"capability": item})

    def r2_open(self, session_id: str, timeout: float = 30.0) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"r2.open cannot run in {session.state.value} state"
                )
            exe = getattr(self.settings, "r2", None)
            client = R2Client(Path(exe) if exe else None)
            data = client.open(session.require_binary(), timeout=timeout)
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"r2.open cannot run in {session.state.value} state"
                )
            _record_backend(self, session_id, "radare2", endpoint="pipe")
            _timeline_append(self, session_id, "r2.open", "r2 binary open validated")
            return _success(data, session_id=session_id, backend="radare2")
        except R2Error as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def r2_info(self, session_id: str, timeout: float = 30.0) -> Result[JsonObject]:
        return _r2_request(self, session_id, ["i"], timeout=timeout)

    def r2_functions(self, session_id: str, timeout: float = 30.0) -> Result[JsonObject]:
        return _r2_request(self, session_id, ["aa", "aflj"], timeout=timeout)

    def r2_strings(self, session_id: str, timeout: float = 30.0) -> Result[JsonObject]:
        return _r2_request(self, session_id, ["izj"], timeout=timeout)

    def r2_imports(self, session_id: str, timeout: float = 30.0) -> Result[JsonObject]:
        return _r2_request(self, session_id, ["iij"], timeout=timeout)

    def r2_exports(self, session_id: str, timeout: float = 30.0) -> Result[JsonObject]:
        return _r2_request(self, session_id, ["iEj"], timeout=timeout)

    def r2_disasm(
        self, session_id: str, address: int, count: int = 32, timeout: float = 30.0
    ) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"r2.disasm cannot run in {session.state.value} state"
                )
            exe = getattr(self.settings, "r2", None)
            client = R2Client(Path(exe) if exe else None)
            data = client.disasm(session.require_binary(), address, count=count, timeout=timeout)
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"r2.disasm cannot run in {session.state.value} state"
                )
            _timeline_append(self, session_id, "r2.disasm", "r2 disasm", address=address, count=count)
            return _success(data, session_id=session_id, backend="radare2")
        except R2Error as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def r2_xrefs(self, session_id: str, address: int, timeout: float = 30.0) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"r2.xrefs cannot run in {session.state.value} state"
                )
            exe = getattr(self.settings, "r2", None)
            client = R2Client(Path(exe) if exe else None)
            data = client.xrefs(session.require_binary(), address, timeout=timeout)
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"r2.xrefs cannot run in {session.state.value} state"
                )
            _timeline_append(self, session_id, "r2.xrefs", "r2 xrefs", address=address)
            return _success(data, session_id=session_id, backend="radare2")
        except R2Error as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def ghidra_analyze(self, session_id: str, timeout: float = 120.0) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"ghidra.analyze cannot run in {session.state.value} state"
                )
            client = GhidraClient(home=getattr(self.settings, "ghidra_home", None))
            project = self.settings.artifact_root.expanduser().resolve() / "ghidra" / session_id
            data = client.analyze_binary(session.require_binary(), project, timeout=timeout)
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"ghidra.analyze cannot run in {session.state.value} state"
                )
            _record_backend(self, session_id, "ghidra", endpoint=str(project))
            _timeline_append(self, session_id, "ghidra.analyze", "ghidra analyze finished")
            return _success(data, session_id=session_id, backend="ghidra")
        except GhidraError as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def ghidra_functions(
        self, session_id: str, limit: int = 256, timeout: float = 180.0
    ) -> Result[JsonObject]:
        return _ghidra_export(self, session_id, "functions", limit=limit, timeout=timeout)

    def ghidra_symbols(
        self, session_id: str, limit: int = 256, timeout: float = 180.0
    ) -> Result[JsonObject]:
        return _ghidra_export(self, session_id, "symbols", limit=limit, timeout=timeout)

    def ghidra_xrefs(
        self, session_id: str, address: str | int, limit: int = 256, timeout: float = 180.0
    ) -> Result[JsonObject]:
        return _ghidra_export(
            self, session_id, "xrefs", limit=limit, address=address, timeout=timeout
        )

    def ghidra_decompile(
        self, session_id: str, address: str | int, timeout: float = 180.0
    ) -> Result[JsonObject]:
        return _ghidra_export(self, session_id, "decompile", address=address, timeout=timeout)

    def frida_attach(self, session_id: str) -> Result[JsonObject]:
        try:
            pid = _require_debuggee_pid(self, session_id)
            client = FridaClient()
            data = client.attach(pid, allowed_pid=pid)
            _record_backend(self, session_id, "frida", pid=pid)
            _timeline_append(self, session_id, "frida.attach", "frida probe attach", pid=pid)
            return _success(data, session_id=session_id, backend="frida")
        except FridaError as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def frida_modules(self, session_id: str, limit: int = 64) -> Result[JsonObject]:
        try:
            pid = _require_debuggee_pid(self, session_id)
            client = FridaClient()
            data = client.modules(pid, allowed_pid=pid, limit=limit)
            _timeline_append(self, session_id, "frida.modules", "frida modules listed", count=data.get("count"))
            return _success(data, session_id=session_id, backend="frida")
        except FridaError as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def frida_exports(
        self, session_id: str, module_name: str, limit: int = 64
    ) -> Result[JsonObject]:
        try:
            pid = _require_debuggee_pid(self, session_id)
            client = FridaClient()
            data = client.exports(pid, module_name, allowed_pid=pid, limit=limit)
            _timeline_append(
                self,
                session_id,
                "frida.exports",
                "frida exports listed",
                module=module_name,
                count=data.get("count"),
            )
            return _success(data, session_id=session_id, backend="frida")
        except FridaError as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def frida_memory_read(
        self, session_id: str, address: int, size: int
    ) -> Result[JsonObject]:
        try:
            pid = _require_debuggee_pid(self, session_id)
            client = FridaClient()
            data = client.memory_read(pid, address, size, allowed_pid=pid)
            return _success(data, session_id=session_id, backend="frida")
        except FridaError as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def frida_hook_template(self, session_id: str, template: str = "noop") -> Result[JsonObject]:
        try:
            client = FridaClient()
            # A device-connected session (APK/web) hooks its authorised device
            # pid; a PE session keeps the local single-pid behaviour unchanged.
            session = self.registry.get(session_id)
            auth = session.metadata.get("frida_authorized")
            if isinstance(auth, dict) and auth.get("pids"):
                # Enforce the same open-session invariant the other device frida
                # ops get from _frida_auth: a retained CLOSING/CLOSED/FAILED
                # session still resolves and still carries frida_authorized
                # (close transitions state but never clears metadata), so without
                # this a late hook.template would inject a script into a device
                # process for a session that is already gone. The PE branch below
                # is already guarded -- _require_debuggee_pid fails once the
                # debuggee is cleared on close.
                if session.state in {
                    SessionState.CLOSING,
                    SessionState.CLOSED,
                    SessionState.FAILED,
                }:
                    raise InvalidStateTransition(
                        f"frida.hook.template cannot run in {session.state.value} state"
                    )
                pid = int(auth["pids"][-1])
                data = client.hook_template_device(
                    auth.get("device_id"), pid, template, allowed_pids=auth.get("pids", [])
                )
            else:
                pid = _require_debuggee_pid(self, session_id)
                data = client.hook_template(pid, template, allowed_pid=pid)
            _timeline_append(
                self,
                session_id,
                "frida.hook",
                "frida hook template injected as a probe (not resident)",
                template=template,
            )
            return _success(data, session_id=session_id, backend="frida")
        except FridaError as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def windbg_open_dump(
        self,
        dump_path: str,
        commands: list[str] | None = None,
        timeout: float = 60.0,
        kernel: bool = False,
    ) -> Result[JsonObject]:
        try:
            client = _windbg_client(self)
            data = client.open_dump(
                Path(dump_path),
                commands or ["lm"],
                timeout=timeout,
                kernel=kernel,
            )
            return _success(data, backend="windbg")
        except WindbgError as exc:
            return _failure(_rpc_error(exc))
        except BaseException as exc:
            return _failure(exc)

    def windbg_threads(self, dump_path: str, timeout: float = 60.0) -> Result[JsonObject]:
        try:
            client = _windbg_client(self)
            return _success(client.threads(Path(dump_path), timeout=timeout), backend="windbg")
        except WindbgError as exc:
            return _failure(_rpc_error(exc))
        except BaseException as exc:
            return _failure(exc)

    def windbg_modules(self, dump_path: str, timeout: float = 60.0) -> Result[JsonObject]:
        try:
            client = _windbg_client(self)
            return _success(client.modules(Path(dump_path), timeout=timeout), backend="windbg")
        except WindbgError as exc:
            return _failure(_rpc_error(exc))
        except BaseException as exc:
            return _failure(exc)

    def windbg_disasm(
        self,
        dump_path: str,
        address: str | int,
        length: int = 16,
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        try:
            client = _windbg_client(self)
            return _success(
                client.disasm(Path(dump_path), address, length=length, timeout=timeout),
                backend="windbg",
            )
        except WindbgError as exc:
            return _failure(_rpc_error(exc))
        except BaseException as exc:
            return _failure(exc)

    def windbg_attach(self, session_id: str, timeout: float = 30.0) -> Result[JsonObject]:
        try:
            pid = _require_debuggee_pid(self, session_id)
            client = _windbg_client(self)
            data = client.attach(pid, allowed_pid=pid, timeout=timeout)
            _record_backend(self, session_id, "windbg", pid=pid)
            _timeline_append(self, session_id, "windbg.attach", "windbg noninvasive attach probe", pid=pid)
            return _success(data, session_id=session_id, backend="windbg")
        except WindbgError as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def windbg_live_threads(self, session_id: str, timeout: float = 30.0) -> Result[JsonObject]:
        try:
            pid = _require_debuggee_pid(self, session_id)
            client = _windbg_client(self)
            data = client.live_threads(pid, allowed_pid=pid, timeout=timeout)
            _timeline_append(self, session_id, "windbg.live_threads", "windbg live threads", pid=pid)
            return _success(data, session_id=session_id, backend="windbg")
        except WindbgError as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def windbg_live_modules(self, session_id: str, timeout: float = 30.0) -> Result[JsonObject]:
        try:
            pid = _require_debuggee_pid(self, session_id)
            client = _windbg_client(self)
            data = client.live_modules(pid, allowed_pid=pid, timeout=timeout)
            _timeline_append(self, session_id, "windbg.live_modules", "windbg live modules", pid=pid)
            return _success(data, session_id=session_id, backend="windbg")
        except WindbgError as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def windbg_live_disasm(
        self,
        session_id: str,
        address: str | int,
        length: int = 16,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        try:
            pid = _require_debuggee_pid(self, session_id)
            client = _windbg_client(self)
            data = client.live_disasm(
                pid, address, allowed_pid=pid, length=length, timeout=timeout
            )
            _timeline_append(
                self, session_id, "windbg.live_disasm", "windbg live disasm", pid=pid, address=str(address)
            )
            return _success(data, session_id=session_id, backend="windbg")
        except WindbgError as exc:
            return _failure(_rpc_error(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    # The store is not infallible, and these read paths used to assume it was.
    # A metadata database that has been corrupted, quarantined or unmounted made
    # them raise straight through the tool boundary, which is the one thing every
    # tool is supposed never to do -- and it happens exactly when a caller is
    # trying to find out what went wrong.

    def artifacts_list(
        self, session_id: str | None = None, offset: int = 0, limit: int = 50
    ) -> Result[JsonObject]:
        try:
            return _success(
                self.services.artifacts.list_artifacts(
                    session_id,
                    offset=offset,
                    limit=limit,
                )
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def artifacts_describe(self, artifact_id: str) -> Result[JsonObject]:
        try:
            item = self.services.artifacts.describe_artifact(artifact_id)
        except BaseException as exc:
            return _failure(exc)
        if item is None:
            return Result(ok=False, error=RpcError(code="not_found", message="artifact not found"))
        return _success({"artifact": item})

    def artifacts_read(
        self, artifact_id: str, offset: int = 0, limit: int = 4096
    ) -> Result[JsonObject]:
        try:
            return self._artifacts_read(artifact_id, offset=offset, limit=limit)
        except BaseException as exc:
            return _failure(exc)

    def _artifacts_read(
        self, artifact_id: str, *, offset: int, limit: int
    ) -> Result[JsonObject]:
        item = _ensure_repository(self).describe_artifact(artifact_id)
        if item is None:
            return Result(ok=False, error=RpcError(code="not_found", message="artifact not found"))
        path = Path(str(item["path"])).resolve()
        root = self.settings.artifact_root.expanduser().resolve()
        if root not in path.parents and path.parent != root:
            return Result(
                ok=False,
                error=RpcError(code="permission_denied", message="artifact path escapes artifact_root"),
            )
        if not path.is_file():
            return Result(ok=False, error=RpcError(code="not_found", message="artifact file missing"))
        limit = max(1, min(int(limit), 256 * 1024))
        offset = max(0, int(offset))
        # Seek rather than read-then-slice. Artifacts here are process dumps and
        # traces: measured on a 200 MB one, twenty paginated 256 KiB reads spiked
        # to 243 MB of RSS against a 42 MB baseline and touched 4 GB to serve
        # 5 MB, because every page re-read the whole file. A 2 GB dump would
        # simply not fit.
        with path.open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            stream.seek(offset)
            data = stream.read(limit)
        return _success(
            {
                "artifact_id": artifact_id,
                "offset": offset,
                "limit": limit,
                "size": size,
                "encoding": "hex",
                "data": data.hex(),
            }
        )

    def artifacts_gc(self, max_total_bytes: int = 512 * 1024 * 1024) -> Result[JsonObject]:
        try:
            return _success(
                self.services.artifacts.gc_artifacts(max_total_bytes=max_total_bytes)
            )
        except BaseException as exc:
            return _failure(exc)

    def timeline_list(
        self, session_id: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            return _success(
                self.services.artifacts.list_timeline(
                    session_id,
                    offset=offset,
                    limit=limit,
                )
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def sessions_unclean(self, offset: int = 0, limit: int = 100) -> Result[JsonObject]:
        try:
            items, total = _ensure_repository(self).list_unclean_sessions(
                offset=offset, limit=limit
            )
        except BaseException as exc:
            return _failure(exc)
        start = max(0, int(offset))
        return _success(
            {
                "sessions": items,
                "count": len(items),
                "total": total,
                "offset": start,
                "has_more": start + len(items) < total,
            }
        )

    def peek_session_record(self, session_id: str) -> Result[JsonObject]:
        """Live session if this process still has it, otherwise the stored row.

        After a console restart unclean rows are hydrated back into the
        registry (same id, dormant). last-known still answers for ids that
        were closed or never restored.
        """
        try:
            try:
                session = self.registry.get(session_id)
            except SessionNotFound:
                session = None
            if session is not None:
                binary = str(session.locator or session.binary or "")
                state = session.state.value if hasattr(session.state, "value") else str(session.state)
                return _success(
                    {
                        "live": True,
                        "id": session.id,
                        "binary": binary,
                        "state": state,
                    }
                )
            row = _ensure_repository(self).peek_session(session_id)
            if not row:
                raise SessionNotFound.for_id(session_id)
            return _success(
                {
                    "live": False,
                    "id": str(row.get("id") or session_id),
                    "binary": str(row.get("binary") or ""),
                    "state": row.get("state"),
                    "updated_at": row.get("updated_at"),
                }
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def audit_list(
        self, session_id: str | None = None, offset: int = 0, limit: int = 50
    ) -> Result[JsonObject]:
        try:
            return _success(
                self.services.artifacts.list_audit(
                    session_id,
                    offset=offset,
                    limit=limit,
                )
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def batch_analyze(
        self,
        binaries: Sequence[str],
        *,
        max_workers: int = 2,
        open_static: bool = True,
    ) -> Result[JsonObject]:
        """Create one session per binary with bounded parallelism.

        Each entry succeeds or fails on its own so a single bad sample cannot
        abort the batch. Parallelism is capped because every static backend is a
        real analyser process, not a coroutine.
        """
        try:
            paths = [str(item).strip() for item in binaries if str(item).strip()]
            if not paths:
                raise ValueError("binaries must contain at least one path")
            if len(paths) > 32:
                raise ValueError("binaries must contain at most 32 paths")
            if (
                isinstance(max_workers, bool)
                or type(max_workers) is not int
                or not 1 <= max_workers <= 8
            ):
                raise ValueError("max_workers must be 1..8")

            def analyse(path: str) -> JsonObject:
                entry: JsonObject = {"binary": path, "ok": False, "session_id": None}
                created = self.create_session(path)
                if not created.ok or created.data is None:
                    if created.error is not None:
                        entry["error"] = created.error.model_dump(mode="json")
                    return entry
                session = created.data.get("session")
                if not isinstance(session, dict):
                    entry["error"] = {"code": "rpc_protocol_error", "message": "no session"}
                    return entry
                session_id = str(session["id"])
                entry["session_id"] = session_id
                entry["ok"] = True
                if open_static:
                    opened = self.open_static(session_id)
                    entry["static_open"] = bool(opened.ok)
                    if not opened.ok:
                        entry["ok"] = False
                        if opened.error is not None:
                            entry["error"] = opened.error.model_dump(mode="json")
                return entry

            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                entries = list(pool.map(analyse, paths))

            succeeded = sum(1 for entry in entries if entry["ok"])
            return _success(
                {
                    "entries": entries,
                    "count": len(entries),
                    "succeeded": succeeded,
                    "failed": len(entries) - succeeded,
                    "max_workers": max_workers,
                }
            )
        except BaseException as exc:
            return _failure(exc)

    def knowledge_record(
        self,
        session_id: str,
        kind: str,
        key: str,
        value: Mapping[str, Any] | None = None,
    ) -> Result[JsonObject]:
        """Record one durable analysis fact, replacing the same (kind, key) pair.

        Keeping findings keyed makes repeated analysis idempotent instead of
        appending duplicates every time an agent revisits a function.
        """
        try:
            normalized_kind = (kind or "").strip()
            normalized_key = (key or "").strip()
            if not normalized_kind or len(normalized_kind) > 64:
                raise ValueError("kind must be a non-empty string of at most 64 chars")
            if not normalized_key or len(normalized_key) > 256:
                raise ValueError("key must be a non-empty string of at most 256 chars")
            # Checked here rather than left to the store's cut. The value is
            # kept as JSON text, so a cut one stops being JSON and reads back as
            # a string fragment: the call answered ok, and the finding an agent
            # relies on for its next decision quietly became something else.
            encoded = len(json.dumps(dict(value or {}), ensure_ascii=False))
            if encoded > KNOWLEDGE_VALUE_MAX_CHARS:
                raise ValueError(
                    f"value serialises to {encoded} chars, over the "
                    f"{KNOWLEDGE_VALUE_MAX_CHARS} a finding may hold; record the bulk as an "
                    "artifact and keep the reference here"
                )
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"knowledge.record cannot run in {session.state.value} state"
                )
            entry = self.services.artifacts.record_knowledge(
                session_id=session_id,
                kind=normalized_kind,
                key=normalized_key,
                value=dict(value) if value else {},
            )
            return _success(entry, session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def knowledge_query(
        self,
        session_id: str,
        *,
        kind: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        """Read accumulated analysis facts for a session, optionally by kind."""
        try:
            self.registry.get(session_id)
            return _success(
                self.services.artifacts.list_knowledge(
                    session_id,
                    kind=(kind or None),
                    offset=offset,
                    limit=limit,
                ),
                session_id=session_id,
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def report_generate(
        self,
        session_id: str,
        *,
        title: str | None = None,
        include_audit: bool = True,
        audit_limit: int = 30,
    ) -> Result[JsonObject]:
        """Render a Markdown analysis report and save it under the artifact root."""
        try:
            if (
                isinstance(audit_limit, bool)
                or type(audit_limit) is not int
                or not 1 <= audit_limit <= 200
            ):
                raise ValueError("audit_limit must be 1..200")
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"report.generate cannot run in {session.state.value} state"
                )
            knowledge = self.services.artifacts.list_knowledge(session_id, limit=500)
            artifacts = self.services.artifacts.list_artifacts(session_id, limit=100)
            audit = (
                self.services.artifacts.list_audit(session_id, limit=audit_limit)
                if include_audit
                else None
            )
            markdown = render_markdown_report(
                session={
                    "id": session_id,
                    "binary": str(session.require_binary()),
                    "sha256": session.sha256 or "",
                    "target": session.target.value,
                    "architecture": (
                        session.architecture.value if session.architecture else ""
                    ),
                    "state": session.state.value,
                    "backends": sorted(backend.value for backend in session.backends),
                },
                knowledge=knowledge,
                artifacts=artifacts,
                audit=audit,
                title=title,
            )
            markdown_bytes = markdown.encode("utf-8", errors="replace")
            response_markdown = markdown
            response_truncated = len(markdown_bytes) > _REPORT_INLINE_MAX_BYTES
            if response_truncated:
                response_markdown = markdown_bytes[:_REPORT_INLINE_MAX_BYTES].decode(
                    "utf-8", errors="ignore"
                )
            directory = (
                self.settings.artifact_root.expanduser().resolve() / "reports" / session_id
            )
            directory.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
            path = directory / f"report-{stamp}-{uuid4().hex}.md"
            path.write_bytes(markdown_bytes)
            payload = _register_capture(
                self,
                session_id,
                path,
                kind="report_markdown",
                source="report.generate",
                payload={
                    "path": str(path),
                    "bytes": len(markdown_bytes),
                    "findings": int(knowledge.get("total") or 0),
                    "markdown": response_markdown,
                    "truncated": response_truncated,
                },
            )
            if response_truncated:
                payload["hint"] = "full_markdown_in_artifact"
            return _success(payload, session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def tool_metrics(self, *, limit: int = 20) -> Result[JsonObject]:
        """Return per-tool call counts, failure counts and latency percentiles.

        Sampled from a bounded in-memory ring, so it reflects the current process
        rather than all history; the same records are emitted as JSON log lines.
        """
        from headless_re_mcp.telemetry import TELEMETRY

        if isinstance(limit, bool) or type(limit) is not int or not 0 <= limit <= 200:
            return _failure(ValueError("limit must be 0..200"))
        payload = TELEMETRY.metrics()
        payload["recent"] = TELEMETRY.recent(limit)
        return _success(payload)


def _require_debuggee_pid(service: Any, session_id: str) -> int:
    state = service.dynamic_state(session_id)
    if not state.ok or state.data is None:
        raise XdbgRpcError("invalid_state", "cannot read dynamic state for optional backend")
    pid = state.data.get("debuggee_pid")
    if not isinstance(pid, int) or pid <= 0:
        raise XdbgRpcError("invalid_state", "no active debuggee for optional backend")
    return pid


def _windbg_client(service: Any) -> WindbgClient:
    if not is_windows_host():
        raise WindbgError(
            "unsupported_on_platform",
            "WinDbg/cdb is available only on Windows",
            **unsupported_on_platform_details("windbg"),
        )
    cdb = getattr(service.settings, "cdb", None)
    allow_kernel = bool(getattr(service.settings, "windbg_allow_kernel", False))
    return WindbgClient(Path(cdb) if cdb else None, allow_kernel=allow_kernel)


def _r2_request(service: Any, session_id: str, commands: list[str], *, timeout: float) -> Result[JsonObject]:
    try:
        session = service.registry.get(session_id)
        if session.state in {
            SessionState.CLOSING,
            SessionState.CLOSED,
            SessionState.FAILED,
        }:
            raise InvalidStateTransition(
                f"r2 request cannot run in {session.state.value} state"
            )
        exe = getattr(service.settings, "r2", None)
        client = R2Client(Path(exe) if exe else None)
        data = client.run(session.require_binary(), commands, timeout=timeout)
        session = service.registry.get(session_id)
        if session.state in {
            SessionState.CLOSING,
            SessionState.CLOSED,
            SessionState.FAILED,
        }:
            raise InvalidStateTransition(
                f"r2 request cannot run in {session.state.value} state"
            )
        _record_backend(service, session_id, "radare2", endpoint="pipe")
        _timeline_append(service, session_id, "r2.request", "r2 whitelist command", commands=commands)
        return _success(data, session_id=session_id, backend="radare2")
    except R2Error as exc:
        return _failure(_rpc_error(exc), session_id=session_id)
    except BaseException as exc:
        return _failure(exc, session_id=session_id)


def _ghidra_export(
    service: Any,
    session_id: str,
    mode: str,
    *,
    limit: int = 256,
    address: str | int | None = None,
    timeout: float = 180.0,
) -> Result[JsonObject]:
    try:
        session = service.registry.get(session_id)
        if session.state in {
            SessionState.CLOSING,
            SessionState.CLOSED,
            SessionState.FAILED,
        }:
            raise InvalidStateTransition(
                f"ghidra.{mode} cannot run in {session.state.value} state"
            )
        client = GhidraClient(home=getattr(service.settings, "ghidra_home", None))
        project = service.settings.artifact_root.expanduser().resolve() / "ghidra" / session_id
        if mode == "functions":
            data = client.functions(session.require_binary(), project, limit=limit, timeout=timeout)
        elif mode == "symbols":
            data = client.symbols(session.require_binary(), project, limit=limit, timeout=timeout)
        elif mode == "xrefs":
            if address is None:
                raise GhidraError("invalid_params", "address required for ghidra.xrefs")
            data = client.xrefs(session.require_binary(), project, address, limit=limit, timeout=timeout)
        elif mode == "decompile":
            if address is None:
                raise GhidraError("invalid_params", "address required for ghidra.decompile")
            data = client.decompile(session.require_binary(), project, address, timeout=timeout)
        else:
            raise GhidraError("invalid_params", "unknown ghidra export mode", mode=mode)
        session = service.registry.get(session_id)
        if session.state in {
            SessionState.CLOSING,
            SessionState.CLOSED,
            SessionState.FAILED,
        }:
            raise InvalidStateTransition(
                f"ghidra.{mode} cannot run in {session.state.value} state"
            )
        _record_backend(service, session_id, "ghidra", endpoint=str(project))
        _timeline_append(service, session_id, f"ghidra.{mode}", f"ghidra {mode} export")
        export_path = data.get("export_path")
        if isinstance(export_path, str) and Path(export_path).is_file():
            exported = Path(export_path)
            # Hashed in chunks like every other artifact here: a full-program
            # decompilation is the one export big enough to matter.
            art = _record_artifact(
                service,
                session_id=session_id,
                kind=f"ghidra_{mode}",
                path=export_path,
                sha256=file_sha256(exported),
                source=f"ghidra.{mode}",
                size=exported.stat().st_size,
            )
            data["artifact_id"] = art["id"]
        return _success(data, session_id=session_id, backend="ghidra")
    except GhidraError as exc:
        return _failure(_rpc_error(exc), session_id=session_id)
    except BaseException as exc:
        return _failure(exc, session_id=session_id)


def _ui_drive(
    service: Any,
    session_id: str,
    *,
    kind: str,
    fields: Mapping[str, Any] | None,
    steps: Sequence[Mapping[str, Any]] | None,
    timeout: float,
    event_budget: int,
    allow_child_pids: list[int] | None,
    include_same_image_children: bool = False,
    accept_ui_goal: bool = True,
    breakpoint_intent_id: str | None = None,
    breakpoint_address: int | None = None,
) -> Result[JsonObject]:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not isfinite(timeout)
        or not 0 < float(timeout) <= 300.0
    ):
        return _failure(ValueError("timeout must be >0 and <=300"), session_id=session_id)
    if type(event_budget) is not int or not 1 <= event_budget <= 100_000:
        return _failure(ValueError("event_budget out of range"), session_id=session_id)
    try:
        pattern = EventPattern.create(kind, fields)
    except BaseException as exc:
        return _failure(exc, session_id=session_id)
    try:
        normalized = normalize_drive_steps(steps)
    except UiPidBoundaryError as exc:
        return _failure(_rpc_error(exc), session_id=session_id)

    deadline = drive_deadline(float(timeout))
    step_results: list[JsonObject] = []
    handles: dict[str, int] = {}
    events_seen = 0
    matched_event: JsonObject | None = None
    ui_goal = False
    saw_windows = False
    stop_reason: str | None = None
    # Burst architecture: resolve PID allow-list once; throttle window enum;
    # short event peeks between steps; long-poll only when waiting for debug events.
    cached_allowed: frozenset[int] | None = None
    cached_for_pid: int | None = None
    last_window_check = 0.0
    _STEP_EVENT_PEEK = 0.05
    _WINDOW_CHECK_INTERVAL = 0.5
    _EVENT_LONG_POLL = 2.0

    def _pause_best_effort() -> None:
        with_suppress = True
        try:
            service.dynamic_pause(session_id, timeout=10.0)
        except BaseException:
            if with_suppress:
                return

    def _match_events(events: list[object]) -> JsonObject | None:
        for event in events:
            if not isinstance(event, dict):
                continue
            event_kind = str(event.get("kind") or "")
            if breakpoint_intent_id and event_kind == "breakpoint.hit":
                data = event.get("data")
                if not isinstance(data, Mapping):
                    continue
                address = data.get("address")
                intent = data.get("intent_id")
                if (
                    type(breakpoint_address) is not int
                    or breakpoint_address <= 0
                    or type(address) is not int
                    or address != breakpoint_address
                    or (intent is not None and intent != breakpoint_intent_id)
                ):
                    continue
                annotated_data = dict(data)
                annotated_data["intent_id"] = breakpoint_intent_id
                annotated_data["binding_address"] = breakpoint_address
                return {**event, "data": annotated_data}
            if event_kind == pattern.kind:
                data = event.get("data") or {}
                ok = True
                for key, expected in pattern.fields:
                    if data.get(key) != expected:
                        ok = False
                        break
                if ok:
                    return event
        return None

    def _drain_events(*, wait_s: float) -> list[object]:
        nonlocal events_seen, stop_reason, matched_event
        remaining = max(0.0, deadline - monotonic())
        timeout_s = max(0.0, min(wait_s, remaining))
        batch = service.dynamic_events(session_id, limit=16, timeout=timeout_s)
        if not batch.ok:
            stop_reason = "event_loss"
            code = batch.error.code if batch.error else "backend_error"
            message = batch.error.message if batch.error else "dynamic.events failed"
            raise XdbgRpcError(
                "event_loss" if code in {"invalid_state", "backend_error"} else code,
                f"event stream failed during ui drive: {message}",
                details={"code": code},
            )
        events: list[object] = []
        if batch.data:
            raw = batch.data.get("events") or []
            if isinstance(raw, list):
                events = raw
            events_seen += len(events)
            for event in events:
                if not isinstance(event, dict):
                    continue
                event_kind = str(event.get("kind") or "")
                if event_kind in _TERMINAL_EVENT_KINDS:
                    stop_reason = "target_exited"
                    raise XdbgRpcError(
                        "target_exited",
                        "terminal debug event during ui drive",
                        details={"kind": event_kind, "event": event},
                    )
            hit = _match_events(events)
            if hit is not None:
                matched_event = hit
        return events

    try:
        while monotonic() < deadline and events_seen < event_budget:
            state = service.dynamic_state(session_id)
            if not state.ok or state.data is None:
                stop_reason = "lost_debuggee"
                raise XdbgRpcError("invalid_state", "lost debuggee during ui drive")
            debuggee_pid = state.data.get("debuggee_pid")
            debugger_pid = state.data.get("debugger_pid")
            if not isinstance(debuggee_pid, int) or debuggee_pid <= 0:
                stop_reason = "no_debuggee"
                raise XdbgRpcError("invalid_state", "no debuggee during ui drive")
            if not is_pid_alive(debuggee_pid):
                stop_reason = "target_exited"
                raise XdbgRpcError(
                    "target_exited",
                    "debuggee process exited during ui drive",
                    details={"debuggee_pid": debuggee_pid},
                )

            if state.data.get("state") == "paused":
                # Short resume barrier; tolerate immediate rebreak (PostMessage still ok).
                resume_timeout = min(2.0, max(0.2, deadline - monotonic()))
                resumed = service.dynamic_resume(session_id, timeout=resume_timeout)
                if not resumed.ok:
                    stop_reason = "resume_failed"
                    code = resumed.error.code if resumed.error else "backend_error"
                    message = resumed.error.message if resumed.error else "dynamic.resume failed"
                    raise XdbgRpcError(code, f"failed to resume before ui drive step: {message}")
                running = service.dynamic_wait(session_id, "running", timeout=resume_timeout)
                if not running.ok:
                    st = service.dynamic_state(session_id)
                    if not (st.ok and st.data and st.data.get("state") in {"paused", "running"}):
                        stop_reason = "resume_failed"
                        code = running.error.code if running.error else "backend_error"
                        message = (
                            running.error.message if running.error else "wait running failed"
                        )
                        raise XdbgRpcError(
                            code, f"debuggee not runnable before ui drive step: {message}"
                        )

            if cached_allowed is None or cached_for_pid != debuggee_pid:
                cached_allowed, _blocked = resolve_allowed_ui_pids(
                    debuggee_pid=debuggee_pid,
                    debugger_pid=debugger_pid if isinstance(debugger_pid, int) else None,
                    allow_child_pids=allow_child_pids or (),
                    include_same_image_children=include_same_image_children,
                )
                cached_for_pid = debuggee_pid
            allowed = cached_allowed

            if normalized:
                now = monotonic()
                need_window_check = (
                    now - last_window_check >= _WINDOW_CHECK_INTERVAL
                    or str(normalized[0].get("action")) in {"wait", "resolve"}
                    or not saw_windows
                )
                if need_window_check:
                    windows = list_windows_for_pids(sorted(allowed))
                    last_window_check = now
                    if windows:
                        saw_windows = True
                    elif saw_windows:
                        stop_reason = "window_gone"
                        raise XdbgRpcError(
                            "window_gone",
                            "debuggee top-level window disappeared during ui drive",
                            details={"debuggee_pid": debuggee_pid},
                        )
                step = normalized.pop(0)
                try:
                    step_result = run_drive_step(step, allowed_pids=allowed, handles=handles)
                except UiPidBoundaryError as exc:
                    raise _rpc_error(exc) from exc
                step_results.append(step_result)
                if step_result.get("action") == "wait" and step_result.get("matched"):
                    ui_goal = True
                    if accept_ui_goal:
                        break
                # Peek events only; do not burn 2s between UI steps.
                _drain_events(wait_s=_STEP_EVENT_PEEK)
                if matched_event is not None:
                    # A queued/stale ``debug.paused`` is common after launch and
                    # must not make a UI-goal drive succeed before its remaining
                    # steps have run.  Other event goals (notably a breakpoint)
                    # still stop immediately; callers that require an event-only
                    # drive use ``accept_ui_goal=False``.
                    incidental_pause = (
                        pattern.kind == "debug.paused"
                        and accept_ui_goal
                        and bool(normalized)
                    )
                    if not incidental_pause:
                        break
                if not normalized and accept_ui_goal and ui_goal:
                    break
                continue

            if accept_ui_goal and ui_goal:
                break

            # No pending UI steps: long-poll for the debug event goal.
            _drain_events(wait_s=_EVENT_LONG_POLL)
            if matched_event is not None:
                break

        _pause_best_effort()
        if matched_event is None and not (accept_ui_goal and ui_goal):
            raise XdbgRpcError(
                "timeout",
                "ui drive did not reach event or UI goal before timeout/budget",
                details={
                    "kind": kind,
                    "events_seen": events_seen,
                    "steps_executed": len(step_results),
                    "stop_reason": stop_reason or "timeout",
                },
            )
        payload = {
            "matched_event": matched_event,
            "ui_goal": ui_goal,
            "steps": step_results,
            "events_seen": events_seen,
            "stopped": "paused",
            "stop_reason": stop_reason or ("ui_goal" if ui_goal else "event"),
            "architecture": "ui_burst",
            "note": "UI drive stopped; debuggee pause attempted",
        }
        _timeline_append(
            service,
            session_id,
            "ui.drive",
            "ui drive finished",
            matched=bool(matched_event),
            ui_goal=ui_goal,
            steps=len(step_results),
        )
        _ensure_repository(service).append_audit(
            session_id=session_id,
            action="ui.drive",
            params_summary={"kind": kind, "steps": len(step_results)},
            ok=True,
            result_summary={"ui_goal": ui_goal, "matched": matched_event is not None},
        )
        return _success(payload, session_id=session_id, capability="ui.drive_to_event")
    except XdbgRpcError as exc:
        _pause_best_effort()
        _ensure_repository(service).append_audit(
            session_id=session_id,
            action="ui.drive",
            params_summary={"kind": kind, "steps": len(step_results), "stop_reason": stop_reason},
            ok=False,
            result_summary={"code": exc.code, "message": str(exc)},
        )
        return _failure(exc, session_id=session_id)
    except BaseException as exc:
        _pause_best_effort()
        return _failure(exc, session_id=session_id)
