"""Workflow orchestration ops extracted from AnalysisService."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.events import DEFAULT_DEBUG_EVENT_BATCH
from headless_re_mcp.core.models import BackendKind, ModuleSelector, Result
from headless_re_mcp.workflows.breakpoints import BreakpointIntent
from headless_re_mcp.workflows.engine import (
    cancel_workflow_navigation,
    disable_workflow_breakpoint_intent,
    prepare_workflow_reset,
    put_workflow_breakpoint_intent,
    remove_workflow_breakpoint_intent,
    request_workflow_module_refresh,
    track_workflow_module,
    untrack_workflow_module,
)
from headless_re_mcp.workflows.executor import (
    WorkflowExecutionError,
    WorkflowExecutionPort,
    execute_workflow_transition,
)
from headless_re_mcp.workflows.navigation import EventPattern, EventScalar
from headless_re_mcp.workflows.runtime import WorkflowRunStatus, create_workflow_runtime

if TYPE_CHECKING:
    from collections.abc import Callable

    from headless_re_mcp.core.addressing import RebasedModuleMapping
    from headless_re_mcp.core.events import DebugEventCursor
    from headless_re_mcp.core.runtime_state import BackendRuntimeOwner, WorkflowStateOwner
    from headless_re_mcp.core.service import _BackendRuntime
    from headless_re_mcp.core.session import SessionRegistry
    from headless_re_mcp.workflows.engine import WorkflowTransition
    from headless_re_mcp.workflows.runtime import WorkflowRuntime

from headless_re_mcp.core.results import _failure, _success

JsonObject = dict[str, Any]


def _ServiceWorkflowPort(
    service: WorkflowAnalysisMixin,
    session_id: str,
    runtime: _BackendRuntime,
) -> WorkflowExecutionPort:
    """Build the real port, imported late to keep the service import acyclic.

    The cast is the honest part of the mixin arrangement: the port needs the
    assembled ``AnalysisService``, and this only ever runs on ``self``.
    """
    from headless_re_mcp.core.service import AnalysisService
    from headless_re_mcp.core.service import _ServiceWorkflowPort as real

    return real(cast(AnalysisService, service), session_id, runtime)


def _workflow_timeout(value: float) -> float | ValueError:
    from headless_re_mcp.core.service import _workflow_timeout as real

    return real(value)


def _max_workflow_event_budget() -> int:
    from headless_re_mcp.core.service import _MAX_WORKFLOW_EVENT_BUDGET as value

    return value


class WorkflowAnalysisMixin:
    """Workflow status / breakpoint / navigation MCP surface.

    The members below are supplied by ``AnalysisService``, which this mixes
    into. Declaring them is what lets the module be type checked at all, and
    mypy verifies the declarations against the real definitions: a signature
    that drifts shows up as an incompatible override on the service.
    """

    registry: SessionRegistry
    _runtime_owner: BackendRuntimeOwner[_BackendRuntime]
    _workflow_owner: WorkflowStateOwner[WorkflowRuntime]

    if TYPE_CHECKING:

        def _workflow_request(
            self,
            session_id: str,
            action: Callable[[_BackendRuntime], JsonObject],
        ) -> Result[JsonObject]: ...

        def _execute_workflow_transition_locked(
            self,
            session_id: str,
            runtime: _BackendRuntime,
            workflow: WorkflowRuntime,
            transition: WorkflowTransition,
            *,
            timeout: float,
            status: WorkflowRunStatus | None = None,
        ) -> WorkflowRuntime: ...

        def _require_mutable_workflow(self, session_id: str) -> WorkflowRuntime: ...

        def _require_workflow(self, session_id: str) -> WorkflowRuntime: ...

        def _workflow_resolve_module_locked(
            self,
            session_id: str,
            runtime: _BackendRuntime,
            selector: ModuleSelector,
            *,
            timeout: float,
        ) -> RebasedModuleMapping: ...

        def _workflow_navigate(
            self,
            session_id: str,
            pattern: EventPattern,
            *,
            timeout: float,
            event_budget: int,
        ) -> Result[JsonObject]: ...

        def _navigate_locked(
            self,
            session_id: str,
            runtime: _BackendRuntime,
            workflow: WorkflowRuntime,
            pattern: EventPattern,
            *,
            timeout: float,
            event_budget: int,
        ) -> JsonObject: ...

        def _require_current_runtime(
            self,
            session_id: str,
            kind: BackendKind,
            runtime: _BackendRuntime,
        ) -> None: ...

        def _record_workflow_failure_locked(
            self,
            session_id: str,
            workflow: WorkflowRuntime,
            error: WorkflowExecutionError,
        ) -> WorkflowRuntime: ...

        def dynamic_events(
            self,
            session_id: str,
            *,
            limit: int = 100,
            timeout: float = 10.0,
        ) -> Result[JsonObject]: ...

        def _workflow_ensure_paused_locked(
            self,
            session_id: str,
            runtime: _BackendRuntime,
            *,
            timeout: float,
        ) -> None: ...

        def _require_event_cursor(self, runtime: _BackendRuntime) -> DebugEventCursor: ...

    def workflow_status(self, session_id: str) -> Result[JsonObject]:
        try:
            self.registry.get(session_id)
            runtime = self._runtime_owner.get(session_id, BackendKind.X64DBG)
            terminal = self._workflow_owner.get_terminal(session_id)
            if runtime is None:
                if terminal is not None:
                    return _success(
                        {"workflow": terminal.to_dict()},
                        session_id=session_id,
                        backend=BackendKind.X64DBG.value,
                        terminal=True,
                    )
                raise XdbgRpcError("backend_unavailable", "x64dbg worker is not open")
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                workflow = self._require_workflow(session_id)
                return _success(
                    {"workflow": workflow.to_dict()},
                    session_id=session_id,
                    backend=BackendKind.X64DBG.value,
                    terminal=False,
                )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)

    def workflow_reset(
        self,
        session_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        validated = _workflow_timeout(timeout)
        if isinstance(validated, ValueError):
            return _failure(validated, session_id=session_id)

        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_workflow(session_id)
            transition = prepare_workflow_reset(workflow.state)
            try:
                execute_workflow_transition(
                    transition,
                    _ServiceWorkflowPort(self, session_id, runtime),
                    timeout=validated,
                )
            except WorkflowExecutionError as exc:
                self._record_workflow_failure_locked(session_id, workflow, exc)
                raise exc.cause from exc
            cursor = self._require_event_cursor(runtime).value
            reset = create_workflow_runtime(cursor=cursor)
            self._workflow_owner.put(session_id, reset)
            return {"workflow": reset.to_dict()}

        return self._workflow_request(session_id, action)

    def workflow_cancel(
        self,
        session_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        validated = _workflow_timeout(timeout)
        if isinstance(validated, ValueError):
            return _failure(validated, session_id=session_id)

        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_mutable_workflow(session_id)
            transition = cancel_workflow_navigation(workflow.state)
            updated = self._execute_workflow_transition_locked(
                session_id,
                runtime,
                workflow,
                transition,
                timeout=validated,
                status=WorkflowRunStatus.CANCELLED,
            )
            return {"workflow": updated.to_dict()}

        return self._workflow_request(session_id, action)

    def workflow_events_consume(
        self,
        session_id: str,
        *,
        limit: int = DEFAULT_DEBUG_EVENT_BATCH,
        timeout: float = 10.0,
    ) -> Result[JsonObject]:
        return self.dynamic_events(session_id, limit=limit, timeout=timeout)

    def workflow_module_track(
        self,
        session_id: str,
        key: str,
        selector: ModuleSelector,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        validated = _workflow_timeout(timeout)
        if isinstance(validated, ValueError):
            return _failure(validated, session_id=session_id)

        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_mutable_workflow(session_id)
            self._workflow_ensure_paused_locked(
                session_id,
                runtime,
                timeout=validated,
            )
            mapping = self._workflow_resolve_module_locked(
                session_id,
                runtime,
                selector,
                timeout=validated,
            )
            transition = track_workflow_module(workflow.state, key, selector, mapping)
            updated = self._execute_workflow_transition_locked(
                session_id,
                runtime,
                workflow,
                transition,
                timeout=validated,
            )
            return {"workflow": updated.to_dict(), "module_key": key.strip()}

        return self._workflow_request(session_id, action)

    def workflow_module_untrack(
        self,
        session_id: str,
        key: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        validated = _workflow_timeout(timeout)
        if isinstance(validated, ValueError):
            return _failure(validated, session_id=session_id)

        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_mutable_workflow(session_id)
            transition = untrack_workflow_module(workflow.state, key)
            updated = self._execute_workflow_transition_locked(
                session_id,
                runtime,
                workflow,
                transition,
                timeout=validated,
            )
            return {"workflow": updated.to_dict(), "module_key": key.strip()}

        return self._workflow_request(session_id, action)

    def workflow_module_refresh(
        self,
        session_id: str,
        *,
        keys: list[str] | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        validated = _workflow_timeout(timeout)
        if isinstance(validated, ValueError):
            return _failure(validated, session_id=session_id)
        normalized_keys = None if keys is None else [key.strip() for key in keys]
        if normalized_keys is not None and (
            not normalized_keys
            or any(not key for key in normalized_keys)
            or len(normalized_keys) != len(set(normalized_keys))
        ):
            return _failure(
                ValueError("module refresh keys must contain non-blank unique values"),
                session_id=session_id,
            )
        selected = None if normalized_keys is None else frozenset(normalized_keys)

        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_mutable_workflow(session_id)
            transition = request_workflow_module_refresh(workflow.state, selected)
            updated = self._execute_workflow_transition_locked(
                session_id,
                runtime,
                workflow,
                transition,
                timeout=validated,
            )
            return {"workflow": updated.to_dict()}

        return self._workflow_request(session_id, action)

    def workflow_breakpoint_put(
        self,
        session_id: str,
        intent_id: str,
        module_key: str,
        rva: int,
        *,
        enabled: bool = True,
        one_shot: bool = False,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        validated = _workflow_timeout(timeout)
        if isinstance(validated, ValueError):
            return _failure(validated, session_id=session_id)
        try:
            intent = BreakpointIntent(
                id=intent_id,
                module_key=module_key,
                rva=rva,
                enabled=enabled,
                one_shot=one_shot,
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_mutable_workflow(session_id)
            transition = put_workflow_breakpoint_intent(workflow.state, intent)
            updated = self._execute_workflow_transition_locked(
                session_id,
                runtime,
                workflow,
                transition,
                timeout=validated,
            )
            return {"workflow": updated.to_dict(), "intent_id": intent.id}

        return self._workflow_request(session_id, action)

    def workflow_breakpoint_disable(
        self,
        session_id: str,
        intent_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        validated = _workflow_timeout(timeout)
        if isinstance(validated, ValueError):
            return _failure(validated, session_id=session_id)

        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_mutable_workflow(session_id)
            transition = disable_workflow_breakpoint_intent(
                workflow.state,
                intent_id,
            )
            updated = self._execute_workflow_transition_locked(
                session_id,
                runtime,
                workflow,
                transition,
                timeout=validated,
            )
            return {"workflow": updated.to_dict(), "intent_id": intent_id}

        return self._workflow_request(session_id, action)

    def workflow_breakpoint_remove(
        self,
        session_id: str,
        intent_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        validated = _workflow_timeout(timeout)
        if isinstance(validated, ValueError):
            return _failure(validated, session_id=session_id)

        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_mutable_workflow(session_id)
            disabled = disable_workflow_breakpoint_intent(
                workflow.state,
                intent_id,
            )
            updated = self._execute_workflow_transition_locked(
                session_id,
                runtime,
                workflow,
                disabled,
                timeout=validated,
            )
            removed = remove_workflow_breakpoint_intent(updated.state, intent_id)
            updated = self._execute_workflow_transition_locked(
                session_id,
                runtime,
                updated,
                removed,
                timeout=validated,
            )
            return {"workflow": updated.to_dict(), "intent_id": intent_id}

        return self._workflow_request(session_id, action)

    def workflow_breakpoint_list(self, session_id: str) -> Result[JsonObject]:
        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_workflow(session_id)
            serialized = workflow.to_dict()
            state = cast(JsonObject, serialized["state"])
            return {
                "workflow_id": workflow.id,
                "status": workflow.status.value,
                "breakpoints": state["breakpoints"],
            }

        return self._workflow_request(session_id, action)

    def workflow_navigate_to_event(
        self,
        session_id: str,
        kind: str,
        *,
        fields: Mapping[str, EventScalar] | None = None,
        timeout: float = 30.0,
        event_budget: int = 1024,
    ) -> Result[JsonObject]:
        try:
            pattern = EventPattern.create(kind, fields)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)
        return self._workflow_navigate(
            session_id,
            pattern,
            timeout=timeout,
            event_budget=event_budget,
        )

    def workflow_navigate_to_breakpoint(
        self,
        session_id: str,
        intent_id: str,
        *,
        timeout: float = 30.0,
        event_budget: int = 1024,
    ) -> Result[JsonObject]:
        validated = _workflow_timeout(timeout)
        if isinstance(validated, ValueError):
            return _failure(validated, session_id=session_id)
        max_budget = _max_workflow_event_budget()
        if type(event_budget) is not int or not 1 <= event_budget <= max_budget:
            return _failure(
                ValueError(f"event_budget must be between 1 and {max_budget}"),
                session_id=session_id,
            )

        def action(runtime: _BackendRuntime) -> JsonObject:
            workflow = self._require_mutable_workflow(session_id)
            intent = workflow.state.breakpoints.intent(intent_id)
            if intent is None:
                raise ValueError(f"breakpoint intent is not defined: {intent_id}")
            if not intent.enabled:
                raise ValueError(f"breakpoint intent is disabled: {intent_id}")
            prepared = put_workflow_breakpoint_intent(workflow.state, intent)
            workflow = self._execute_workflow_transition_locked(
                session_id,
                runtime,
                workflow,
                prepared,
                timeout=validated,
            )
            binding = workflow.state.breakpoints.binding(intent_id)
            if binding is None:
                raise ValueError(
                    f"breakpoint intent is deferred until its module is loaded: {intent_id}"
                )
            pattern = EventPattern.create(
                "breakpoint.hit",
                {"address": binding.address},
            )
            return self._navigate_locked(
                session_id,
                runtime,
                workflow,
                pattern,
                timeout=validated,
                event_budget=event_budget,
            )

        return self._workflow_request(session_id, action)


