"""Contract tests for the workflow MCP surface's input guards and routing.

``WorkflowAnalysisMixin`` is a thin orchestration layer that ``AnalysisService``
mixes in: every method validates untrusted arguments (timeouts, module-refresh
keys, breakpoint intents, navigation budgets) and then hands a closure to
``_workflow_request`` to run under the x64dbg runtime lock. These tests drive
that surface with all service helpers stubbed, so the validation branches and
the closure routing are exercised without a live backend.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace
from typing import Any, cast

import pytest

import headless_re_mcp.core.service_workflow as sw
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.workflows.executor import WorkflowExecution, WorkflowExecutionError
from headless_re_mcp.workflows.runtime import WorkflowRunStatus


class _FakeBreakpoints:
    def __init__(
        self,
        *,
        intents: dict[str, Any] | None = None,
        bindings: dict[str, Any] | None = None,
    ) -> None:
        self._intents = dict(intents or {})
        self._bindings = dict(bindings or {})

    def intent(self, intent_id: str) -> Any:
        return self._intents.get(intent_id)

    def binding(self, intent_id: str) -> Any:
        return self._bindings.get(intent_id)


class _FakeState:
    def __init__(self, breakpoints: _FakeBreakpoints | None = None) -> None:
        self.breakpoints = breakpoints or _FakeBreakpoints()


class _FakeWorkflow:
    def __init__(self, state: _FakeState | None = None) -> None:
        self.id = "wf-1"
        self.status = SimpleNamespace(value="running")
        self.state = state or _FakeState()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status.value,
            "state": {"breakpoints": [{"id": "b1"}]},
        }


class _Double(sw.WorkflowAnalysisMixin):
    """A ``WorkflowAnalysisMixin`` host with every service helper stubbed."""

    def __init__(self, workflow: _FakeWorkflow | None = None) -> None:
        self.workflow = workflow or _FakeWorkflow()
        self.calls: list[tuple[Any, ...]] = []
        self.cancel_signalled = False
        self._rt = SimpleNamespace(
            lock=threading.RLock(),
            navigation_cancel=SimpleNamespace(set=self._signal_cancel),
        )
        self._workflow_owner = SimpleNamespace(  # type: ignore[assignment]
            put=lambda sid, wf: self.calls.append(("owner_put", wf)),
        )

    def _signal_cancel(self) -> None:
        self.cancel_signalled = True

    def _runtime(self, session_id: str, kind: Any) -> Any:
        self.calls.append(("_runtime", kind))
        return self._rt

    def _workflow_request(self, session_id: str, action: Any) -> Any:
        # Mirrors AnalysisService._workflow_request: lock, run, wrap.
        try:
            with self._rt.lock:
                data = action(self._rt)
            return _success(data, session_id=session_id, backend="x64dbg")
        except BaseException as exc:  # noqa: BLE001 - envelope contract
            return _failure(exc, session_id=session_id)

    def _require_workflow(self, session_id: str) -> Any:
        return self.workflow

    def _require_mutable_workflow(self, session_id: str) -> Any:
        return self.workflow

    def _execute_workflow_transition_locked(
        self,
        session_id: str,
        runtime: Any,
        workflow: Any,
        transition: Any,
        *,
        timeout: float,
        status: Any = None,
    ) -> Any:
        self.calls.append(("exec", transition, status))
        return self.workflow

    def _workflow_ensure_paused_locked(
        self, session_id: str, runtime: Any, *, timeout: float
    ) -> None:
        self.calls.append(("ensure_paused",))

    def _workflow_resolve_module_locked(
        self, session_id: str, runtime: Any, selector: Any, *, timeout: float
    ) -> Any:
        self.calls.append(("resolve_module", selector))
        return "MAPPING"

    def _require_event_cursor(self, runtime: Any) -> Any:
        return SimpleNamespace(value=7)

    def _navigate_locked(
        self,
        session_id: str,
        runtime: Any,
        workflow: Any,
        pattern: Any,
        *,
        timeout: float,
        event_budget: int,
    ) -> Any:
        self.calls.append(("navigate", pattern.kind, event_budget))
        return {"navigated": True, "pattern": pattern.kind}

    def _record_workflow_failure_locked(self, session_id: str, workflow: Any, error: Any) -> Any:
        self.calls.append(("record_failure", error))
        return self.workflow


@pytest.fixture
def engine(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    """Replace the workflow engine functions with recording stubs."""
    recorded: dict[str, list[Any]] = {}

    def stub(name: str, ret: Any) -> Any:
        def fn(*args: Any, **kwargs: Any) -> Any:
            recorded.setdefault(name, []).append((args, kwargs))
            return ret

        return fn

    monkeypatch.setattr(sw, "prepare_workflow_reset", stub("prepare_reset", "T_reset"))
    monkeypatch.setattr(sw, "cancel_workflow_navigation", stub("cancel_nav", "T_cancel"))
    monkeypatch.setattr(sw, "track_workflow_module", stub("track", "T_track"))
    monkeypatch.setattr(sw, "untrack_workflow_module", stub("untrack", "T_untrack"))
    monkeypatch.setattr(sw, "request_workflow_module_refresh", stub("refresh", "T_refresh"))
    monkeypatch.setattr(sw, "put_workflow_breakpoint_intent", stub("put", "T_put"))
    monkeypatch.setattr(sw, "disable_workflow_breakpoint_intent", stub("disable", "T_disable"))
    monkeypatch.setattr(sw, "remove_workflow_breakpoint_intent", stub("remove", "T_remove"))
    monkeypatch.setattr(sw, "execute_workflow_transition", stub("execute", None))
    monkeypatch.setattr(sw, "create_workflow_runtime", lambda *, cursor: _FakeWorkflow())
    monkeypatch.setattr(sw, "_ServiceWorkflowPort", stub("port", "PORT"))
    return recorded


# --- timeout guards ---------------------------------------------------------

_TIMEOUT_GUARDED = (
    ("workflow_reset", ()),
    ("workflow_cancel", ()),
    ("workflow_module_track", ("key", SimpleNamespace())),
    ("workflow_module_untrack", ("key",)),
    ("workflow_module_refresh", ()),
    ("workflow_breakpoint_put", ("intent", "module", 0)),
    ("workflow_breakpoint_disable", ("intent",)),
    ("workflow_breakpoint_remove", ("intent",)),
    ("workflow_navigate_to_breakpoint", ("intent",)),
)


@pytest.mark.parametrize(("method_name", "extra"), _TIMEOUT_GUARDED)
def test_a_nonpositive_deadline_is_refused_before_any_backend_touch(
    method_name: str, extra: tuple[Any, ...]
) -> None:
    host = _Double()
    method = getattr(host, method_name)
    result = method("sess", *extra, timeout=-1.0)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_request"
    # A refused deadline must not have reached the runtime.
    assert not host.calls


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0.0, -5.0, 10_000_000.0])
def test_the_timeout_validator_rejects_the_whole_hostile_range(bad: float) -> None:
    host = _Double()
    result = host.workflow_reset("sess", timeout=bad)
    assert result.ok is False


# --- module-refresh key validation ------------------------------------------


@pytest.mark.parametrize(
    "keys",
    [
        [],  # empty selection is not "refresh all"; it is nonsense
        ["a", ""],  # a blank key
        ["a", "   "],  # a whitespace-only key strips to blank
        ["dup", "dup"],  # duplicates
    ],
)
def test_module_refresh_rejects_blank_empty_or_duplicate_keys(keys: list[str]) -> None:
    host = _Double()
    result = host.workflow_module_refresh("sess", keys=keys)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_request"
    assert not host.calls


def test_module_refresh_of_every_key_runs_the_transition(
    engine: dict[str, list[Any]],
) -> None:
    host = _Double()
    result = host.workflow_module_refresh("sess", keys=None)
    assert result.ok is True
    # None means "all", so the selection forwarded to the engine is None.
    (args, _kwargs) = engine["refresh"][0]
    assert args[1] is None
    assert ("exec", "T_refresh", None) in host.calls


def test_module_refresh_of_named_keys_strips_and_forwards_a_frozenset(
    engine: dict[str, list[Any]],
) -> None:
    host = _Double()
    result = host.workflow_module_refresh("sess", keys=["  a  ", "b"])
    assert result.ok is True
    (args, _kwargs) = engine["refresh"][0]
    assert args[1] == frozenset({"a", "b"})


# --- breakpoint intent validation -------------------------------------------


@pytest.mark.parametrize(
    ("intent_id", "module_key", "rva"),
    [
        ("", "mod", 0),  # blank intent id
        ("i", "", 0),  # blank module key
        ("i", "mod", -1),  # negative rva
    ],
)
def test_breakpoint_put_refuses_a_malformed_intent_as_invalid_request(
    intent_id: str, module_key: str, rva: int
) -> None:
    host = _Double()
    result = host.workflow_breakpoint_put("sess", intent_id, module_key, rva)
    assert result.ok is False
    assert result.error is not None
    # WorkflowInvariantError is a ValueError, so this stays a caller fault,
    # not a logged internal incident.
    assert result.error.code == "invalid_request"
    assert not host.calls


# --- navigation guards -------------------------------------------------------


def test_navigate_to_event_rejects_a_blank_pattern_kind() -> None:
    host = _Double()
    result = host.workflow_navigate_to_event("sess", "")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_request"


@pytest.mark.parametrize("budget", [0, -1, 10_000_000, "5", 3.0])
def test_navigate_to_breakpoint_bounds_the_event_budget(budget: Any) -> None:
    host = _Double()
    result = host.workflow_navigate_to_breakpoint("sess", "i", event_budget=budget)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_request"


# --- closure routing (engine stubbed) ---------------------------------------


def test_reset_records_the_failure_and_reraises_the_cause(
    engine: dict[str, list[Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _Double()
    cause = ValueError("worker refused reset")

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise WorkflowExecutionError(cause, cast(WorkflowExecution, SimpleNamespace()))

    monkeypatch.setattr(sw, "execute_workflow_transition", boom)
    result = host.workflow_reset("sess")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_request"
    assert result.error.message == "worker refused reset"
    assert any(call[0] == "record_failure" for call in host.calls)
    # The reset runtime was never published because the transition failed.
    assert not any(call[0] == "owner_put" for call in host.calls)


def test_reset_publishes_a_fresh_runtime_on_success(
    engine: dict[str, list[Any]],
) -> None:
    host = _Double()
    result = host.workflow_reset("sess")
    assert result.ok is True
    assert result.data is not None
    assert "workflow" in result.data
    assert any(call[0] == "owner_put" for call in host.calls)


def test_module_untrack_runs_the_transition_and_echoes_the_key(
    engine: dict[str, list[Any]],
) -> None:
    host = _Double()
    result = host.workflow_module_untrack("sess", "  libc  ")
    assert result.ok is True
    assert result.data is not None
    assert result.data["module_key"] == "libc"
    assert ("exec", "T_untrack", None) in host.calls


def test_cancel_signals_navigation_then_records_a_cancelled_status(
    engine: dict[str, list[Any]],
) -> None:
    host = _Double()
    result = host.workflow_cancel("sess")
    assert result.ok is True
    assert host.cancel_signalled is True
    # The transition was recorded with the CANCELLED run status.
    exec_calls = [c for c in host.calls if c[0] == "exec"]
    assert exec_calls and exec_calls[0][2] is WorkflowRunStatus.CANCELLED
    assert any(c[0] == "ensure_paused" for c in host.calls)


def test_breakpoint_list_projects_status_and_breakpoints() -> None:
    host = _Double()
    result = host.workflow_breakpoint_list("sess")
    assert result.ok is True
    assert result.data is not None
    assert result.data["workflow_id"] == "wf-1"
    assert result.data["status"] == "running"
    assert result.data["breakpoints"] == [{"id": "b1"}]


def test_navigate_to_breakpoint_errors_when_the_intent_is_unknown(
    engine: dict[str, list[Any]],
) -> None:
    host = _Double(_FakeWorkflow(_FakeState(_FakeBreakpoints())))
    result = host.workflow_navigate_to_breakpoint("sess", "ghost")
    assert result.ok is False
    assert result.error is not None
    assert "not defined" in result.error.message


def test_navigate_to_breakpoint_errors_when_the_intent_is_disabled(
    engine: dict[str, list[Any]],
) -> None:
    intent = SimpleNamespace(id="i1", enabled=False)
    host = _Double(_FakeWorkflow(_FakeState(_FakeBreakpoints(intents={"i1": intent}))))
    result = host.workflow_navigate_to_breakpoint("sess", "i1")
    assert result.ok is False
    assert result.error is not None
    assert "disabled" in result.error.message


def test_navigate_to_breakpoint_reports_a_deferred_intent_with_no_binding(
    engine: dict[str, list[Any]],
) -> None:
    intent = SimpleNamespace(id="i1", enabled=True)
    host = _Double(_FakeWorkflow(_FakeState(_FakeBreakpoints(intents={"i1": intent}))))
    result = host.workflow_navigate_to_breakpoint("sess", "i1")
    assert result.ok is False
    assert result.error is not None
    assert "deferred" in result.error.message


def test_navigate_to_breakpoint_navigates_once_the_binding_resolves(
    engine: dict[str, list[Any]],
) -> None:
    intent = SimpleNamespace(id="i1", enabled=True)
    binding = SimpleNamespace(address=0x401000)
    host = _Double(
        _FakeWorkflow(
            _FakeState(_FakeBreakpoints(intents={"i1": intent}, bindings={"i1": binding}))
        )
    )
    result = host.workflow_navigate_to_breakpoint("sess", "i1", event_budget=64)
    assert result.ok is True
    assert result.data is not None
    assert result.data["navigated"] is True
    assert any(c[0] == "navigate" and c[2] == 64 for c in host.calls)
