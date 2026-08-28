"""Workflow navigation guards, sync/runtime fatal arms, and debuggee annotation.

The workflow happy paths are covered in test_dynamic_service.py; this targets the
composition root's error edges: navigate argument guards and the missing
``events.read`` capability, the ``_sync_address`` / ``_main_module_mapping``
capability and fatal-worker arms (which drive ``_fail_runtime``), the
``_dynamic_request`` fatal arm, the redundant-run-control probe failure, and the
``_annotate_debuggee_pids`` helper.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import BackendKind, SessionState
from headless_re_mcp.core.service import JsonObject
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    FakeStaticWorker,
    _create,
    _service,
    _write_minimal_pe,
)


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "fixture.exe"
    _write_minimal_pe(path)
    return path


def _dynamic_session(tmp_path: Path, worker: FakeDynamicWorker) -> tuple[Any, str]:
    service = _service(tmp_path, worker)
    session_id = _create(service, _binary(tmp_path))
    assert service.open_dynamic(session_id).ok
    return service, session_id


def _both_backends(
    tmp_path: Path, dynamic: FakeDynamicWorker, static: FakeStaticWorker
) -> tuple[Any, str]:
    service = _service(tmp_path, dynamic, static)
    session_id = _create(service, _binary(tmp_path))
    assert service.open_static(session_id).ok
    assert service.open_dynamic(session_id).ok
    return service, session_id


class _NoModulesWorker(FakeDynamicWorker):
    @property
    def capabilities(self) -> frozenset[str]:
        return super().capabilities - {"modules.list"}


class _NoEventsWorker(FakeDynamicWorker):
    @property
    def capabilities(self) -> frozenset[str]:
        return super().capabilities - {"events.read"}


class _FatalOnCommandWorker(FakeDynamicWorker):
    def __init__(self, command: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._command = command

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == self._command:
            self.requests.append((command, params or {}))
            raise XdbgRpcError("worker_exited", f"{command} died")
        return super().request(command, params, timeout=timeout)


class _PauseAndProbeFailWorker(FakeDynamicWorker):
    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "debug.pause":
            self.requests.append((command, params or {}))
            raise XdbgRpcError("debugger_command_failed", "pause rejected")
        if command == "debug.state":
            self.requests.append((command, params or {}))
            raise XdbgRpcError("worker_protocol_error", "state probe failed")
        return super().request(command, params, timeout=timeout)


class _FatalStaticWorker(FakeStaticWorker):
    def __init__(self) -> None:
        self.armed = False

    @property
    def metadata(self) -> JsonObject:
        # Armed only after the backend has opened, so the fatal worker loss
        # surfaces during the mapping build rather than at open time.
        if self.armed:
            raise IdaWorkerError("worker_exited", "static worker vanished")
        return {"image_base": 0x140000000, "capabilities": ["static.functions"]}


# --- _annotate_debuggee_pids ----------------------------------------------------


def test_annotate_debuggee_pids_attaches_fields(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))

    annotated = service._annotate_debuggee_pids(
        session_id, {"state": "running", "process_id": 4321}
    )

    assert annotated["state"] == "running"


# --- workflow navigate guards ---------------------------------------------------


def test_workflow_navigate_rejects_a_bad_timeout(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))

    result = service.workflow_navigate_to_event(session_id, "debug.paused", timeout=-1)

    assert not result.ok
    assert result.error is not None
    assert "timeout" in result.error.message


def test_workflow_navigate_rejects_a_bad_event_budget(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))

    result = service.workflow_navigate_to_event(session_id, "debug.paused", event_budget=0)

    assert not result.ok
    assert result.error is not None
    assert "event_budget" in result.error.message


def test_workflow_navigate_requires_events_read(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, _NoEventsWorker())

    result = service.workflow_navigate_to_event(session_id, "debug.paused")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "capability_unavailable"
    assert result.error.details["capability"] == "events.read"


# --- sync / main-module-mapping capability and fatal arms -----------------------


def test_sync_reports_a_missing_modules_list_capability(tmp_path: Path) -> None:
    service, session_id = _both_backends(tmp_path, _NoModulesWorker(), FakeStaticWorker())

    result = service.sync_static_to_runtime(session_id, 0x140001000)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "capability_unavailable"
    assert result.error.details["capability"] == "modules.list"


def test_sync_fails_the_runtime_on_a_fatal_dynamic_error(tmp_path: Path) -> None:
    service, session_id = _both_backends(
        tmp_path, _FatalOnCommandWorker("modules.list"), FakeStaticWorker()
    )

    result = service.sync_static_to_runtime(session_id, 0x140001000)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "worker_exited"
    # The fatal error tears the x64dbg runtime down and fails the session.
    assert service.registry.get(session_id).state is SessionState.FAILED


def test_sync_fails_the_runtime_on_a_fatal_static_error(tmp_path: Path) -> None:
    static = _FatalStaticWorker()
    service, session_id = _both_backends(tmp_path, FakeDynamicWorker(), static)
    static.armed = True  # the static worker "dies" only after it opened

    result = service.sync_static_to_runtime(session_id, 0x140001000)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "worker_exited"
    assert result.error.details.get("backend") == BackendKind.IDA.value


# --- _dynamic_request / _absorb_redundant_run_control fatal & probe arms ---------


def test_dynamic_request_fails_the_runtime_on_a_fatal_error(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, _FatalOnCommandWorker("debug.state"))

    result = service.dynamic_state(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "worker_exited"
    assert service.registry.get(session_id).state is SessionState.FAILED


def test_pause_surfaces_the_real_failure_when_the_state_probe_also_fails(
    tmp_path: Path,
) -> None:
    service, session_id = _dynamic_session(tmp_path, _PauseAndProbeFailWorker())

    result = service.dynamic_pause(session_id)

    assert not result.ok
    assert result.error is not None
    # The absorb path probes debug.state; when that also fails, the original
    # pause rejection is surfaced rather than the probe error.
    assert result.error.code == "debugger_command_failed"
