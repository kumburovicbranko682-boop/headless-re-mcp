"""Attach/launch/modules/stealth branches of the AnalysisService dynamic surface.

test_dynamic_service.py drives the run-control happy paths; the composition
root's ``dynamic_attach`` (pid liveness, pause-after-attach, child-window hints),
``dynamic_launch`` (working dir, implicit open failure, pass-system-breakpoint
resume), the ``dynamic_modules`` argument guards, and the stealth status/set
guard arms had no direct test. Everything runs against the FakeDynamicWorker;
pid-liveness and child-window probes are patched so nothing touches the host.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.process_tree as process_tree
import headless_re_mcp.core.service as service_mod
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService, JsonObject
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _service,
    _settings,
    _state,
    _write_minimal_pe,
)


def _service_with_headless(
    tmp_path: Path, *, x64: Path | None, x86: Path | None
) -> AnalysisService:
    settings = replace(
        _settings(tmp_path),
        x64dbg_headless_x64=x64,
        x64dbg_headless_x86=x86,
    )
    return AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, s: FakeDynamicWorker(),
    )


class _FailOnCommandWorker(FakeDynamicWorker):
    """Runs normally except for one run-control command, which raises."""

    def __init__(self, fail_command: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._fail_command = fail_command

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == self._fail_command:
            self.requests.append((command, params or {}))
            raise XdbgRpcError("backend_error", f"{command} rejected")
        return super().request(command, params, timeout=timeout)


def _dynamic_session(tmp_path: Path, worker: FakeDynamicWorker) -> tuple[Any, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    return service, session_id


# --- dynamic_attach -------------------------------------------------------------


def test_attach_rejects_a_non_positive_pid(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_attach(session_id, 0)

    assert not result.ok
    assert result.error is not None
    assert "positive integer" in result.error.message


def test_attach_reports_a_dead_pid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_mod, "is_pid_alive", lambda pid: False)
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_attach(session_id, 4321)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"
    assert result.error.details["pid"] == 4321


def test_attach_annotates_child_window_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_mod, "is_pid_alive", lambda pid: True)
    candidates = [{"pid": 8123, "title": "child window"}]
    monkeypatch.setattr(
        process_tree,
        "probe_child_window_candidates",
        lambda debuggee, list_windows_fn=None: candidates,
    )
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_attach(session_id, 4321)

    assert result.ok and result.data is not None
    assert result.data["child_windows_hint"] == "windows_on_child_pids"
    assert result.data["suggested_child_pids"] == [8123]
    assert result.data["child_candidates"] == candidates


def test_attach_without_children_leaves_no_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_mod, "is_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        process_tree,
        "probe_child_window_candidates",
        lambda debuggee, list_windows_fn=None: [],
    )
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_attach(session_id, 4321)

    assert result.ok and result.data is not None
    assert "child_windows_hint" not in result.data


def test_attach_survives_a_failing_child_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_mod, "is_pid_alive", lambda pid: True)

    def boom(debuggee: int, list_windows_fn: Any = None) -> Any:
        raise RuntimeError("toolhelp exploded")

    monkeypatch.setattr(process_tree, "probe_child_window_candidates", boom)
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_attach(session_id, 4321)

    assert result.ok and result.data is not None  # the probe failure is swallowed
    assert "child_windows_hint" not in result.data


class _RunningAfterAttachWorker(FakeDynamicWorker):
    """Reports 'running' even when the service waited for a pause."""

    def wait_for_state(
        self,
        states: set[str],
        *,
        timeout: float = 30.0,
        after_event_sequence: int | None = None,
        transition_event_kinds: Any = frozenset(),
    ) -> JsonObject:
        self.waits.append((states, timeout, after_event_sequence, transition_event_kinds))
        self.current_state = _state("running")
        return dict(self.current_state)


def test_attach_that_stays_running_is_paused_when_requested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_mod, "is_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        process_tree,
        "probe_child_window_candidates",
        lambda debuggee, list_windows_fn=None: [],
    )
    service, session_id = _dynamic_session(tmp_path, _RunningAfterAttachWorker())

    result = service.dynamic_attach(session_id, 4321, pause_after_attach=True)

    assert result.ok and result.data is not None
    # dynamic_pause was invoked after the attach reported still-running.
    assert isinstance(result.data.get("state"), dict)


def test_attach_returns_the_backend_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_mod, "is_pid_alive", lambda pid: True)
    service, session_id = _dynamic_session(tmp_path, _FailOnCommandWorker("debug.attach"))

    result = service.dynamic_attach(session_id, 4321)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


class _RunningPauseFailsWorker(_RunningAfterAttachWorker):
    """Attach reports running; the follow-up pause request then fails."""

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "debug.pause":
            self.requests.append((command, params or {}))
            raise XdbgRpcError("backend_error", "pause rejected")
        return super().request(command, params, timeout=timeout)


def test_attach_returns_a_failing_follow_up_pause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_mod, "is_pid_alive", lambda pid: True)
    service, session_id = _dynamic_session(tmp_path, _RunningPauseFailsWorker())

    result = service.dynamic_attach(session_id, 4321, pause_after_attach=True)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


# --- dynamic_launch -------------------------------------------------------------


def test_launch_forwards_the_working_directory(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id = _dynamic_session(tmp_path, worker)

    result = service.dynamic_launch(session_id, arguments="--go", working_directory="/tmp/work")

    assert result.ok
    launch_calls = [params for cmd, params in worker.requests if cmd == "debug.launch"]
    assert launch_calls and launch_calls[0]["working_directory"] == "/tmp/work"
    assert launch_calls[0]["arguments"] == "--go"


def test_launch_returns_the_open_failure_when_implicit_open_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    # Do not open the dynamic backend: launch will try an implicit open, which
    # we force to fail so the failure is surfaced verbatim.
    failure = Result[JsonObject](
        ok=False, error=RpcError(code="backend_unavailable", message="cannot open")
    )
    monkeypatch.setattr(
        type(service.services.runtime),
        "open_dynamic",
        lambda self, sid: failure,
    )

    result = service.dynamic_launch(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_unavailable"


def test_launch_resumes_past_the_system_breakpoint(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id = _dynamic_session(tmp_path, worker)

    result = service.dynamic_launch(session_id, pass_system_breakpoint=True)

    assert result.ok and result.data is not None
    assert result.data["pass_system_breakpoint"] is True
    assert "Resumed once after initial pause" in result.data["note"]
    commands = [cmd for cmd, _ in worker.requests]
    assert "debug.launch" in commands and "debug.resume" in commands


def test_launch_returns_the_backend_failure(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, _FailOnCommandWorker("debug.launch"))

    result = service.dynamic_launch(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_launch_returns_a_failing_post_breakpoint_resume(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, _FailOnCommandWorker("debug.resume"))

    result = service.dynamic_launch(session_id, pass_system_breakpoint=True)

    assert not result.ok  # the launch succeeded but the follow-up resume failed
    assert result.error is not None
    assert result.error.code == "backend_error"


# --- dynamic_modules argument guards --------------------------------------------


def test_modules_rejects_a_negative_offset(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_modules(session_id, offset=-1)

    assert not result.ok
    assert result.error is not None
    assert "non-negative" in result.error.message


def test_modules_rejects_an_out_of_range_limit(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_modules(session_id, limit=0)

    assert not result.ok
    assert result.error is not None
    assert "between 1 and 1024" in result.error.message


def test_modules_swallows_a_failed_resync_flag_clear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # modules.list clears snapshot_resync_required on a best-effort basis. If the
    # runtime lookup for that flag write throws, the successful listing must still
    # be returned. _dynamic_request looks the runtime up once; the post-listing
    # flag clear is the second lookup, which we make raise.
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())
    real = AnalysisService._runtime
    calls = {"n": 0}

    def flaky(self: AnalysisService, sid: str, kind: Any) -> Any:
        calls["n"] += 1
        if calls["n"] >= 2:
            raise RuntimeError("runtime vanished mid-clear")
        return real(self, sid, kind)

    monkeypatch.setattr(AnalysisService, "_runtime", flaky)

    result = service.dynamic_modules(session_id)

    assert result.ok  # the swallowed flag-clear failure did not sink the listing


# --- stealth status / set guards ------------------------------------------------


def test_stealth_status_reports_the_session_architecture(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_stealth_status(session_id)

    assert result.ok and result.data is not None
    assert result.data["session_id"] == session_id
    assert result.data["session_architecture"] == "x64"


def test_stealth_set_without_a_configured_headless_is_plugin_missing(
    tmp_path: Path,
) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_stealth_set("vmp")  # no session, no configured layout

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "plugin_missing"
    assert "no x64dbg headless executable" in result.error.message


def test_stealth_set_for_a_session_without_a_layout_is_plugin_missing(
    tmp_path: Path,
) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_stealth_set("vmp", session_id=session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "plugin_missing"
    assert result.error.details["architecture"] == "x64"


def test_stealth_set_rejects_armadillo_for_an_x64_session(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_stealth_set("armadillo", session_id=session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_params"
    assert "x86-only" in result.error.message


def test_stealth_set_off_applies_to_every_configured_architecture(
    tmp_path: Path,
) -> None:
    service = _service_with_headless(
        tmp_path,
        x64=tmp_path / "x64" / "x64_headless.exe",
        x86=tmp_path / "x86" / "x32_headless.exe",
    )

    result = service.dynamic_stealth_set("off")

    assert result.ok and result.data is not None
    assert result.data["profile"] == "off"
    # "off" requires no plugin files, so both configured layouts get written.
    architectures = {item["architecture"] for item in result.data["applied"]}
    assert architectures == {"x86", "x64"}


def test_stealth_set_armadillo_with_only_x64_configured_has_no_target(
    tmp_path: Path,
) -> None:
    # armadillo is x86-only, so with only an x64 layout the sole target is
    # skipped and nothing is applied.
    service = _service_with_headless(
        tmp_path,
        x64=tmp_path / "x64" / "x64_headless.exe",
        x86=None,
    )

    result = service.dynamic_stealth_set("armadillo")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_params"
    assert "x86-only" in result.error.message


def test_stealth_status_for_an_unknown_session_is_a_structured_failure(
    tmp_path: Path,
) -> None:
    # The session lookup at the end of the try raises SessionNotFound, which
    # the method's BaseException arm turns into a Result failure rather than
    # letting it escape.
    service, _ = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.dynamic_stealth_status("not-a-real-session")

    assert not result.ok
    assert result.error is not None


# --- address-translation argument guards ----------------------------------------


def test_resolve_runtime_address_rejects_a_negative_address(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.resolve_runtime_address(session_id, -1)

    assert not result.ok
    assert result.error is not None
    assert "non-negative integer" in result.error.message


def test_resolve_runtime_address_rejects_an_unknown_source(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.resolve_runtime_address(session_id, 0x1000, source="galaxy")

    assert not result.ok
    assert result.error is not None
    assert "static, rva, runtime" in result.error.message


def test_analyze_function_dynamic_rejects_a_non_numeric_timeout(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.analyze_function_dynamic(session_id, 0x1000, timeout="soon")

    assert not result.ok
    assert result.error is not None
    assert "timeout must be a number" in result.error.message


def test_analyze_function_dynamic_rejects_an_out_of_range_timeout(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path, FakeDynamicWorker())

    result = service.analyze_function_dynamic(session_id, 0x1000, timeout=0.0)

    assert not result.ok
    assert result.error is not None
    assert "timeout must be >" in result.error.message
