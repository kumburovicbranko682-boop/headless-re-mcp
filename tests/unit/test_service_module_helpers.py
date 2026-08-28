"""Module-level helpers of the AnalysisService facade.

These are the free functions at the bottom of ``core/service.py`` that the
class methods lean on: the x64dbg worker factory's platform/config guards, the
workflow status/failure classifiers, the session serialiser's type guard, the
fail-closed artifact-ownership resolve guard, and the DIE / Exeinfo PE artifact
writers' invalid-id, size-limit, and temp-file cleanup arms. None of these need
a live backend, so they are exercised directly rather than through a session.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service as service_module
from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.addressing import AddressSyncError
from headless_re_mcp.core.models import Architecture, BackendKind, Session, TargetKind
from headless_re_mcp.core.service import (
    AnalysisService,
    _create_xdbg_worker,
    _exeinfope_log_path,
    _session_json,
    _session_owns_artifact_path,
    _workflow_failure,
    _workflow_status_for_state,
    _write_die_artifact,
    _write_exeinfope_artifact,
)
from headless_re_mcp.core.session import InvalidStateTransition
from headless_re_mcp.workflows.engine import WorkflowState
from headless_re_mcp.workflows.navigation import EventPattern, NavigationState, NavigationStatus
from headless_re_mcp.workflows.runtime import WorkflowRunStatus

# Reuse the detection guards' fully-populated scan-result factories so the
# writers see the exact shape they persist in production.
from tests.unit.test_detection_service_guards import _die_result, _exeinfo_result


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = dict(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    base.update(overrides)
    return Settings(**base)


def _pe_session(tmp_path: Path, arch: Architecture) -> Session:
    binary = tmp_path / "fixture.exe"
    binary.write_bytes(b"MZ")
    return Session(target=TargetKind.PE, binary=binary, architecture=arch)


# --- _create_xdbg_worker ----------------------------------------------------


def test_create_xdbg_worker_refuses_off_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "name", "posix")
    session = _pe_session(tmp_path, Architecture.X64)
    with pytest.raises(XdbgRpcError) as caught:
        _create_xdbg_worker(session, _settings(tmp_path))
    assert caught.value.code == "unsupported_on_platform"


@pytest.mark.parametrize(
    "arch,variable",
    [
        (Architecture.X86, "HEADLESS_RE_X64DBG_HEADLESS_X86"),
        (Architecture.X64, "HEADLESS_RE_X64DBG_HEADLESS_X64"),
    ],
)
def test_create_xdbg_worker_reports_the_missing_executable_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arch: Architecture, variable: str
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    session = _pe_session(tmp_path, arch)
    with pytest.raises(XdbgRpcError) as caught:
        _create_xdbg_worker(session, _settings(tmp_path))
    assert caught.value.code == "backend_unavailable"
    assert caught.value.details["environment_variable"] == variable


def test_create_xdbg_worker_builds_the_client_when_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    built: dict[str, Any] = {}

    def fake_client(executable: Any, architecture: Any, *, hidden_desktop: Any) -> str:
        built["executable"] = executable
        built["architecture"] = architecture
        built["hidden_desktop"] = hidden_desktop
        return "client"

    monkeypatch.setattr(service_module, "XdbgClient", fake_client)
    exe = tmp_path / "x64dbg.exe"
    exe.write_bytes(b"")
    session = _pe_session(tmp_path, Architecture.X64)
    result: Any = _create_xdbg_worker(session, _settings(tmp_path, x64dbg_headless_x64=exe))
    assert result == "client"
    assert built["architecture"] is Architecture.X64
    assert built["executable"] == exe


# --- workflow classifiers ---------------------------------------------------


def test_workflow_status_is_active_while_navigation_is_waiting() -> None:
    nav = NavigationState(pattern=EventPattern.create("breakpoint.hit"), cursor=0, event_budget=4)
    assert nav.status is NavigationStatus.WAITING
    state = WorkflowState(navigation=nav)
    assert _workflow_status_for_state(state) is WorkflowRunStatus.ACTIVE


def test_workflow_status_is_idle_without_a_waiting_navigation() -> None:
    assert _workflow_status_for_state(WorkflowState()) is WorkflowRunStatus.IDLE


def test_workflow_failure_maps_each_exception_family() -> None:
    sync = AddressSyncError("module_not_found", "gone", key="v")
    assert _workflow_failure(sync) == ("module_not_found", {"key": "v"}, False)

    worker = IdaWorkerError("boom", "ida fell over")
    code, details, retryable = _workflow_failure(worker)
    assert code == "boom" and retryable == worker.retryable

    assert _workflow_failure(TimeoutError()) == ("workflow_timeout", {}, True)
    assert _workflow_failure(InvalidStateTransition("closing")) == ("invalid_request", {}, False)
    assert _workflow_failure(ValueError("nope")) == ("invalid_request", {}, False)
    other = _workflow_failure(RuntimeError("weird"))
    assert other == ("workflow_execution_failed", {"exception": "RuntimeError"}, False)


# --- _session_json ----------------------------------------------------------


def test_session_json_rejects_a_non_object_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Weird:
        def model_dump(self, *, mode: str) -> Any:
            return ["not", "a", "dict"]

    with pytest.raises(TypeError, match="did not serialize to an object"):
        _session_json(_Weird())  # type: ignore[arg-type]


# --- _session_owns_artifact_path fail-closed resolve ------------------------


def test_ownership_is_refused_when_an_owned_root_cannot_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A root whose resolve() raises is skipped, never treated as a match."""
    real_resolve = Path.resolve
    calls = {"n": 0}

    def flaky_resolve(self: Path, *args: Any, **kwargs: Any) -> Path:
        calls["n"] += 1
        # Calls 1 (the target) and 2 (the artifact root inside
        # _session_artifact_roots) must succeed; every owned-root resolve after
        # them raises so the loop skips all of them and fails closed.
        if calls["n"] <= 2:
            return real_resolve(self, *args, **kwargs)
        raise OSError("resolve failed")

    monkeypatch.setattr(Path, "resolve", flaky_resolve)
    root = tmp_path / "artifacts"
    sid = "a" * 32
    target = root / "detection" / sid / "x.json"
    assert _session_owns_artifact_path(root, sid, target) is False


# --- artifact writers -------------------------------------------------------


def test_die_writer_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    result = _die_result(sample)
    with pytest.raises(OSError, match="invalid session id"):
        _write_die_artifact(tmp_path / "artifacts", "..", result)


def test_die_writer_refuses_a_payload_over_the_limit(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    result = _die_result(sample)
    object.__setattr__(result, "raw_json", "x" * (9 * 1024 * 1024))
    with pytest.raises(OSError, match="exceeds the 8 MiB"):
        _write_die_artifact(tmp_path / "artifacts", "s" * 32, result)


def test_die_writer_cleans_up_the_temp_file_when_the_rename_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    result = _die_result(sample)
    leftover: dict[str, Path] = {}
    real_replace = os.replace

    def failing_replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        leftover["src"] = Path(src)
        raise OSError("rename failed")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(OSError, match="rename failed"):
        _write_die_artifact(tmp_path / "artifacts", "s" * 32, result)
    del real_replace
    assert not leftover["src"].exists(), "the temp file must be unlinked in the finally arm"


def test_exeinfope_log_path_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="invalid session id"):
        _exeinfope_log_path(tmp_path / "artifacts", "..")


def test_exeinfope_writer_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    result = _exeinfo_result(sample, tmp_path / "log.txt")
    with pytest.raises(OSError, match="invalid session id"):
        _write_exeinfope_artifact(tmp_path / "artifacts", ".", result)


def test_exeinfope_writer_refuses_a_payload_over_the_limit(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    result = _exeinfo_result(sample, tmp_path / "log.txt")
    object.__setattr__(result, "raw_log", "y" * (9 * 1024 * 1024))
    with pytest.raises(OSError, match="exceeds the 8 MiB"):
        _write_exeinfope_artifact(tmp_path / "artifacts", "s" * 32, result)


def test_exeinfope_writer_cleans_up_the_temp_file_when_the_rename_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    result = _exeinfo_result(sample, tmp_path / "log.txt")
    leftover: dict[str, Path] = {}

    def failing_replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        leftover["src"] = Path(src)
        raise OSError("rename failed")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(OSError, match="rename failed"):
        _write_exeinfope_artifact(tmp_path / "artifacts", "s" * 32, result)
    assert not leftover["src"].exists()


# --- AnalysisService lifecycle guards ---------------------------------------


def test_configuring_both_worker_factories_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="worker_factory or static_worker_factory"):
        AnalysisService(
            _settings(tmp_path),
            worker_factory=lambda session, settings: None,  # type: ignore[arg-type,return-value]
            static_worker_factory=lambda session, settings: None,  # type: ignore[arg-type,return-value]
        )


def test_discarding_a_runtime_that_was_never_registered_is_a_noop(tmp_path: Path) -> None:
    service = AnalysisService(_settings(tmp_path))
    # No runtime is registered, so the pop returns None and the method returns
    # before touching any worker; the call must simply not raise.
    service._discard_dead_runtime("no-such-session", BackendKind.X64DBG)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink escape semantics")
def test_session_work_dir_refuses_a_symlink_that_escapes_the_category(tmp_path: Path) -> None:
    service = AnalysisService(_settings(tmp_path))
    root = service.settings.artifact_root.expanduser().resolve()
    category = root / "unpack"
    category.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    # A single-component id passes the name guard, but the symlink resolves out
    # of the category tree, so relative_to raises and the dir is refused.
    (category / "escape").symlink_to(outside, target_is_directory=True)
    assert service._session_work_dir("unpack", "escape") is None


def test_session_work_dir_returns_the_nested_path_for_a_plain_id(tmp_path: Path) -> None:
    service = AnalysisService(_settings(tmp_path))
    resolved = service._session_work_dir("unpack", "s" * 32)
    assert resolved is not None
    assert resolved.name == "s" * 32
    assert resolved.parent.name == "unpack"
