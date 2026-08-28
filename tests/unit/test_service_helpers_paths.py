"""Unit coverage for the module-level helpers in ``core/service.py``.

These are the small, pure functions the facade leans on: the x64dbg worker
factory's platform/configuration guards, backend-name recovery, the workflow
timeout and failure mappers, session JSON serialization, and the atomic DIE /
Exeinfo PE artifact writers with their fail-closed guards.
"""

from __future__ import annotations

import os
import struct
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.backends.x64dbg.stealth import layout_for_headless
from headless_re_mcp.config import Settings
from headless_re_mcp.core.addressing import AddressSyncError
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT
from headless_re_mcp.core.models import Architecture, BackendKind, Session, SessionState
from headless_re_mcp.core.results import _success
from headless_re_mcp.core.service import (
    AnalysisService,
    DynamicWorker,
    StaticWorker,
    _create_xdbg_worker,
    _exeinfope_log_path,
    _recover_backend_kinds,
    _session_artifact_roots,
    _session_json,
    _session_owns_artifact_path,
    _workflow_failure,
    _workflow_timeout,
    _write_die_artifact,
    _write_exeinfope_artifact,
)
from headless_re_mcp.core.session import InvalidStateTransition
from headless_re_mcp.detection.die import DieScanResult
from headless_re_mcp.detection.exeinfope import ExeinfopeScanResult
from headless_re_mcp.detection.models import DetectionSource, ScanMode
from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker, _state


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def _pe_session(tmp_path: Path) -> Any:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    created = service.create_session(str(binary))
    assert created.data is not None
    return service.registry.get(str(created.data["session"]["id"]))


def _die_result(path: Path, *, raw_json: str = "{}") -> DieScanResult:
    return DieScanResult(
        path=path,
        size=path.stat().st_size if path.exists() else 0,
        mode=ScanMode.NORMAL,
        findings=(),
        source=DetectionSource(name="diec", status="completed", version="3.21"),
        raw={"detects": []},
        raw_json=raw_json,
        stdout="{}",
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )


def _exeinfope_result(path: Path, *, raw_log: str = "log") -> ExeinfopeScanResult:
    return ExeinfopeScanResult(
        path=path,
        size=path.stat().st_size if path.exists() else 0,
        mode=ScanMode.NORMAL,
        findings=(),
        source=DetectionSource(name="exeinfope", status="completed", version="0.0.7"),
        raw_log=raw_log,
        log_path=path.with_suffix(".log"),
        stdout="",
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# _create_xdbg_worker
# ---------------------------------------------------------------------------


def test_create_xdbg_worker_refuses_non_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _pe_session(tmp_path)
    monkeypatch.setattr(os, "name", "posix")
    with pytest.raises(XdbgRpcError) as excinfo:
        _create_xdbg_worker(session, _settings(tmp_path))
    assert excinfo.value.code == "unsupported_on_platform"


def test_create_xdbg_worker_requires_a_configured_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _pe_session(tmp_path)
    monkeypatch.setattr(os, "name", "nt")
    with pytest.raises(XdbgRpcError) as excinfo:
        _create_xdbg_worker(session, _settings(tmp_path))
    assert excinfo.value.code == "backend_unavailable"


# ---------------------------------------------------------------------------
# _recover_backend_kinds
# ---------------------------------------------------------------------------


def test_recover_backend_kinds_dedupes_aliases() -> None:
    kinds = _recover_backend_kinds(["ida", "static", "x64dbg", "dynamic"])
    assert kinds == (BackendKind.IDA, BackendKind.X64DBG)


def test_recover_backend_kinds_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="ida, static, x64dbg, dynamic"):
        _recover_backend_kinds(["nonsense"])


# ---------------------------------------------------------------------------
# _workflow_timeout
# ---------------------------------------------------------------------------


def test_workflow_timeout_accepts_a_valid_value() -> None:
    assert _workflow_timeout(5.0) == 5.0


@pytest.mark.parametrize("bad", [0, -1, True, float("inf"), MAX_WORKFLOW_TIMEOUT + 1])
def test_workflow_timeout_rejects_invalid_values(bad: object) -> None:
    result = _workflow_timeout(bad)  # type: ignore[arg-type]
    assert isinstance(result, ValueError)


# ---------------------------------------------------------------------------
# _workflow_failure
# ---------------------------------------------------------------------------


def test_workflow_failure_maps_address_sync_error() -> None:
    code, details, retryable = _workflow_failure(
        AddressSyncError("addr_desync", "mismatch", where="iat")
    )
    assert code == "addr_desync"
    assert details == {"where": "iat"}
    assert retryable is False


def test_workflow_failure_maps_backend_errors() -> None:
    code, _details, retryable = _workflow_failure(
        IdaWorkerError("ida_boom", "boom", retryable=True)
    )
    assert code == "ida_boom"
    assert retryable is True


def test_workflow_failure_maps_timeout() -> None:
    code, _details, retryable = _workflow_failure(TimeoutError("slow"))
    assert code == "workflow_timeout"
    assert retryable is True


def test_workflow_failure_maps_invalid_request() -> None:
    code, _details, retryable = _workflow_failure(InvalidStateTransition("bad state"))
    assert code == "invalid_request"
    assert retryable is False


def test_workflow_failure_maps_unknown() -> None:
    code, details, retryable = _workflow_failure(RuntimeError("weird"))
    assert code == "workflow_execution_failed"
    assert details == {"exception": "RuntimeError"}
    assert retryable is False


# ---------------------------------------------------------------------------
# _session_json
# ---------------------------------------------------------------------------


def test_session_json_rejects_a_non_object_dump() -> None:
    fake = SimpleNamespace(model_dump=lambda mode: ["not", "a", "dict"])
    with pytest.raises(TypeError, match="did not serialize to an object"):
        _session_json(fake)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _session_artifact_roots / _session_owns_artifact_path
# ---------------------------------------------------------------------------


def test_session_artifact_roots_lists_owned_subtrees(tmp_path: Path) -> None:
    roots = _session_artifact_roots(tmp_path, "session-1")
    assert roots
    assert all(root.name == "session-1" for root in roots)
    categories = {root.parent.name for root in roots}
    assert {"unpack", "dump", "detection"} <= categories


def test_session_artifact_roots_fails_closed_for_unsafe_ids(tmp_path: Path) -> None:
    assert _session_artifact_roots(tmp_path, "..") == ()


def test_session_owns_artifact_path_accepts_owned_and_rejects_foreign(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    owned = artifact_root / "unpack" / "session-1" / "dump.bin"
    owned.parent.mkdir(parents=True, exist_ok=True)
    owned.write_bytes(b"x")
    assert _session_owns_artifact_path(artifact_root, "session-1", owned) is True

    foreign = tmp_path / "elsewhere" / "dump.bin"
    foreign.parent.mkdir(parents=True, exist_ok=True)
    foreign.write_bytes(b"x")
    assert _session_owns_artifact_path(artifact_root, "session-1", foreign) is False


def test_session_owns_artifact_path_rejects_another_sessions_tree(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    other = artifact_root / "unpack" / "session-2" / "dump.bin"
    other.parent.mkdir(parents=True, exist_ok=True)
    other.write_bytes(b"x")
    assert _session_owns_artifact_path(artifact_root, "session-1", other) is False


# ---------------------------------------------------------------------------
# _write_die_artifact
# ---------------------------------------------------------------------------


def test_write_die_artifact_persists_json(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    out = _write_die_artifact(tmp_path / "artifacts", "session-1", _die_result(binary))
    written = Path(out)
    assert written.is_file()
    assert written.parent.name == "session-1"


def test_write_die_artifact_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    with pytest.raises(OSError, match="invalid session id"):
        _write_die_artifact(tmp_path / "artifacts", "..", _die_result(binary))


def test_write_die_artifact_refuses_an_oversized_payload(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    big = _die_result(binary, raw_json="x" * (9 * 1024 * 1024))
    with pytest.raises(OSError, match="8 MiB"):
        _write_die_artifact(tmp_path / "artifacts", "session-1", big)


def test_write_die_artifact_cleans_up_after_a_failed_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)

    def boom(src: Any, dst: Any) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="replace failed"):
        _write_die_artifact(tmp_path / "artifacts", "session-1", _die_result(binary))
    directory = (tmp_path / "artifacts").resolve() / "detection" / "session-1"
    assert not list(directory.glob(".die-*.tmp"))


# ---------------------------------------------------------------------------
# _exeinfope_log_path
# ---------------------------------------------------------------------------


def test_exeinfope_log_path_builds_a_path(tmp_path: Path) -> None:
    path = _exeinfope_log_path(tmp_path / "artifacts", "session-1")
    assert path.parent.name == "session-1"
    assert path.name.startswith("exeinfope-")


def test_exeinfope_log_path_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="invalid session id"):
        _exeinfope_log_path(tmp_path / "artifacts", ".")


# ---------------------------------------------------------------------------
# _write_exeinfope_artifact
# ---------------------------------------------------------------------------


def test_write_exeinfope_artifact_persists_json(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    out = _write_exeinfope_artifact(tmp_path / "artifacts", "session-1", _exeinfope_result(binary))
    assert Path(out).is_file()


def test_write_exeinfope_artifact_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    with pytest.raises(OSError, match="invalid session id"):
        _write_exeinfope_artifact(tmp_path / "artifacts", "..", _exeinfope_result(binary))


def test_write_exeinfope_artifact_refuses_an_oversized_payload(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    big = _exeinfope_result(binary, raw_log="x" * (9 * 1024 * 1024))
    with pytest.raises(OSError, match="8 MiB"):
        _write_exeinfope_artifact(tmp_path / "artifacts", "session-1", big)


def test_write_exeinfope_artifact_cleans_up_after_a_failed_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)

    def boom(src: Any, dst: Any) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="replace failed"):
        _write_exeinfope_artifact(tmp_path / "artifacts", "session-1", _exeinfope_result(binary))
    directory = (tmp_path / "artifacts").resolve() / "detection" / "session-1"
    assert not list(directory.glob(".exeinfope-*.tmp"))


# ---------------------------------------------------------------------------
# session_recover / _open_backend facade arms
# ---------------------------------------------------------------------------


def _facade(
    tmp_path: Path,
    *,
    dynamic_workers: list[FakeDynamicWorker] | None = None,
    static_factory: Any | None = None,
) -> AnalysisService:
    remaining: deque[FakeDynamicWorker] = deque(dynamic_workers or [])

    def dynamic_factory(session: Session, settings: Settings) -> DynamicWorker:
        del session, settings
        return remaining.popleft()

    return AnalysisService(
        _settings(tmp_path),
        dynamic_worker_factory=dynamic_factory if dynamic_workers is not None else None,
        static_worker_factory=static_factory,
    )


def _static_factory() -> Any:
    def factory(session: Session, settings: Settings) -> StaticWorker:
        del session, settings
        return FakeStaticWorker()

    return factory


def _create(service: AnalysisService, binary: Path) -> str:
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    session = created.data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _failed_session(
    tmp_path: Path,
    *,
    static_factory: Any | None = None,
) -> tuple[AnalysisService, str, Path]:
    """Drive a session into FAILED through a fatal dynamic worker error."""
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    fatal = FakeDynamicWorker(
        XdbgRpcError("worker_exited", "x64dbg exited with code 1", retryable=False)
    )
    service = _facade(
        tmp_path,
        dynamic_workers=[fatal, FakeDynamicWorker()],
        static_factory=static_factory,
    )
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert not service.dynamic_state(session_id).ok
    assert service.registry.get(session_id).state is SessionState.FAILED
    return service, session_id, binary


def test_session_recover_rejects_a_closed_session(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _create(service, binary)
    assert service.close_session(session_id).ok

    result = service.session_recover(session_id)

    assert not result.ok and result.error is not None
    assert "closed" in result.error.message


def test_session_recover_reopens_a_backend_that_never_opened(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _facade(tmp_path, static_factory=_static_factory())
    session_id = _create(service, binary)

    result = service.session_recover(session_id, backends=["ida"])

    assert result.ok and result.data is not None
    assert result.data["backends"] == [{"backend": "ida", "action": "reopened", "ok": True}]
    assert result.data["recovered"] == 1


def test_session_recover_with_nothing_attached_recovers_zero(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _create(service, binary)

    result = service.session_recover(session_id)

    assert result.ok and result.data is not None
    assert result.data["requested"] == []
    assert result.data["recovered"] == 0
    assert result.data["failed"] == 0


def test_recover_by_replacement_propagates_create_failure(tmp_path: Path) -> None:
    service, session_id, binary = _failed_session(tmp_path)
    binary.unlink()

    result = service.session_recover(session_id)

    assert not result.ok and result.error is not None


def test_recover_by_replacement_rejects_a_malformed_created_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _binary = _failed_session(tmp_path)
    monkeypatch.setattr(
        service,
        "create_session",
        lambda binary, target=None: _success({"session": "not-a-dict"}),
    )

    result = service.session_recover(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_protocol_error"


def test_recover_by_replacement_skips_backends_after_a_failure(tmp_path: Path) -> None:
    armed = {"raise": False}

    def flaky_static(session: Session, settings: Settings) -> StaticWorker:
        del session, settings
        if armed["raise"]:
            raise IdaWorkerError("ida_launch_failed", "no ida", retryable=False)
        return FakeStaticWorker()

    service, session_id, _binary = _failed_session(tmp_path, static_factory=flaky_static)
    armed["raise"] = True
    result = service.session_recover(session_id, backends=["ida", "x64dbg"])

    assert not result.ok and result.error is not None
    assert result.error.code == "recovery_failed"
    assert result.data is not None
    entries = result.data["backends"]
    assert isinstance(entries, list)
    assert entries[0]["action"] == "reopened" and not entries[0]["ok"]
    assert "error" in entries[0]
    assert entries[1]["action"] == "skipped" and not entries[1]["ok"]
    assert result.data["replaced"] is True


def test_open_static_reuses_a_live_backend(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _facade(tmp_path, static_factory=_static_factory())
    session_id = _create(service, binary)
    assert service.open_static(session_id).ok

    again = service.open_static(session_id)

    assert again.ok and again.data is not None
    assert again.data["reused"] is True


def test_open_backend_refuses_reuse_in_failed_state(tmp_path: Path) -> None:
    service, session_id, _binary = _failed_session(tmp_path, static_factory=_static_factory())
    assert not service.open_static(session_id).ok  # FAILED blocks a fresh open

    # Rebuild the terminal-state-with-live-runtime shape directly: a session
    # whose static worker is still registered while the session is FAILED.
    binary2 = tmp_path / "second.exe"
    _write_pe(binary2)
    second_id = _create(service, binary2)
    assert service.open_static(second_id).ok
    service.registry.transition(second_id, SessionState.FAILED)

    result = service.open_static(second_id)

    assert not result.ok and result.error is not None
    assert "cannot reuse ida in failed state" in result.error.message


def test_open_backend_fails_when_the_factory_returns_no_worker(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)

    def none_factory(session: Session, settings: Settings) -> StaticWorker:
        del session, settings
        return None  # type: ignore[return-value]

    service = AnalysisService(_settings(tmp_path), static_worker_factory=none_factory)
    session_id = _create(service, binary)

    result = service.open_static(session_id)

    assert not result.ok
    assert service.registry.get(session_id).state is SessionState.FAILED


def test_second_backend_open_failure_leaves_the_session_ready(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)

    def broken_dynamic(session: Session, settings: Settings) -> DynamicWorker:
        del session, settings
        raise XdbgRpcError("backend_unavailable", "no x64dbg here", retryable=False)

    service = AnalysisService(
        _settings(tmp_path),
        dynamic_worker_factory=broken_dynamic,
        static_worker_factory=_static_factory(),
    )
    session_id = _create(service, binary)
    assert service.open_static(session_id).ok

    result = service.open_dynamic(session_id)

    assert not result.ok
    assert service.registry.get(session_id).state is SessionState.READY


def test_open_backend_aborts_when_the_session_closes_mid_open(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    holder: dict[str, Any] = {}

    def closing_dynamic(session: Session, settings: Settings) -> DynamicWorker:
        del settings
        holder["service"].close_session(session.id)
        return FakeDynamicWorker()

    service = AnalysisService(
        _settings(tmp_path),
        dynamic_worker_factory=closing_dynamic,
        static_worker_factory=_static_factory(),
    )
    holder["service"] = service
    session_id = _create(service, binary)
    assert service.open_static(session_id).ok

    result = service.open_dynamic(session_id)

    assert not result.ok and result.error is not None
    assert "closed while x64dbg was opening" in result.error.message


# ---------------------------------------------------------------------------
# recovery helpers called directly
# ---------------------------------------------------------------------------


def test_recover_outcome_treats_a_bad_failed_count_as_zero() -> None:
    result = AnalysisService._recover_outcome({"failed": "not-a-number"}, session_id="session-1")
    assert result.ok


def test_recover_outcome_fails_the_envelope_when_backends_failed() -> None:
    result = AnalysisService._recover_outcome({"failed": 2}, session_id="session-1")
    assert not result.ok and result.error is not None
    assert result.error.code == "recovery_failed"
    assert result.error.retryable is True


def test_discard_dead_runtime_without_a_registration_is_a_no_op(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _create(service, binary)
    service._discard_dead_runtime(session_id, BackendKind.X64DBG)
    assert service.registry.get(session_id).state is SessionState.CREATED


def test_rebind_recovered_knowledge_skips_malformed_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = AnalysisService(_settings(tmp_path))
    recorded: list[tuple[str, str, dict[str, Any]]] = []

    def record(self: Any, *, session_id: str, kind: str, key: str, value: Any) -> Any:
        del self, session_id
        recorded.append((kind, key, value))
        return _success({})

    monkeypatch.setattr(type(service.services.artifacts), "record_knowledge", record)

    service._rebind_recovered_knowledge({"entries": "not-a-list"}, "replacement")
    assert recorded == []

    service._rebind_recovered_knowledge(
        {
            "entries": [
                42,
                {"kind": 1, "key": "k"},
                {"kind": "fact", "key": None},
                {"kind": "fact", "key": "good", "value": {"a": 1}},
                {"kind": "fact", "key": "bare", "value": "not-a-dict"},
            ]
        },
        "replacement",
    )
    assert recorded == [("fact", "good", {"a": 1}), ("fact", "bare", {})]


def test_session_work_dir_fails_closed_on_unsafe_ids(tmp_path: Path) -> None:
    service = AnalysisService(_settings(tmp_path))
    assert service._session_work_dir("jadx", "") is None
    assert service._session_work_dir("jadx", "a/b") is None


# ---------------------------------------------------------------------------
# dynamic_launch / dynamic_attach
# ---------------------------------------------------------------------------


def test_dynamic_launch_resumes_past_the_system_breakpoint(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _facade(tmp_path, dynamic_workers=[FakeDynamicWorker()])
    session_id = _create(service, binary)

    result = service.dynamic_launch(
        session_id,
        arguments="--go",
        working_directory=str(tmp_path),
        pass_system_breakpoint=True,
    )

    assert result.ok and result.data is not None
    assert result.data["pass_system_breakpoint"] is True
    assert "Resumed once" in result.data["note"]


def test_dynamic_attach_rejects_a_dead_pid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _facade(tmp_path, dynamic_workers=[FakeDynamicWorker()])
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr("headless_re_mcp.core.service.is_pid_alive", lambda pid: False)

    result = service.dynamic_attach(session_id, 4321)

    assert not result.ok and result.error is not None
    assert result.error.code == "not_found"


def test_dynamic_attach_annotates_child_window_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _facade(tmp_path, dynamic_workers=[FakeDynamicWorker()])
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr("headless_re_mcp.core.service.is_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.probe_child_window_candidates",
        lambda debuggee, list_windows_fn=None: [{"pid": 9100, "name": "child.exe"}],
    )

    result = service.dynamic_attach(session_id, 7100)

    assert result.ok and result.data is not None
    assert result.data["child_windows_hint"] == "windows_on_child_pids"
    assert result.data["suggested_child_pids"] == [9100]


def test_dynamic_attach_pauses_a_running_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class RunningWorker(FakeDynamicWorker):
        def wait_for_state(self, states: set[str], **kwargs: Any) -> Any:
            del states, kwargs
            self.current_state = _state("running")
            return dict(self.current_state)

    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _facade(tmp_path, dynamic_workers=[RunningWorker()])
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr("headless_re_mcp.core.service.is_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.probe_child_window_candidates",
        lambda debuggee, list_windows_fn=None: [],
    )

    result = service.dynamic_attach(session_id, 7100, pause_after_attach=True)

    assert result.ok and result.data is not None
    assert "state" in result.data


# ---------------------------------------------------------------------------
# dynamic_stealth_set
# ---------------------------------------------------------------------------


def _headless_with_plugin(tmp_path: Path, architecture: Architecture) -> Path:
    root = tmp_path / f"x64dbg-{architecture.value}"
    (root / "plugins").mkdir(parents=True)
    headless = root / "headless.exe"
    headless.write_bytes(b"MZ")
    layout = layout_for_headless(headless, architecture)
    assert layout is not None
    layout.plugin.write_bytes(b"plugin")
    layout.hook_library.write_bytes(b"hook")
    return headless


def _stealth_settings(
    tmp_path: Path,
    *,
    x64: bool = True,
    x86: bool = False,
) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=_headless_with_plugin(tmp_path, Architecture.X64) if x64 else None,
        x64dbg_headless_x86=_headless_with_plugin(tmp_path, Architecture.X86) if x86 else None,
        artifact_root=tmp_path / "artifacts",
        debug_event_background_drain=False,
        x64dbg_stealth_enabled=True,
        x64dbg_stealth_profile="vmp",
    )


def test_stealth_set_without_any_layout_reports_plugin_missing(tmp_path: Path) -> None:
    service = AnalysisService(_settings(tmp_path))

    result = service.dynamic_stealth_set("vmp")

    assert not result.ok and result.error is not None
    assert result.error.code == "plugin_missing"


def test_stealth_set_applies_a_profile_to_a_session_architecture(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = AnalysisService(_stealth_settings(tmp_path))
    session_id = _create(service, binary)

    result = service.dynamic_stealth_set("themida", session_id=session_id)

    assert result.ok and result.data is not None
    assert result.data["profile"] == "themida"
    assert result.data["applied"]


def test_stealth_set_rejects_armadillo_for_an_x64_session(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = AnalysisService(_stealth_settings(tmp_path))
    session_id = _create(service, binary)

    result = service.dynamic_stealth_set("armadillo", session_id=session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_stealth_set_armadillo_without_session_applies_to_nothing_on_x64(tmp_path: Path) -> None:
    service = AnalysisService(_stealth_settings(tmp_path, x64=True, x86=False))

    result = service.dynamic_stealth_set("armadillo")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_stealth_set_reports_plugin_missing_for_an_unconfigured_arch(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    # Only x86 is configured, but the PE session is x64, so its layout is absent.
    service = AnalysisService(_stealth_settings(tmp_path, x64=False, x86=True))
    session_id = _create(service, binary)

    result = service.dynamic_stealth_set("vmp", session_id=session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "plugin_missing"
