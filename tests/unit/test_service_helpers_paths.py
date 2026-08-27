"""Unit coverage for the module-level helpers in ``core/service.py``.

These are the small, pure functions the facade leans on: the x64dbg worker
factory's platform/configuration guards, backend-name recovery, the workflow
timeout and failure mappers, session JSON serialization, and the atomic DIE /
Exeinfo PE artifact writers with their fail-closed guards.
"""

from __future__ import annotations

import os
import struct
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.addressing import AddressSyncError
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT
from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.core.service import (
    AnalysisService,
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
