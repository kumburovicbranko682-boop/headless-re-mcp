"""Module-level helpers and worker factory of the core.service module.

The ``_create_xdbg_worker`` factory (platform / configuration guards), the
``_workflow_timeout`` / ``_workflow_failure`` classifiers, and the DIE / Exeinfo
PE artifact writers (unsafe-id, size-limit, and temp-file cleanup arms) are pure
functions with no direct coverage. They are exercised here in isolation.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service as service_mod
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.addressing import AddressSyncError
from headless_re_mcp.core.session import InvalidStateTransition
from headless_re_mcp.detection.die import DieScanResult
from headless_re_mcp.detection.exeinfope import ExeinfopeScanResult
from headless_re_mcp.detection.models import DetectionSource, ScanMode
from tests.unit.test_dynamic_service import (
    _create,
    _service,
    _settings,
    _write_minimal_pe,
)


def _session(tmp_path: Path) -> Any:
    service = _service(tmp_path, _fake_dynamic())
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    session_id = _create(service, binary)
    return service.registry.get(session_id)


def _fake_dynamic() -> Any:
    from tests.unit.test_dynamic_service import FakeDynamicWorker

    return FakeDynamicWorker()


# --- _create_xdbg_worker --------------------------------------------------------


def test_create_xdbg_worker_is_windows_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session(tmp_path)
    monkeypatch.setattr(service_mod, "os", SimpleNamespace(name="posix"))

    with pytest.raises(XdbgRpcError) as caught:
        service_mod._create_xdbg_worker(session, _settings(tmp_path))

    assert caught.value.code == "unsupported_on_platform"


def test_create_xdbg_worker_requires_a_configured_headless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session(tmp_path)
    monkeypatch.setattr(service_mod, "os", SimpleNamespace(name="nt"))

    # x64 fixture with no configured x64 headless executable.
    with pytest.raises(XdbgRpcError) as caught:
        service_mod._create_xdbg_worker(session, _settings(tmp_path))

    assert caught.value.code == "backend_unavailable"
    assert "HEADLESS_RE_X64DBG_HEADLESS_X64" in str(caught.value.details)


def test_create_xdbg_worker_builds_the_client_when_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session(tmp_path)
    monkeypatch.setattr(service_mod, "os", SimpleNamespace(name="nt"))
    sentinel = object()
    captured: dict[str, Any] = {}

    def fake_client(executable: Path, architecture: Any, *, hidden_desktop: Any) -> Any:
        captured["executable"] = executable
        captured["architecture"] = architecture
        return sentinel

    monkeypatch.setattr(service_mod, "XdbgClient", fake_client)
    headless = tmp_path / "x64_headless.exe"
    settings = replace(_settings(tmp_path), x64dbg_headless_x64=headless)

    worker = service_mod._create_xdbg_worker(session, settings)

    assert worker is sentinel
    assert captured["executable"] == headless


# --- _workflow_timeout / _workflow_failure --------------------------------------


def test_workflow_timeout_rejects_a_non_positive_value() -> None:
    result = service_mod._workflow_timeout(-1.0)

    assert isinstance(result, ValueError)


def test_workflow_timeout_accepts_a_valid_value() -> None:
    assert service_mod._workflow_timeout(5.0) == 5.0


def test_workflow_failure_classifies_exception_types() -> None:
    code, details, retryable = service_mod._workflow_failure(
        AddressSyncError("module_not_found", "missing", name="x")
    )
    assert code == "module_not_found" and retryable is False

    code, _, retryable = service_mod._workflow_failure(TimeoutError())
    assert code == "workflow_timeout" and retryable is True

    code, _, retryable = service_mod._workflow_failure(InvalidStateTransition("bad"))
    assert code == "invalid_request" and retryable is False

    code, _, _ = service_mod._workflow_failure(ValueError("bad"))
    assert code == "invalid_request"

    code, details, _ = service_mod._workflow_failure(RuntimeError("boom"))
    assert code == "workflow_execution_failed"
    assert details["exception"] == "RuntimeError"


# --- resolve_runtime_address guard ----------------------------------------------


def test_resolve_runtime_address_rejects_a_negative_address(tmp_path: Path) -> None:
    service = _service(tmp_path, _fake_dynamic())

    result = service.resolve_runtime_address("nonexistent", -1)

    assert not result.ok
    assert result.error is not None
    assert "non-negative integer" in result.error.message


# --- DIE / Exeinfo PE artifact writers ------------------------------------------


def _die_result(tmp_path: Path, raw_json: str = "{}") -> DieScanResult:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x90\x00")
    return DieScanResult(
        path=binary,
        size=binary.stat().st_size,
        mode=ScanMode.NORMAL,
        findings=(),
        source=DetectionSource(name="diec", status="completed"),
        raw={},
        raw_json=raw_json,
        stdout="",
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )


def _exeinfope_result(tmp_path: Path, raw_log: str = "log") -> ExeinfopeScanResult:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x90\x00")
    log = tmp_path / "scan.log"
    log.write_text("log\n", encoding="utf-8")
    return ExeinfopeScanResult(
        path=binary,
        size=binary.stat().st_size,
        mode=ScanMode.NORMAL,
        findings=(),
        source=DetectionSource(name="exeinfope", status="completed"),
        raw_log=raw_log,
        log_path=log,
        stdout="",
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )


def test_die_artifact_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="invalid session id"):
        service_mod._write_die_artifact(tmp_path, "..", _die_result(tmp_path))


def test_die_artifact_rejects_an_oversized_payload(tmp_path: Path) -> None:
    huge = "x" * (8 * 1024 * 1024 + 128)
    with pytest.raises(OSError, match="8 MiB"):
        service_mod._write_die_artifact(tmp_path, "sess", _die_result(tmp_path, huge))


def test_die_artifact_cleans_up_a_temp_file_on_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(src: Any, dst: Any) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(service_mod.os, "replace", boom)

    with pytest.raises(OSError, match="replace failed"):
        service_mod._write_die_artifact(tmp_path, "sess", _die_result(tmp_path))

    # The aborted write left no stray temp file behind.
    leftovers = list((tmp_path / "detection" / "sess").glob(".die-*.tmp"))
    assert leftovers == []


def test_die_artifact_written_for_a_safe_session(tmp_path: Path) -> None:
    path = service_mod._write_die_artifact(tmp_path, "sess", _die_result(tmp_path))

    assert Path(path).is_file()


def test_exeinfope_log_path_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="invalid session id"):
        service_mod._exeinfope_log_path(tmp_path, "..")


def test_exeinfope_artifact_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="invalid session id"):
        service_mod._write_exeinfope_artifact(tmp_path, "..", _exeinfope_result(tmp_path))


def test_exeinfope_artifact_rejects_an_oversized_payload(tmp_path: Path) -> None:
    huge = "x" * (8 * 1024 * 1024 + 128)
    with pytest.raises(OSError, match="8 MiB"):
        service_mod._write_exeinfope_artifact(tmp_path, "sess", _exeinfope_result(tmp_path, huge))


def test_exeinfope_artifact_cleans_up_a_temp_file_on_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(src: Any, dst: Any) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(service_mod.os, "replace", boom)

    with pytest.raises(OSError, match="replace failed"):
        service_mod._write_exeinfope_artifact(tmp_path, "sess", _exeinfope_result(tmp_path))

    leftovers = list((tmp_path / "detection" / "sess").glob(".exeinfope-*.tmp"))
    assert leftovers == []
