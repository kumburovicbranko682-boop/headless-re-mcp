"""Coverage for the module-level helpers at the bottom of core/service.py.

These are pure functions the service leans on: the x64dbg worker factory's
platform/configuration guards, the backend-name normaliser, the workflow
status/failure classifiers, and the artifact writers with their fail-closed
session-segment checks and bounded-size and temp-cleanup arms. They are
exercised directly rather than through a live backend.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service as service
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.addressing import AddressSyncError
from headless_re_mcp.core.models import Architecture, BackendKind
from headless_re_mcp.core.session import InvalidStateTransition
from headless_re_mcp.detection.models import ScanMode
from headless_re_mcp.workflows.navigation import NavigationStatus
from headless_re_mcp.workflows.runtime import WorkflowRunStatus

# --------------------------------------------------------------------------- #
# _create_xdbg_worker
# --------------------------------------------------------------------------- #


class _FakeSession:
    def __init__(self, architecture: Architecture = Architecture.X64) -> None:
        self._architecture = architecture
        self.pe_required = False

    def require_pe(self) -> str:
        self.pe_required = True
        return "C:\\sample.exe"

    def require_architecture(self) -> Architecture:
        return self._architecture


def _settings(**over: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "x64dbg_headless_x64": None,
        "x64dbg_headless_x86": None,
        "hidden_desktop": False,
    }
    base.update(over)
    return SimpleNamespace(**base)


def test_create_xdbg_worker_refuses_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service.os, "name", "posix")
    session = _FakeSession()
    with pytest.raises(XdbgRpcError) as exc:
        service._create_xdbg_worker(session, _settings())  # type: ignore[arg-type]
    assert exc.value.code == "unsupported_on_platform"
    assert session.pe_required, "the PE must be required before the platform guard"


@pytest.mark.parametrize(
    ("architecture", "variable"),
    [
        (Architecture.X86, "HEADLESS_RE_X64DBG_HEADLESS_X86"),
        (Architecture.X64, "HEADLESS_RE_X64DBG_HEADLESS_X64"),
    ],
)
def test_create_xdbg_worker_reports_a_missing_executable(
    monkeypatch: pytest.MonkeyPatch, architecture: Architecture, variable: str
) -> None:
    monkeypatch.setattr(service.os, "name", "nt")
    with pytest.raises(XdbgRpcError) as exc:
        service._create_xdbg_worker(_FakeSession(architecture), _settings())  # type: ignore[arg-type]
    assert exc.value.code == "backend_unavailable"
    assert exc.value.details["environment_variable"] == variable


def test_create_xdbg_worker_builds_the_client_for_a_configured_arch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(service.os, "name", "nt")
    exe = tmp_path / "x64dbg.exe"
    built: list[tuple[Any, Architecture, bool]] = []

    def fake_client(executable: Any, arch: Architecture, *, hidden_desktop: bool) -> str:
        built.append((executable, arch, hidden_desktop))
        return "XDBG"

    monkeypatch.setattr(service, "XdbgClient", fake_client)

    worker = service._create_xdbg_worker(
        _FakeSession(Architecture.X64),  # type: ignore[arg-type]
        _settings(x64dbg_headless_x64=exe, hidden_desktop=True),
    )

    assert worker == "XDBG"
    assert built == [(exe, Architecture.X64, True)]


# --------------------------------------------------------------------------- #
# _recover_backend_kinds
# --------------------------------------------------------------------------- #


def test_recover_backend_kinds_normalises_aliases_and_dedupes() -> None:
    kinds = service._recover_backend_kinds(["IDA", "static", "x64dbg", "dynamic"])
    # ida/static collapse to one IDA; x64dbg/dynamic collapse to one X64DBG.
    assert kinds == (BackendKind.IDA, BackendKind.X64DBG)


def test_recover_backend_kinds_rejects_an_unknown_name() -> None:
    with pytest.raises(ValueError, match="backends entries"):
        service._recover_backend_kinds(["frida"])


# --------------------------------------------------------------------------- #
# _workflow_status_for_state
# --------------------------------------------------------------------------- #


def test_workflow_status_is_active_while_navigation_waits() -> None:
    state = SimpleNamespace(navigation=SimpleNamespace(status=NavigationStatus.WAITING))
    assert service._workflow_status_for_state(state) is WorkflowRunStatus.ACTIVE


def test_workflow_status_is_idle_without_a_waiting_navigation() -> None:
    assert service._workflow_status_for_state(SimpleNamespace(navigation=None)) is (
        WorkflowRunStatus.IDLE
    )
    settled = SimpleNamespace(navigation=SimpleNamespace(status=NavigationStatus.MATCHED))
    assert service._workflow_status_for_state(settled) is WorkflowRunStatus.IDLE


# --------------------------------------------------------------------------- #
# _workflow_failure
# --------------------------------------------------------------------------- #


def test_workflow_failure_classifies_each_exception_family() -> None:
    sync = AddressSyncError("addr_desync", "modules drifted", k=1)
    assert service._workflow_failure(sync) == ("addr_desync", {"k": 1}, False)

    rpc = XdbgRpcError("worker_exited", "gone", details={"pid": 9}, retryable=True)
    assert service._workflow_failure(rpc) == ("worker_exited", {"pid": 9}, True)

    assert service._workflow_failure(TimeoutError("slow")) == ("workflow_timeout", {}, True)

    assert service._workflow_failure(InvalidStateTransition("bad")) == (
        "invalid_request",
        {},
        False,
    )
    assert service._workflow_failure(ValueError("nope")) == ("invalid_request", {}, False)

    code, details, retryable = service._workflow_failure(RuntimeError("boom"))
    assert code == "workflow_execution_failed"
    assert details == {"exception": "RuntimeError"}
    assert retryable is False


# --------------------------------------------------------------------------- #
# _session_json
# --------------------------------------------------------------------------- #


def test_session_json_returns_the_serialised_mapping() -> None:
    session = SimpleNamespace(model_dump=lambda *, mode: {"id": "abc", "state": "ready"})
    assert service._session_json(session) == {"id": "abc", "state": "ready"}


def test_session_json_rejects_a_non_object_serialisation() -> None:
    session = SimpleNamespace(model_dump=lambda *, mode: ["not", "a", "dict"])
    with pytest.raises(TypeError, match="did not serialize to an object"):
        service._session_json(session)


# --------------------------------------------------------------------------- #
# _session_owns_artifact_path OSError arm
# --------------------------------------------------------------------------- #


def test_ownership_skips_a_root_that_cannot_be_resolved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A root whose resolve() fails is skipped, not fatal; a later real root still matches."""
    root = tmp_path / "artifacts"
    sid = "a" * 32
    owned = root / "unpack" / sid
    owned.mkdir(parents=True)
    target = owned / "dumped.bin"
    target.write_bytes(b"MZ")

    class _UnresolvableRoot:
        def resolve(self) -> Path:
            raise OSError("stale mount")

    monkeypatch.setattr(
        service,
        "_session_artifact_roots",
        lambda artifact_root, session_id: (_UnresolvableRoot(), owned),
    )

    assert service._session_owns_artifact_path(root, sid, target) is True


# --------------------------------------------------------------------------- #
# artifact writers: DIE
# --------------------------------------------------------------------------- #


def _die_result(raw_json: str = "{}") -> SimpleNamespace:
    return SimpleNamespace(
        path=Path("C:\\sample.exe"),
        size=1024,
        mode=ScanMode.NORMAL,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        returncode=0,
        stderr="",
        raw_json=raw_json,
    )


def test_write_die_artifact_refuses_an_unsafe_session_segment(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="invalid session id"):
        service._write_die_artifact(tmp_path, "..", _die_result())


def test_write_die_artifact_persists_and_returns_the_path(tmp_path: Path) -> None:
    written = service._write_die_artifact(tmp_path, "b" * 32, _die_result('{"tool":"diec"}'))
    path = Path(written)
    assert path.is_file()
    assert path.parent.name == "b" * 32
    assert "diec" in path.read_text(encoding="utf-8")


def test_write_die_artifact_refuses_an_oversized_payload(tmp_path: Path) -> None:
    huge = _die_result("x" * (8 * 1024 * 1024 + 10))
    with pytest.raises(OSError, match="8 MiB"):
        service._write_die_artifact(tmp_path, "c" * 32, huge)


def test_write_die_artifact_cleans_up_a_temp_left_by_a_failed_rename(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A rename that fails mid-write must not leave a stray temp file behind."""

    def refuse_replace(src: Any, dst: Any) -> None:
        raise OSError("cross-device rename")

    monkeypatch.setattr(service.os, "replace", refuse_replace)
    sid = "d" * 32
    with pytest.raises(OSError, match="cross-device"):
        service._write_die_artifact(tmp_path, sid, _die_result())

    directory = (tmp_path / "detection" / sid).resolve()
    assert list(directory.glob(".die-*.tmp")) == [], "the temp file must be unlinked"


# --------------------------------------------------------------------------- #
# artifact writers: Exeinfo PE
# --------------------------------------------------------------------------- #


def _exeinfo_result(raw_log: str = "log") -> SimpleNamespace:
    return SimpleNamespace(
        path=Path("C:\\sample.exe"),
        size=2048,
        mode=ScanMode.NORMAL,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        returncode=0,
        stderr="",
        log_path=Path("C:\\logs\\exeinfope.log"),
        raw_log=raw_log,
        analyzer_windows=("Exeinfo PE",),
    )


def test_exeinfope_log_path_refuses_an_unsafe_segment(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="invalid session id"):
        service._exeinfope_log_path(tmp_path, "..")


def test_exeinfope_log_path_returns_a_path_in_the_detection_tree(tmp_path: Path) -> None:
    path = service._exeinfope_log_path(tmp_path, "e" * 32)
    assert path.parent.name == "e" * 32
    assert path.parent.is_dir()
    assert path.name.startswith("exeinfope-")


def test_write_exeinfope_artifact_refuses_an_unsafe_segment(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="invalid session id"):
        service._write_exeinfope_artifact(tmp_path, "..", _exeinfo_result())


def test_write_exeinfope_artifact_persists_the_bounded_log(tmp_path: Path) -> None:
    written = service._write_exeinfope_artifact(tmp_path, "f" * 32, _exeinfo_result())
    path = Path(written)
    assert path.is_file()
    assert "exeinfope" in path.read_text(encoding="utf-8")


def test_write_exeinfope_artifact_refuses_an_oversized_payload(tmp_path: Path) -> None:
    huge = _exeinfo_result("y" * (8 * 1024 * 1024 + 10))
    with pytest.raises(OSError, match="8 MiB"):
        service._write_exeinfope_artifact(tmp_path, "0" * 32, huge)


def test_write_exeinfope_artifact_cleans_up_a_temp_left_by_a_failed_rename(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def refuse_replace(src: Any, dst: Any) -> None:
        raise OSError("cross-device rename")

    monkeypatch.setattr(service.os, "replace", refuse_replace)
    sid = "9" * 32
    with pytest.raises(OSError, match="cross-device"):
        service._write_exeinfope_artifact(tmp_path, sid, _exeinfo_result())

    directory = (tmp_path / "detection" / sid).resolve()
    assert list(directory.glob(".exeinfope-*.tmp")) == []
