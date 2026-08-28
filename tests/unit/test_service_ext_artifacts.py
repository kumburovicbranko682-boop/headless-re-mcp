"""Artifact, timeline, knowledge, report, and bookkeeping arms of the service extras.

These are the non-backend methods of the extras mixin: repository-backed reads,
the fail-closed artifact reader (a path-traversal guard over raw byte reads),
the knowledge-value size guard, report rendering, and the session-bookkeeping
helpers that must degrade a store failure into a meta note rather than a raised
traceback. All are exercised against an in-memory repository.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import headless_re_mcp.core.service_ext as service_ext
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.application_services import (
    ApplicationServices,
    ArtifactApplicationService,
)
from headless_re_mcp.core.models import (
    Architecture,
    Result,
    RpcError,
    Session,
    SessionState,
    TargetKind,
)
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service_ext import (
    ExtAnalysisMixin,
    _breakpoint_binding_address,
    _register_capture,
    note_session_closed,
    note_session_created,
)
from headless_re_mcp.core.session import SessionRegistry

JsonObject = dict[str, Any]


class _Service(ExtAnalysisMixin):
    def __init__(self, artifact_root: Path, repository: Any = None) -> None:
        self.settings = Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
        )
        self.registry = SessionRegistry()
        self.repository = repository or InMemoryAnalysisRepository(artifact_root)
        self.services = cast(
            ApplicationServices,
            SimpleNamespace(
                artifacts=ArtifactApplicationService(facade=self, repository=self.repository)
            ),
        )

    def pe_session(self, session_id: str = "sid") -> str:
        binary = self.settings.artifact_root / "sample.exe"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"MZ sample")
        self.registry.adopt(
            Session(
                id=session_id,
                target=TargetKind.PE,
                binary=binary,
                sha256="c" * 64,
                architecture=Architecture.X64,
            )
        )
        return session_id


class _BoomRepository(InMemoryAnalysisRepository):
    """Repository whose one named method raises, to reach the failure arms."""

    def __init__(self, artifact_root: Path, boom_method: str) -> None:
        super().__init__(artifact_root)
        self._boom_method = boom_method

    def _maybe_boom(self, name: str) -> None:
        if name == self._boom_method:
            raise RuntimeError(f"{name} is unavailable")

    def list_artifacts(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("list_artifacts")
        return super().list_artifacts(*args, **kwargs)

    def describe_artifact(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("describe_artifact")
        return super().describe_artifact(*args, **kwargs)

    def gc_artifacts(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("gc_artifacts")
        return super().gc_artifacts(*args, **kwargs)

    def list_timeline(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("list_timeline")
        return super().list_timeline(*args, **kwargs)

    def list_unclean_sessions(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("list_unclean_sessions")
        return super().list_unclean_sessions(*args, **kwargs)

    def list_audit(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("list_audit")
        return super().list_audit(*args, **kwargs)

    def peek_session(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("peek_session")
        return super().peek_session(*args, **kwargs)

    def record_knowledge(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("record_knowledge")
        return super().record_knowledge(*args, **kwargs)

    def list_knowledge(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("list_knowledge")
        return super().list_knowledge(*args, **kwargs)

    def note_session_created(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("note_session_created")
        return super().note_session_created(*args, **kwargs)

    def note_session_closed(self, *args: Any, **kwargs: Any) -> Any:
        self._maybe_boom("note_session_closed")
        return super().note_session_closed(*args, **kwargs)


def _register(service: _Service, path: Path, session_id: str = "sid") -> JsonObject:
    return service.repository.register_artifact(
        session_id=session_id,
        kind="dump",
        path=path,
        sha256="0" * 64,
        source="test",
    )


# --- _breakpoint_binding_address (pure fail-closed parser) -------------------


def _workflow_with_binding(intent_id: str, address: Any) -> JsonObject:
    return {
        "workflow": {
            "state": {
                "breakpoints": {
                    "bindings": [{"intent_id": intent_id, "address": address}],
                }
            }
        }
    }


def test_binding_address_returns_the_single_bound_address() -> None:
    assert _breakpoint_binding_address(_workflow_with_binding("bp1", 0x4010), "bp1") == 0x4010


def test_binding_address_rejects_a_blank_intent_id() -> None:
    with pytest.raises(ValueError, match="must not be blank"):
        _breakpoint_binding_address(_workflow_with_binding("bp1", 0x4010), "  ")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"workflow": {}},
        {"workflow": {"state": {}}},
        {"workflow": {"state": {"breakpoints": {}}}},
    ],
)
def test_binding_address_rejects_missing_workflow_layers(payload: JsonObject) -> None:
    with pytest.raises(XdbgRpcError) as excinfo:
        _breakpoint_binding_address(payload, "bp1")
    assert excinfo.value.code == "invalid_state"


def test_binding_address_rejects_an_intent_without_exactly_one_binding() -> None:
    empty: JsonObject = {"workflow": {"state": {"breakpoints": {"bindings": []}}}}
    with pytest.raises(XdbgRpcError) as excinfo:
        _breakpoint_binding_address(empty, "bp1")
    assert excinfo.value.details["binding_count"] == 0


def test_binding_address_rejects_a_non_positive_bound_address() -> None:
    with pytest.raises(XdbgRpcError) as excinfo:
        _breakpoint_binding_address(_workflow_with_binding("bp1", 0), "bp1")
    assert excinfo.value.code == "invalid_state"
    assert excinfo.value.details["address"] == 0


# --- _register_capture missing-file arm --------------------------------------


def test_register_capture_returns_the_payload_when_the_file_is_absent(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    payload = {"note": "kept"}

    result = _register_capture(
        service,
        "sid",
        tmp_path / "never-written.bin",
        kind="dump",
        source="test",
        payload=payload,
    )

    assert result == payload
    assert "artifact_id" not in result


# --- session bookkeeping degrade-not-raise -----------------------------------


def test_note_session_created_records_a_store_failure_in_meta(tmp_path: Path) -> None:
    service = _Service(tmp_path, repository=_BoomRepository(tmp_path, "note_session_created"))
    result = Result[JsonObject](ok=True, data={"session": {"id": "sid"}})

    note_session_created(service, "sample.exe", result)

    assert result.ok  # the outcome is unchanged
    assert result.meta["persisted"] is False
    assert "RuntimeError" in result.meta["persist_error"]


def test_note_session_closed_records_a_store_failure_in_meta(tmp_path: Path) -> None:
    service = _Service(tmp_path, repository=_BoomRepository(tmp_path, "note_session_closed"))
    service.pe_session()
    result = Result[JsonObject](ok=True, data={"ok": True})

    note_session_closed(service, "sid", result)

    assert result.meta["persisted"] is False
    assert "RuntimeError" in result.meta["persist_error"]


def test_note_session_closed_treats_an_unknown_session_as_none(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    result = Result[JsonObject](ok=True, data={"ok": True})

    note_session_closed(service, "never-seen", result)

    assert result.ok
    assert service.repository.peek_session("never-seen") is None


# --- capabilities ------------------------------------------------------------


def test_capabilities_search_reports_the_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        service_ext,
        "list_capabilities",
        lambda settings, backend=None, status=None: [{"id": "static.functions"}],
    )
    result = _Service(tmp_path).capabilities_search()

    assert result.ok and result.data is not None
    assert result.data["count"] == 1
    assert result.data["capabilities"][0]["id"] == "static.functions"


def test_capabilities_describe_reports_a_missing_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_ext, "describe_capability", lambda cid, settings: None)
    result = _Service(tmp_path).capabilities_describe("no.such.cap")

    assert not result.ok and result.error is not None
    assert result.error.code == "not_found"
    assert result.error.details["id"] == "no.such.cap"


def test_capabilities_describe_reports_a_present_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        service_ext, "describe_capability", lambda cid, settings: {"id": cid, "status": "ready"}
    )
    result = _Service(tmp_path).capabilities_describe("static.functions")

    assert result.ok and result.data is not None
    assert result.data["capability"]["status"] == "ready"


# --- artifacts_list / describe / gc ------------------------------------------


def test_artifacts_list_pages_the_repository(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    blob = tmp_path / "a.bin"
    blob.write_bytes(b"x" * 8)
    recorded = _register(service, blob)

    result = service.artifacts_list("sid")

    assert result.ok and result.data is not None
    assert [item["id"] for item in result.data["artifacts"]] == [recorded["id"]]


def test_artifacts_list_maps_a_store_failure(tmp_path: Path) -> None:
    service = _Service(tmp_path, repository=_BoomRepository(tmp_path, "list_artifacts"))

    result = service.artifacts_list("sid")

    assert not result.ok and result.error is not None
    assert result.error.code == "internal_error"


def test_artifacts_describe_reports_a_missing_artifact(tmp_path: Path) -> None:
    result = _Service(tmp_path).artifacts_describe("nope")

    assert not result.ok and result.error is not None
    assert result.error.code == "not_found"


def test_artifacts_describe_maps_a_store_failure(tmp_path: Path) -> None:
    service = _Service(tmp_path, repository=_BoomRepository(tmp_path, "describe_artifact"))

    result = service.artifacts_describe("any")

    assert not result.ok and result.error is not None
    assert result.error.code == "internal_error"


@pytest.mark.parametrize("bad_id", [["x"], {"a": 1}, 5, True])
def test_store_bound_id_arguments_reject_a_non_string(tmp_path: Path, bad_id: Any) -> None:
    """An unbindable id must not read as a store outage or silently match nothing.

    artifact_id and the optional session_id filter never meet
    SessionRegistry.get's refusal (a filter needn't name a live session), so a
    list/dict reached sqlite parameter binding and the InterfaceError was filed
    as storage_unavailable -- a store outage the caller might retry against,
    when their argument was wrong -- while an int silently matched nothing
    because ids are TEXT columns. All must read as invalid_request.
    """
    service = _Service(tmp_path)

    for result in (
        service.artifacts_list(cast(Any, bad_id)),
        service.audit_list(cast(Any, bad_id)),
        service.artifacts_describe(cast(Any, bad_id)),
        service.artifacts_read(cast(Any, bad_id)),
    ):
        assert not result.ok and result.error is not None
        assert result.error.code == "invalid_request"


def test_listings_keep_a_none_session_filter_as_all_sessions(tmp_path: Path) -> None:
    """The type refusal must not disturb the documented unfiltered listing."""
    service = _Service(tmp_path)

    assert service.artifacts_list(None).ok
    assert service.audit_list(None).ok


def test_artifacts_gc_reports_the_collection_summary(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    blob = tmp_path / "old.bin"
    blob.write_bytes(b"x" * 16)
    _register(service, blob)
    newest = tmp_path / "new.bin"
    newest.write_bytes(b"x" * 16)
    _register(service, newest)

    result = service.artifacts_gc(max_total_bytes=16)

    assert result.ok and result.data is not None
    assert result.data["count"] >= 1


def test_artifacts_gc_maps_a_store_failure(tmp_path: Path) -> None:
    service = _Service(tmp_path, repository=_BoomRepository(tmp_path, "gc_artifacts"))

    result = service.artifacts_gc()

    assert not result.ok and result.error is not None
    assert result.error.code == "internal_error"


# --- artifacts_read (path-traversal guard over raw reads) --------------------


def test_artifacts_read_returns_a_paginated_hex_window(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    blob = tmp_path / "dump.bin"
    blob.write_bytes(bytes(range(16)))
    recorded = _register(service, blob)

    result = service.artifacts_read(str(recorded["id"]), offset=4, limit=4)

    assert result.ok and result.data is not None
    assert result.data["size"] == 16
    assert result.data["data"] == "04050607"
    assert result.data["offset"] == 4


def test_artifacts_read_reports_a_missing_artifact_id(tmp_path: Path) -> None:
    result = _Service(tmp_path).artifacts_read("missing")

    assert not result.ok and result.error is not None
    assert result.error.code == "not_found"


def test_artifacts_read_refuses_a_path_outside_the_artifact_root(tmp_path: Path) -> None:
    """The stored path is the trust boundary; a row pointing outside must fail closed."""
    outside = tmp_path.parent / f"escape-{tmp_path.name}.bin"
    outside.write_bytes(b"secret")
    try:
        service = _Service(tmp_path)
        recorded = _register(service, outside)

        result = service.artifacts_read(str(recorded["id"]))

        assert not result.ok and result.error is not None
        assert result.error.code == "permission_denied"
    finally:
        outside.unlink(missing_ok=True)


def test_artifacts_read_reports_a_row_whose_file_is_gone(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    blob = tmp_path / "dump.bin"
    blob.write_bytes(b"x" * 8)
    recorded = _register(service, blob)
    blob.unlink()

    result = service.artifacts_read(str(recorded["id"]))

    assert not result.ok and result.error is not None
    assert result.error.code == "not_found"


# --- timeline / unclean / peek / audit ---------------------------------------


def test_timeline_list_reports_recorded_events(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.repository.append_timeline("sid", "session.created", "created")

    result = service.timeline_list("sid")

    assert result.ok and result.data is not None
    assert result.data["total"] == 1


def test_timeline_list_maps_a_store_failure(tmp_path: Path) -> None:
    service = _Service(tmp_path, repository=_BoomRepository(tmp_path, "list_timeline"))

    result = service.timeline_list("sid")

    assert not result.ok and result.error is not None
    assert result.error.code == "internal_error"


def test_sessions_unclean_reports_the_worklist_with_paging(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.repository.note_session_created(
        "sample.exe", Result[JsonObject](ok=True, data={"session": {"id": "sid"}})
    )

    result = service.sessions_unclean(offset=0, limit=100)

    assert result.ok and result.data is not None
    assert result.data["total"] == 1
    assert result.data["has_more"] is False


def test_sessions_unclean_maps_a_store_failure(tmp_path: Path) -> None:
    service = _Service(tmp_path, repository=_BoomRepository(tmp_path, "list_unclean_sessions"))

    result = service.sessions_unclean()

    assert not result.ok and result.error is not None
    assert result.error.code == "internal_error"


def test_peek_session_record_reports_a_live_session(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.pe_session()

    result = service.peek_session_record("sid")

    assert result.ok and result.data is not None
    assert result.data["live"] is True
    assert result.data["state"] == "created"


def test_peek_session_record_falls_back_to_the_stored_row(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.repository.note_session_created(
        "sample.exe", Result[JsonObject](ok=True, data={"session": {"id": "stored"}})
    )

    result = service.peek_session_record("stored")

    assert result.ok and result.data is not None
    assert result.data["live"] is False
    assert result.data["id"] == "stored"


def test_peek_session_record_reports_an_unknown_session(tmp_path: Path) -> None:
    result = _Service(tmp_path).peek_session_record("never-seen")

    assert not result.ok and result.error is not None
    assert result.error.code == "session_not_found"


def test_audit_list_reports_recorded_entries(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.repository.append_audit(
        session_id="sid", action="session.create", params_summary={}, ok=True, result_summary={}
    )

    result = service.audit_list("sid")

    assert result.ok and result.data is not None
    assert result.data["total"] == 1


def test_audit_list_maps_a_store_failure(tmp_path: Path) -> None:
    service = _Service(tmp_path, repository=_BoomRepository(tmp_path, "list_audit"))

    result = service.audit_list()

    assert not result.ok and result.error is not None
    assert result.error.code == "internal_error"


# --- knowledge ----------------------------------------------------------------


def test_knowledge_record_stores_a_finding(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.pe_session()

    result = service.knowledge_record("sid", "note", "decrypt", {"addr": 0x401000})

    assert result.ok and result.data is not None
    assert result.data["kind"] == "note"


@pytest.mark.parametrize(
    ("kind", "key"),
    [("", "k"), ("k" * 65, "k"), ("note", ""), ("note", "k" * 257)],
)
def test_knowledge_record_rejects_out_of_bound_kind_or_key(
    tmp_path: Path, kind: str, key: str
) -> None:
    service = _Service(tmp_path)
    service.pe_session()

    result = service.knowledge_record("sid", kind, key, {"v": 1})

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


def test_knowledge_record_rejects_an_oversized_value(tmp_path: Path) -> None:
    """A value cut by the store would read back as a broken JSON fragment.

    The size guard runs before the session lookup, so an oversized value for an
    absent session is refused as invalid_request rather than session_not_found:
    that ordering is what pins the service-level guard rather than the store's.
    """
    service = _Service(tmp_path)

    result = service.knowledge_record("never-seen", "note", "big", {"blob": "x" * 9000})

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
    assert "over the" in result.error.message


def test_knowledge_record_refuses_a_terminal_session(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    service.registry.transition("sid", SessionState.FAILED)

    result = service.knowledge_record("sid", "note", "k", {"v": 1})

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


def test_knowledge_query_lists_recorded_findings(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    service.knowledge_record("sid", "note", "k", {"v": 1})

    result = service.knowledge_query("sid", kind="note")

    assert result.ok and result.data is not None
    assert result.data["total"] == 1


def test_knowledge_query_maps_an_unknown_session(tmp_path: Path) -> None:
    result = _Service(tmp_path).knowledge_query("never-seen")

    assert not result.ok and result.error is not None
    assert result.error.code == "session_not_found"


# --- report_generate ----------------------------------------------------------


def test_report_generate_renders_and_registers_a_markdown_artifact(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    service.knowledge_record("sid", "note", "k", {"v": 1})

    result = service.report_generate("sid", title="Sample")

    assert result.ok and result.data is not None
    assert result.data["truncated"] is False
    assert "artifact_id" in result.data
    saved = Path(str(result.data["path"]))
    assert saved.is_file()
    assert saved.read_text(encoding="utf-8")


@pytest.mark.parametrize("audit_limit", [0, 201, True])
def test_report_generate_rejects_an_out_of_range_audit_limit(
    tmp_path: Path, audit_limit: Any
) -> None:
    service = _Service(tmp_path)
    service.pe_session()

    result = service.report_generate("sid", audit_limit=audit_limit)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


def test_report_generate_refuses_a_terminal_session(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    service.registry.transition("sid", SessionState.FAILED)

    result = service.report_generate("sid")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


def test_report_generate_truncates_the_inline_markdown_but_saves_it_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    huge = "# report\n" + ("x" * (service_ext._REPORT_INLINE_MAX_BYTES + 100))
    monkeypatch.setattr(service_ext, "render_markdown_report", lambda **kwargs: huge)

    result = service.report_generate("sid")

    assert result.ok and result.data is not None
    assert result.data["truncated"] is True
    assert result.data["hint"] == "full_markdown_in_artifact"
    saved = Path(str(result.data["path"]))
    assert saved.stat().st_size == len(huge.encode("utf-8"))


# --- tool_metrics -------------------------------------------------------------


def test_tool_metrics_reports_the_recent_ring(tmp_path: Path) -> None:
    result = _Service(tmp_path).tool_metrics(limit=5)

    assert result.ok and result.data is not None
    assert "recent" in result.data


@pytest.mark.parametrize("limit", [-1, 201, True])
def test_tool_metrics_rejects_an_out_of_range_limit(tmp_path: Path, limit: Any) -> None:
    result = _Service(tmp_path).tool_metrics(limit=limit)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


# --- batch_analyze ------------------------------------------------------------


def test_batch_analyze_reports_a_per_binary_outcome(tmp_path: Path) -> None:
    service = _Service(tmp_path)

    def create_session(path: str) -> Result[JsonObject]:
        return Result[JsonObject](ok=True, data={"session": {"id": f"sid-{Path(path).name}"}})

    def open_static(session_id: str) -> Result[JsonObject]:
        return Result[JsonObject](ok=True, data={})

    service.create_session = create_session
    service.open_static = open_static

    result = service.batch_analyze(["one.exe", "two.exe"], max_workers=1)

    assert result.ok and result.data is not None
    assert result.data["succeeded"] == 2
    assert result.data["count"] == 2


def test_batch_analyze_records_a_failed_create_without_aborting(tmp_path: Path) -> None:
    service = _Service(tmp_path)

    def create_session(path: str) -> Result[JsonObject]:
        if path == "bad.exe":
            return Result[JsonObject](
                ok=False, error=RpcError(code="invalid_pe", message="not a PE")
            )
        return Result[JsonObject](ok=True, data={"session": {"id": "sid-ok"}})

    service.create_session = create_session
    service.open_static = lambda session_id: Result[JsonObject](ok=True, data={})

    result = service.batch_analyze(["good.exe", "bad.exe"], max_workers=1)

    assert result.ok and result.data is not None
    assert result.data["succeeded"] == 1
    assert result.data["failed"] == 1


def test_batch_analyze_rejects_an_empty_list(tmp_path: Path) -> None:
    result = _Service(tmp_path).batch_analyze([])

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


@pytest.mark.parametrize("max_workers", [0, 9, True])
def test_batch_analyze_rejects_an_out_of_range_worker_count(
    tmp_path: Path, max_workers: Any
) -> None:
    result = _Service(tmp_path).batch_analyze(["one.exe"], max_workers=max_workers)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
