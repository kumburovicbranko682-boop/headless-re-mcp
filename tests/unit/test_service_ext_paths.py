"""Coverage for the optional-backend delegating methods on ``ExtAnalysisMixin``.

The r2 / ghidra / frida / windbg tools are absent in unit environments, so every
one of these wrappers is exercised through the arm that matters most for a tool
boundary: a clean ``Result`` failure instead of an escaping exception. Live
sessions reach the client call (which fails ``capability_unavailable`` /
``unsupported_on_platform``); closed sessions and missing debuggees trip the
guards before it.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    FakeStaticWorker,
    _create,
    _service,
    _settings,
    _write_minimal_pe,
)

JsonResult = Result[dict[str, object]]


def _plain_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    return service, _create(service, binary)


def _repo_service(tmp_path: Path) -> tuple[AnalysisService, InMemoryAnalysisRepository, Path]:
    root = tmp_path / "artifacts"
    repository = InMemoryAnalysisRepository(root)
    service = AnalysisService(_settings(tmp_path), repository=repository)
    return service, repository, root


def _debuggee_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.dynamic_launch(session_id).ok
    state = service.dynamic_state(session_id)
    assert state.ok and state.data is not None
    assert state.data.get("debuggee_pid")
    return service, session_id


def _assert_failed(result: JsonResult) -> None:
    assert not result.ok and result.error is not None


# ---------------------------------------------------------------------------
# radare2
# ---------------------------------------------------------------------------


def test_r2_methods_fail_closed_without_the_tool(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _assert_failed(service.r2_open(session_id))
    _assert_failed(service.r2_info(session_id))
    _assert_failed(service.r2_functions(session_id))
    _assert_failed(service.r2_strings(session_id))
    _assert_failed(service.r2_imports(session_id))
    _assert_failed(service.r2_exports(session_id))
    _assert_failed(service.r2_disasm(session_id, 0x140001000))
    _assert_failed(service.r2_xrefs(session_id, 0x140001000))


def test_r2_methods_reject_a_closed_session(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)
    assert service.close_session(session_id).ok

    for result in (
        service.r2_open(session_id),
        service.r2_disasm(session_id, 0x140001000),
        service.r2_xrefs(session_id, 0x140001000),
    ):
        _assert_failed(result)
        assert result.error is not None
        assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# ghidra
# ---------------------------------------------------------------------------


def test_ghidra_methods_fail_closed_without_the_tool(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _assert_failed(service.ghidra_analyze(session_id))
    _assert_failed(service.ghidra_functions(session_id))
    _assert_failed(service.ghidra_symbols(session_id))
    _assert_failed(service.ghidra_xrefs(session_id, 0x140001000))
    _assert_failed(service.ghidra_decompile(session_id, 0x140001000))


def test_ghidra_analyze_rejects_a_closed_session(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)
    assert service.close_session(session_id).ok

    result = service.ghidra_analyze(session_id)

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# frida
# ---------------------------------------------------------------------------


def test_frida_methods_reach_the_client_with_a_live_debuggee(tmp_path: Path) -> None:
    service, session_id = _debuggee_session(tmp_path)

    _assert_failed(service.frida_attach(session_id))
    _assert_failed(service.frida_modules(session_id))
    _assert_failed(service.frida_exports(session_id, "kernel32.dll"))
    _assert_failed(service.frida_memory_read(session_id, 0x140001000, 16))
    _assert_failed(service.frida_hook_template(session_id))


def test_frida_attach_rejects_a_session_without_a_debuggee(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    result = service.frida_attach(session_id)

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "invalid_state"


# ---------------------------------------------------------------------------
# windbg
# ---------------------------------------------------------------------------


def test_windbg_dump_methods_fail_closed(tmp_path: Path) -> None:
    service, _session_id = _plain_session(tmp_path)
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"MDMP")

    _assert_failed(service.windbg_open_dump(str(dump)))
    _assert_failed(service.windbg_threads(str(dump)))
    _assert_failed(service.windbg_modules(str(dump)))
    _assert_failed(service.windbg_disasm(str(dump), 0x1000))


def test_windbg_live_methods_reach_the_client_with_a_debuggee(tmp_path: Path) -> None:
    service, session_id = _debuggee_session(tmp_path)

    _assert_failed(service.windbg_attach(session_id))
    _assert_failed(service.windbg_live_threads(session_id))
    _assert_failed(service.windbg_live_modules(session_id))
    _assert_failed(service.windbg_live_disasm(session_id, 0x140001000))


def test_windbg_live_threads_rejects_a_session_without_a_debuggee(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    result = service.windbg_live_threads(session_id)

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "invalid_state"


# ---------------------------------------------------------------------------
# capabilities
# ---------------------------------------------------------------------------


def test_capabilities_search_and_describe(tmp_path: Path) -> None:
    service, _repo, _root = _repo_service(tmp_path)

    listed = service.capabilities_search()
    assert listed.ok and listed.data is not None
    assert listed.data["count"] == len(listed.data["capabilities"])

    missing = service.capabilities_describe("no-such-capability")
    _assert_failed(missing)
    assert missing.error is not None
    assert missing.error.code == "not_found"

    if listed.data["capabilities"]:
        first = listed.data["capabilities"][0]
        described = service.capabilities_describe(str(first["id"]))
        assert described.ok and described.data is not None


# ---------------------------------------------------------------------------
# artifacts
# ---------------------------------------------------------------------------


def test_artifacts_read_returns_hex_slice(tmp_path: Path) -> None:
    service, repository, root = _repo_service(tmp_path)
    payload = b"artifact-bytes-0123456789"
    path = root / "capture.bin"
    root.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    artifact = repository.register_artifact(
        session_id="session", kind="capture", path=path, sha256="a" * 64, source="test"
    )

    result = service.artifacts_read(str(artifact["id"]))

    assert result.ok and result.data is not None
    assert bytes.fromhex(str(result.data["data"])) == payload
    assert result.data["size"] == len(payload)


def test_artifacts_read_reports_a_missing_file(tmp_path: Path) -> None:
    service, repository, root = _repo_service(tmp_path)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "gone.bin"
    path.write_bytes(b"temp")
    artifact = repository.register_artifact(
        session_id="session", kind="capture", path=path, sha256="a" * 64, source="test"
    )
    path.unlink()

    result = service.artifacts_read(str(artifact["id"]))

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "not_found"


def test_artifacts_read_refuses_a_path_outside_the_root(tmp_path: Path) -> None:
    service, repository, _root = _repo_service(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"escape")
    artifact = repository.register_artifact(
        session_id="session", kind="capture", path=outside, sha256="a" * 64, source="test"
    )

    result = service.artifacts_read(str(artifact["id"]))

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "permission_denied"


def test_artifacts_describe_reports_missing(tmp_path: Path) -> None:
    service, _repo, _root = _repo_service(tmp_path)

    result = service.artifacts_describe("no-such-artifact")

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "not_found"


def test_artifacts_list_timeline_audit_and_gc(tmp_path: Path) -> None:
    service, _repo, _root = _repo_service(tmp_path)

    assert service.artifacts_list().ok
    assert service.artifacts_gc().ok
    assert service.timeline_list("session").ok
    assert service.audit_list().ok


def test_sessions_unclean_pages_the_store(tmp_path: Path) -> None:
    service, _repo, _root = _repo_service(tmp_path)

    result = service.sessions_unclean()

    assert result.ok and result.data is not None
    assert "sessions" in result.data
    assert result.data["has_more"] is False


# ---------------------------------------------------------------------------
# peek_session_record
# ---------------------------------------------------------------------------


def test_peek_session_record_returns_a_live_session(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    result = service.peek_session_record(session_id)

    assert result.ok and result.data is not None
    assert result.data["live"] is True
    assert result.data["id"] == session_id


def test_peek_session_record_rejects_an_unknown_id(tmp_path: Path) -> None:
    service, _repo, _root = _repo_service(tmp_path)

    result = service.peek_session_record("does-not-exist")

    _assert_failed(result)


# ---------------------------------------------------------------------------
# batch_analyze
# ---------------------------------------------------------------------------


def test_batch_analyze_validates_its_inputs(tmp_path: Path) -> None:
    service, _repo, _root = _repo_service(tmp_path)

    _assert_failed(service.batch_analyze([]))
    _assert_failed(service.batch_analyze([f"b{i}.exe" for i in range(33)]))
    _assert_failed(service.batch_analyze(["a.exe"], max_workers=0))
    _assert_failed(service.batch_analyze(["a.exe"], max_workers=True))


def test_batch_analyze_reports_per_entry_outcomes(tmp_path: Path) -> None:
    service, _repo, _root = _repo_service(tmp_path)
    good = tmp_path / "good.exe"
    _write_minimal_pe(good)

    result = service.batch_analyze([str(good), str(tmp_path / "missing.exe")], open_static=False)

    assert result.ok and result.data is not None
    assert result.data["count"] == 2
    assert result.data["succeeded"] == 1
    assert result.data["failed"] == 1


def test_batch_analyze_marks_failed_static_open(tmp_path: Path) -> None:
    service, _repo, _root = _repo_service(tmp_path)
    good = tmp_path / "good.exe"
    _write_minimal_pe(good)

    result = service.batch_analyze([str(good)], open_static=True)

    assert result.ok and result.data is not None
    entry = result.data["entries"][0]
    assert entry["static_open"] is False
    assert entry["ok"] is False


# ---------------------------------------------------------------------------
# knowledge / report / tool metrics
# ---------------------------------------------------------------------------


def test_knowledge_record_validates_kind_and_key(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _assert_failed(service.knowledge_record(session_id, "", "key"))
    _assert_failed(service.knowledge_record(session_id, "kind", ""))
    oversized = {"blob": "x" * 200_000}
    _assert_failed(service.knowledge_record(session_id, "kind", "key", oversized))


def test_knowledge_record_rejects_a_closed_session(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)
    assert service.close_session(session_id).ok

    result = service.knowledge_record(session_id, "note", "k", {"v": 1})

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_knowledge_record_and_query_round_trip(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    recorded = service.knowledge_record(session_id, "note", "entry", {"value": 1})
    assert recorded.ok

    queried = service.knowledge_query(session_id, kind="note")
    assert queried.ok and queried.data is not None
    assert queried.data["total"] >= 1


def test_knowledge_query_rejects_an_unknown_session(tmp_path: Path) -> None:
    service, _repo, _root = _repo_service(tmp_path)

    _assert_failed(service.knowledge_query("does-not-exist"))


def test_report_generate_validates_audit_limit(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _assert_failed(service.report_generate(session_id, audit_limit=0))
    _assert_failed(service.report_generate(session_id, audit_limit=True))


def test_report_generate_rejects_a_closed_session(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)
    assert service.close_session(session_id).ok

    result = service.report_generate(session_id)

    _assert_failed(result)
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_report_generate_renders_and_saves_markdown(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)
    assert service.knowledge_record(session_id, "note", "finding", {"value": 1}).ok

    result = service.report_generate(session_id, title="Sample Report")

    assert result.ok and result.data is not None
    assert "markdown" in result.data
    saved = Path(str(result.data["path"]))
    assert saved.is_file()
    assert saved.suffix == ".md"


def test_tool_metrics_validates_limit_and_reports(tmp_path: Path) -> None:
    service, _repo, _root = _repo_service(tmp_path)

    _assert_failed(service.tool_metrics(limit=-1))
    _assert_failed(service.tool_metrics(limit=True))

    metrics = service.tool_metrics(limit=5)
    assert metrics.ok and metrics.data is not None
    assert "recent" in metrics.data


# ---------------------------------------------------------------------------
# ui_drive validation guards
# ---------------------------------------------------------------------------


def test_ui_drive_to_event_validates_timeout_and_budget(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _assert_failed(service.ui_drive_to_event(session_id, "debug.paused", timeout=0))
    _assert_failed(service.ui_drive_to_event(session_id, "debug.paused", event_budget=0))


def test_ui_drive_to_breakpoint_propagates_a_missing_workflow(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    result = service.ui_drive_to_breakpoint(session_id, "intent-1")

    _assert_failed(result)
