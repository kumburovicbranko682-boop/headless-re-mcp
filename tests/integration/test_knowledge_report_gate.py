"""Knowledge store + report Gate: the analysis notebook works with no backend.

``knowledge.record`` / ``knowledge.query`` / ``report.generate`` are the pure-Python,
cross-target "analysis notebook": an agent records durable facts as it works, reads
them back, and renders a Markdown report saved as a collectable artifact. None of that
needs IDA, x64dbg, or any external tool -- the facts live in the session's SQLite store
and the report is assembled in-process.

Yet the only place these three are exercised end to end is
``test_composite_tools_gate.py::test_batch_opens_parallel_ida_sessions_and_reports``,
which requires a real IDA + x64dbg backend and is marked Windows-only, so on Linux the
whole notebook surface is unproven. This gate drives it against a committed PE fixture
with every backend unset, proving:

  * a re-recorded ``(kind, key)`` updates in place instead of duplicating (the
    idempotency the store promises), and values round-trip as structured objects;
  * ``knowledge.query`` filters by kind and counts honestly;
  * ``report.generate`` writes a real Markdown file under the artifact root, carries
    the recorded facts, reports the right finding count, and registers a collectable
    artifact whose bytes read back exactly (size + SHA-256 + content);
  * an untouched session renders a report that says so and honours ``include_audit``;
  * malformed input is refused with an envelope rather than silently stored.

No external tool is involved, so nothing should skip on any platform; a missing fixture
skips loudly (skip != pass).
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService, JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
# Any committed PE works: the notebook is target-agnostic and never opens a backend.
_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _fixture() -> Path:
    if not _FIXTURE.is_file():
        pytest.skip(f"missing committed PE fixture: {_FIXTURE} (skip != pass)")
    return _FIXTURE


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=None,
        diec=None,
    )
    return AnalysisService(settings)


def _data(result: object) -> JsonObject:
    assert getattr(result, "ok", False), getattr(result, "error", None)
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


def _session_id(service: AnalysisService, binary: Path) -> str:
    created = _data(service.create_session(str(binary)))
    session = created["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _artifact_bytes(read: JsonObject) -> bytes:
    """Decode an artifacts.read payload by its declared encoding."""
    encoding = read["encoding"]
    payload = read["data"]
    if encoding == "hex":
        return bytes.fromhex(payload)
    if encoding == "base64":
        return base64.b64decode(payload)
    return str(payload).encode("utf-8")


@pytest.mark.integration
def test_knowledge_records_query_and_report_round_trip(tmp_path: Path) -> None:
    binary = _fixture()
    service = _service(tmp_path)
    try:
        session_id = _session_id(service, binary)

        # First write of each key is a create, not a replace.
        first = _data(
            service.knowledge_record(
                session_id,
                "api",
                "CreateFileW",
                {"module": "kernel32", "note": "opens the license file"},
            )
        )
        assert first["replaced"] is False, first
        created = _data(service.knowledge_record(session_id, "function", "entry", {"rva": 0x1000}))
        assert created["replaced"] is False, created

        # Re-recording the same (kind, key) must update in place, keeping created_at.
        updated = _data(
            service.knowledge_record(
                session_id, "function", "entry", {"rva": 0x1000, "note": "OEP"}
            )
        )
        assert updated["replaced"] is True, updated
        assert updated["created_at"] == created["created_at"], (created, updated)

        # Query by kind: the update did not duplicate, and the value is structured.
        functions = _data(service.knowledge_query(session_id, kind="function"))
        assert functions["total"] == 1, functions
        entry = functions["entries"][0]
        assert entry["key"] == "entry"
        assert entry["value"] == {"rva": 0x1000, "note": "OEP"}, entry

        apis = _data(service.knowledge_query(session_id, kind="api"))
        assert apis["total"] == 1, apis
        assert apis["entries"][0]["value"]["module"] == "kernel32", apis

        everything = _data(service.knowledge_query(session_id))
        assert everything["total"] == 2, everything

        # The report gathers those facts into a saved Markdown document.
        report = _data(service.report_generate(session_id, title="Gate report"))
        assert report["findings"] == 2, report
        assert report["truncated"] is False, report
        report_path = Path(str(report["path"]))
        assert report_path.is_file(), report_path
        assert report_path.parent.name == session_id, report_path
        assert report_path.parent.parent.name == "reports", report_path

        on_disk = report_path.read_bytes()
        assert report["bytes"] == len(on_disk), report
        markdown = on_disk.decode("utf-8")
        assert markdown.startswith("# Gate report"), markdown[:40]
        # The recorded facts made it into the document, including the updated note.
        assert "CreateFileW" in markdown, markdown
        assert "OEP" in markdown, markdown

        # The report is a collectable artifact that reads back byte-for-byte.
        artifact_id = str(report["artifact_id"])
        described = _data(service.artifacts_describe(artifact_id))["artifact"]
        assert described["kind"] == "report_markdown", described
        assert int(described["size"]) == len(on_disk), described
        assert described["sha256"] == hashlib.sha256(on_disk).hexdigest(), described

        read = _data(service.artifacts_read(artifact_id))
        assert _artifact_bytes(read) == on_disk
    finally:
        service.close_all()


@pytest.mark.integration
def test_report_of_an_untouched_session_says_so_and_can_omit_audit(tmp_path: Path) -> None:
    binary = _fixture()
    service = _service(tmp_path)
    try:
        session_id = _session_id(service, binary)

        report = _data(service.report_generate(session_id, include_audit=False))
        assert report["findings"] == 0, report
        markdown = Path(str(report["path"])).read_text(encoding="utf-8")
        assert "No findings were recorded" in markdown, markdown
        # include_audit=False must actually drop the section, not just the rows.
        assert "Recent actions" not in markdown, markdown
    finally:
        service.close_all()


@pytest.mark.integration
def test_knowledge_and_report_reject_malformed_input(tmp_path: Path) -> None:
    binary = _fixture()
    service = _service(tmp_path)
    try:
        session_id = _session_id(service, binary)

        assert service.knowledge_record(session_id, "  ", "key", {}).ok is False
        assert service.knowledge_record(session_id, "note", "  ", {}).ok is False
        # A value that serialises past the store's cap is refused rather than
        # silently truncated into something that no longer parses as JSON.
        oversize = service.knowledge_record(session_id, "note", "big", {"blob": "A" * 9000})
        assert oversize.ok is False, oversize.data

        assert service.report_generate(session_id, audit_limit=0).ok is False
        assert service.report_generate(session_id, audit_limit=201).ok is False
    finally:
        service.close_all()
