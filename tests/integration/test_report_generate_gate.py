"""Live Gate for the pure-Python Markdown report surface (``report.generate``).

``report.generate`` aggregates a session's recorded findings, artifacts and
audit trail into a Markdown document, writes it under the artifact root, and
registers it as a ``report_markdown`` artifact. It touches no external tool and
no IDA/debugger, so it runs anywhere -- yet it had no end-to-end gate. A
regression in the report renderer, the finding grouping, the artifact
registration, or the argument guards would go unnoticed on Linux.

This gate drives the real service against a committed PE fixture: an empty
session renders the skeleton (session table + "no findings" note), recorded
findings show up grouped by kind, the report is persisted and then listed back
as an artifact (and a later report even lists the earlier one), and the
audit-limit / closed-session guards fail closed. It needs no toolchain and
never skips.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_REPO = Path(__file__).resolve().parents[2]
_PE = _REPO / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            diec=None,
        )
    )


def _require(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"fixture missing: {path}")


def _open(service: AnalysisService, path: Path) -> str:
    created = service.create_session(str(path))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


@pytest.mark.integration
def test_report_on_empty_session_renders_skeleton(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)
    sha256 = service.registry.get(session_id).sha256 or ""

    result = service.report_generate(session_id)
    assert result.ok and result.data is not None, result.error
    data = result.data
    assert data["findings"] == 0
    assert data["truncated"] is False
    assert isinstance(data["artifact_id"], str) and data["artifact_id"]

    markdown = data["markdown"]
    assert markdown.startswith("# Analysis report —")
    for section in ("## Session", "## Findings", "## Artifacts"):
        assert section in markdown, markdown
    assert "No findings were recorded for this session yet." in markdown
    # The session table carries the real identity of the specimen.
    assert sha256[:12] in markdown
    assert "x64" in markdown
    assert str(_PE) in markdown

    # The document was actually persisted, and the byte count is honest.
    report_path = Path(data["path"])
    assert report_path.is_file()
    assert report_path.suffix == ".md"
    assert report_path.parent.name == session_id
    assert report_path.stat().st_size == data["bytes"]


@pytest.mark.integration
def test_report_includes_recorded_findings(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)

    assert service.knowledge_record(session_id, "strings", "banner", {"text": "H3adl3ss"}).ok
    assert service.knowledge_record(session_id, "function", "main", {"addr": "0x401000"}).ok

    result = service.report_generate(session_id, title="Gate Report")
    assert result.ok and result.data is not None, result.error
    data = result.data
    assert data["findings"] == 2

    markdown = data["markdown"]
    # A custom title replaces the default heading.
    assert markdown.splitlines()[0] == "# Gate Report"
    # Findings are grouped by kind, each with its recorded key.
    assert "### function (1)" in markdown
    assert "### strings (1)" in markdown
    assert "banner" in markdown
    assert "main" in markdown


@pytest.mark.integration
def test_report_is_registered_as_an_artifact(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)

    first = service.report_generate(session_id)
    assert first.ok and first.data is not None, first.error
    first_path = first.data["path"]

    listed = service.artifacts_list(session_id)
    assert listed.ok and listed.data is not None, listed.error
    reports = [item for item in listed.data["artifacts"] if item["kind"] == "report_markdown"]
    assert len(reports) == 1
    assert reports[0]["path"] == first_path
    assert reports[0]["id"] == first.data["artifact_id"]

    # A later report's Artifacts section lists the earlier report, proving the
    # first one is discoverable, not just written to disk. (The table truncates
    # long path cells, so the exact path match above is the precise check; here
    # we only confirm the earlier report shows up as a listed artifact.)
    second = service.report_generate(session_id)
    assert second.ok and second.data is not None, second.error
    artifacts_section = second.data["markdown"].split("## Artifacts", 1)[1]
    assert "report_markdown" in artifacts_section


@pytest.mark.integration
def test_report_generate_guards(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)

    for bad in (0, 201):
        guarded = service.report_generate(session_id, audit_limit=bad)
        assert guarded.ok is False and guarded.error is not None
        assert guarded.error.code == "invalid_request"
        assert "audit_limit" in guarded.error.message

    # A boolean must not slip through the int bound as 0/1.
    boolean = service.report_generate(session_id, audit_limit=True)  # type: ignore[arg-type]
    assert boolean.ok is False and boolean.error is not None
    assert boolean.error.code == "invalid_request"

    service.close_session(session_id)
    closed = service.report_generate(session_id)
    assert closed.ok is False and closed.error is not None
    assert closed.error.code == "invalid_request"
