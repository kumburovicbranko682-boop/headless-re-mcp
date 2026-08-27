from __future__ import annotations

from headless_re_mcp.reporting import render_markdown_report

_SESSION = {

    "id": "sess-1",

    "binary": r"C:\samples\fixture.exe",

    "sha256": "abc123",

    "architecture": "x64",

    "state": "suspended",

    "backends": ["ida", "x64dbg"],

}


def test_report_renders_session_and_grouped_findings() -> None:

    knowledge = {

        "entries": [

            {

                "kind": "function",

                "key": "0x401000",

                "value": {"name": "main"},

                "updated_at": "2026-08-11T00:00:00+00:00",

            },

            {

                "kind": "api",

                "key": "CreateFileW",

                "value": {"module": "kernel32"},

                "updated_at": "2026-08-11T00:01:00+00:00",

            },

        ]

    }

    markdown = render_markdown_report(

        session=_SESSION,

        knowledge=knowledge,

        generated_at="2026-08-11T12:00:00+00:00",

    )

    assert markdown.startswith("# Analysis report — C:\\samples\\fixture.exe")

    assert "2026-08-11T12:00:00+00:00" in markdown

    assert "### api (1)" in markdown

    assert "### function (1)" in markdown

    assert "module=kernel32" in markdown

    assert "ida, x64dbg" in markdown

    assert markdown.endswith("\n")


def test_report_states_empty_sections_explicitly() -> None:

    markdown = render_markdown_report(session=_SESSION, generated_at="t")

    assert "No findings were recorded for this session yet." in markdown

    assert "No artifacts were produced for this session yet." in markdown

    assert "## Recent actions" not in markdown


def test_report_escapes_pipes_and_truncates_long_cells() -> None:

    knowledge = {

        "entries": [

            {

                "kind": "note",

                "key": "pipe|key",

                "value": {"text": "x" * 400},

                "updated_at": "t",

            }

        ]

    }

    markdown = render_markdown_report(

        session=_SESSION,

        knowledge=knowledge,

        generated_at="t",

    )

    assert "pipe\\|key" in markdown

    assert "…" in markdown

    row = next(line for line in markdown.splitlines() if line.startswith("| pipe"))

    # The escaped pipe must not create a fourth column.

    assert len(row.replace("\\|", "").strip("| ").split(" | ")) == 3


def test_report_includes_audit_when_supplied() -> None:

    audit = {

        "entries": [

            {"at": "2026-08-11T00:00:00+00:00", "action": "static.open", "ok": True},

            {"at": "2026-08-11T00:00:01+00:00", "action": "dynamic.open", "ok": False},

        ]

    }

    markdown = render_markdown_report(session=_SESSION, audit=audit, generated_at="t")

    assert "## Recent actions" in markdown

    assert "static.open" in markdown

    assert "failed" in markdown


def test_a_capped_report_says_it_is_capped() -> None:
    """The report is the artefact someone keeps; it must not read as complete.

    report.generate caps findings at 500 and artifacts at 100. A session that
    recorded more produced a report that looked like the whole picture, and a
    finding the report never mentions is indistinguishable from one that was
    never made -- which is the wrong conclusion to hand someone.
    """
    session = {
        "id": "s1",
        "binary": "target.exe",
        "sha256": "ab" * 32,
        "architecture": "x64",
        "state": "ready",
        "backends": ["x64dbg"],
    }

    whole = render_markdown_report(
        session=session,
        knowledge={"entries": [{"kind": "note", "key": "k", "value": 1}], "count": 1, "total": 1},
        artifacts={
            "entries": [{"kind": "dump", "path": "a.bin", "size": 10}],
            "count": 1,
            "total": 1,
        },
    )
    assert "Showing" not in whole, "a complete report needs no disclaimer"

    partial = render_markdown_report(
        session=session,
        knowledge={
            "entries": [{"kind": "note", "key": f"k{i}", "value": i} for i in range(500)],
            "count": 500,
            "total": 913,
        },
        artifacts={
            "entries": [{"kind": "dump", "path": "a.bin", "size": 10}] * 100,
            "count": 100,
            "total": 247,
        },
    )
    assert "Showing 500 of 913 findings" in partial
    assert "Showing 100 of 247 artifacts" in partial


def test_a_capped_audit_section_says_it_is_capped() -> None:
    """report.generate caps the audit trail too (audit_limit 1..200, store 256).

    The other two capped sections disclose it; the ``Recent actions`` table did
    not, so a session with more actions than the cap rendered an audit log that
    read as the whole history -- an action the report never lists reads exactly
    like one that never happened.
    """
    audit = {
        "entries": [
            {"at": f"2026-08-11T00:00:{i:02d}+00:00", "action": "static.open", "ok": True}
            for i in range(50)
        ],
        "count": 50,
        "total": 4096,
    }

    markdown = render_markdown_report(session=_SESSION, audit=audit, generated_at="t")

    assert "## Recent actions" in markdown
    assert "Showing 50 of 4096 actions" in markdown


def test_a_complete_audit_section_needs_no_disclaimer() -> None:
    audit = {
        "entries": [
            {"at": "2026-08-11T00:00:00+00:00", "action": "static.open", "ok": True},
        ],
        "count": 1,
        "total": 1,
    }

    markdown = render_markdown_report(session=_SESSION, audit=audit, generated_at="t")

    assert "## Recent actions" in markdown
    assert "Showing" not in markdown


def test_report_reads_the_list_artifacts_key() -> None:
    """Production list_artifacts returns artifacts, not entries."""
    markdown = render_markdown_report(
        session=_SESSION,
        artifacts={
            "artifacts": [{"kind": "dump", "path": "mod.bin", "size": 4096}],
            "count": 1,
            "total": 1,
        },
        generated_at="t",
    )
    assert "mod.bin" in markdown
    assert "No artifacts were produced for this session yet." not in markdown