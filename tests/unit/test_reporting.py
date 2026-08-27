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


def test_a_summarized_value_says_when_it_dropped_fields() -> None:
    """A finding's value is summarised to a few fields; the rest must be owned.

    render_markdown_report shows only the first handful of a value dict's keys
    to keep the row readable. Dropping the remainder with no marker made a
    six-field finding read as a two- or four-field one in the artefact someone
    keeps -- the same silent omission the section 'Showing X of Y' notes guard
    against, one level down. A value at or under the cap must stay unadorned.
    """
    from headless_re_mcp.reporting import _MAX_VALUE_FIELDS

    over = {f"k{i}": i for i in range(_MAX_VALUE_FIELDS + 2)}
    knowledge = {
        "entries": [
            {"kind": "note", "key": "many", "value": over, "updated_at": "t"},
            {
                "kind": "note",
                "key": "few",
                "value": {"only": "one"},
                "updated_at": "t",
            },
        ]
    }
    markdown = render_markdown_report(session=_SESSION, knowledge=knowledge, generated_at="t")

    assert "(+2 more)" in markdown
    many_row = next(line for line in markdown.splitlines() if line.startswith("| many"))
    few_row = next(line for line in markdown.splitlines() if line.startswith("| few"))
    assert "(+2 more)" in many_row
    assert "more)" not in few_row


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