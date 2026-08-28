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


def test_report_title_is_length_bounded_like_every_other_field() -> None:
    """The H1 heading is the one field that skips _cell, so an unbounded caller
    title otherwise grew the persisted report without limit. It must be clipped
    the way _cell clips values (the report's own discipline, and the 200-char cap
    the agent thread store already applies to titles)."""
    from headless_re_mcp.reporting import _MAX_TITLE

    markdown = render_markdown_report(
        session=_SESSION,
        title="T" * 5000,
        generated_at="t",
    )
    heading = markdown.splitlines()[0]
    assert heading.startswith("# ")
    assert heading.endswith("…")
    # The whole heading line is "# " + clipped title, so bounded near _MAX_TITLE
    # rather than echoing the 5000-char input.
    assert len(heading) <= _MAX_TITLE + 2
    assert "T" * 5000 not in markdown


def test_report_title_newlines_cannot_break_out_of_the_heading() -> None:
    """A newline in the title would otherwise split the `# ` line, injecting
    arbitrary document structure after the heading. Newlines are neutralised to
    spaces, like _cell does for table values, so the heading stays one line."""
    markdown = render_markdown_report(
        session=_SESSION,
        title="Real title\n## Injected Section\nbody",
        generated_at="t",
    )
    lines = markdown.splitlines()
    assert lines[0] == "# Real title ## Injected Section body"
    # The injected text stayed on the heading line; it did not become its own
    # markdown heading.
    assert "## Injected Section" not in lines[1:]


def test_report_blank_title_falls_back_to_the_default_heading() -> None:
    markdown = render_markdown_report(session=_SESSION, title="   \n  ", generated_at="t")
    assert markdown.startswith("# Analysis report — C:\\samples\\fixture.exe")


def test_report_finding_kind_newlines_cannot_inject_a_section_heading() -> None:
    """The `### {kind}` section heading is the other field that skips _cell. A
    finding kind carrying a newline would otherwise split it into an injected
    heading; it must be collapsed to one line like the title and table cells."""
    knowledge = {
        "entries": [
            {
                "kind": "note\n## Injected Section",
                "key": "k",
                "value": {"a": "b"},
                "updated_at": "t",
            }
        ]
    }
    markdown = render_markdown_report(session=_SESSION, knowledge=knowledge, generated_at="t")
    heading = next(line for line in markdown.splitlines() if line.startswith("### "))
    assert heading == "### note ## Injected Section (1)"
    # The injected text stayed on the one section-heading line rather than
    # becoming its own `##` heading.
    assert "## Injected Section" not in [
        line for line in markdown.splitlines() if line.startswith("## ")
    ]


def test_report_cell_carriage_returns_cannot_break_a_table_row() -> None:
    """A bare \\r in a table value must not split the row.

    _cell is the sink every table value flows through, and a markdown table row
    is one line. CommonMark/GFM treat a lone \\r as a line ending just like \\n,
    so a finding value carrying \\r (a captured string, an agent note) would end
    its row early -- terminating the table and spilling the tail as body text,
    the same breakout _inline already blocks for headings. _cell collapsed \\n
    but not \\r; this pins that both are neutralised so the row stays intact.
    """
    knowledge = {
        "entries": [
            {
                "kind": "note",
                # The key flows through _cell exactly once (the value column is
                # summarised then re-celled, which double-escapes pipes), so the
                # key is where the \r-plus-pipes payload reads cleanly.
                "key": "before\r| injected | fake | row",
                "value": {"a": "b"},
                "updated_at": "t",
            }
        ]
    }
    markdown = render_markdown_report(session=_SESSION, knowledge=knowledge, generated_at="t")
    lines = markdown.splitlines()
    row = next(line for line in lines if line.startswith("| before"))
    # The whole key stayed on the one row line: the \r became a space and the
    # pipes were escaped, so nothing spilled onto a new line markdown would read
    # as body text or a fresh row.
    assert "\r" not in row
    assert "before \\| injected \\| fake \\| row" in row
    row_index = lines.index(row)
    assert not lines[row_index + 1].startswith("| injected")


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