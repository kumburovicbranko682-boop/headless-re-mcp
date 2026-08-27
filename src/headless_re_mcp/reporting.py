"""Render a session analysis report as Markdown.


The renderer is pure: callers gather session metadata, accumulated knowledge,

artifacts and audit rows, and this module turns them into a reviewable document.

Keeping it side-effect free means the layout is unit-testable without a debugger,

a database, or a filesystem.

"""


from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

JsonObject = dict[str, Any]


_MAX_CELL = 120


def _cell(value: object) -> str:

    text = "" if value is None else str(value)

    text = text.replace("|", "\\|").replace("\n", " ").strip()

    if len(text) > _MAX_CELL:

        text = text[: _MAX_CELL - 1] + "…"

    return text or "—"


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:

    lines = ["| " + " | ".join(headers) + " |"]

    lines.append("|" + "|".join([" --- "] * len(headers)) + "|")

    for row in rows:

        lines.append("| " + " | ".join(_cell(item) for item in row) + " |")

    return lines


def _summarize_value(value: object) -> str:

    if isinstance(value, dict):

        if not value:

            return "—"

        return ", ".join(f"{key}={_cell(item)}" for key, item in list(value.items())[:4])

    return _cell(value)


def _note_if_partial(
    lines: list[str], section: JsonObject | None, *, shown: int, noun: str
) -> None:
    """Say so when a section is only part of what the session holds.

    report.generate caps each section, so a session that recorded more than the
    cap produced a report that read as complete and was not. This is the
    artefact someone keeps and acts on, and a finding it never mentions is
    indistinguishable from a finding that was never made.
    """
    total = (section or {}).get("total")

    if not isinstance(total, int) or total <= shown:
        return

    lines.append(
        f"> Showing {shown} of {total} {noun}. "
        f"The rest are in the session, not in this report."
    )

    lines.append("")


def render_markdown_report(

    *,

    session: JsonObject,

    knowledge: JsonObject | None = None,

    artifacts: JsonObject | None = None,

    audit: JsonObject | None = None,

    title: str | None = None,

    generated_at: str | None = None,

) -> str:

    """Render one Markdown report; every section degrades to a clear note."""

    stamp = generated_at or datetime.now(UTC).isoformat()

    subject = session.get("binary") or session.get("id") or "session"

    heading = title or f"Analysis report — {subject}"

    lines: list[str] = [f"# {heading}", ""]

    lines.append(f"Generated at `{stamp}`.")

    lines.append("")

    lines.append("## Session")

    lines.append("")

    lines.extend(

        _table(

            ["Field", "Value"],

            [

                ["Session", session.get("id")],

                ["Binary", session.get("binary")],

                ["SHA-256", session.get("sha256")],

                ["Architecture", session.get("architecture")],

                ["State", session.get("state")],

                ["Backends", ", ".join(session.get("backends") or []) or None],

            ],

        )

    )

    lines.append("")

    entries = list((knowledge or {}).get("entries") or [])

    lines.append("## Findings")

    lines.append("")

    _note_if_partial(lines, knowledge, shown=len(entries), noun="findings")

    if not entries:

        lines.append("No findings were recorded for this session yet.")

        lines.append("")

    else:

        grouped: dict[str, list[JsonObject]] = {}

        for entry in entries:

            grouped.setdefault(str(entry.get("kind") or "note"), []).append(entry)

        for kind in sorted(grouped):

            items = grouped[kind]

            lines.append(f"### {kind} ({len(items)})")

            lines.append("")

            lines.extend(

                _table(

                    ["Key", "Value", "Updated"],

                    [

                        [

                            item.get("key"),

                            _summarize_value(item.get("value")),

                            item.get("updated_at"),

                        ]

                        for item in items

                    ],

                )

            )

            lines.append("")

    payload = artifacts or {}
    raw_artifacts = payload.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raw_artifacts = payload.get("entries")
    artifact_entries = list(raw_artifacts) if isinstance(raw_artifacts, list) else []

    lines.append("## Artifacts")

    lines.append("")

    _note_if_partial(lines, artifacts, shown=len(artifact_entries), noun="artifacts")

    if not artifact_entries:

        lines.append("No artifacts were produced for this session yet.")

        lines.append("")

    else:

        lines.extend(

            _table(

                ["Kind", "Path", "Bytes"],

                [

                    [item.get("kind"), item.get("path"), item.get("size")]

                    for item in artifact_entries

                ],

            )

        )

        lines.append("")

    audit_entries = list((audit or {}).get("entries") or [])

    if audit_entries:

        lines.append("## Recent actions")

        lines.append("")

        _note_if_partial(lines, audit, shown=len(audit_entries), noun="actions")

        lines.extend(

            _table(

                ["At", "Action", "Result"],

                [

                    [

                        item.get("at"),

                        item.get("action"),

                        "ok" if item.get("ok") else "failed",

                    ]

                    for item in audit_entries

                ],

            )

        )

        lines.append("")

    lines.append("---")

    lines.append("")

    lines.append(

        "Generated by Headless RE-MCP. Findings are what the analysis recorded; "

        "they are not a proof of behaviour."

    )

    return "\n".join(lines).rstrip() + "\n"
