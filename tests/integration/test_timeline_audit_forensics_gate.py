"""Timeline-vs-audit forensic contract over a real MCP stdio server.

An unattended run leaves two logs, and they answer different questions on
purpose. ``timeline.list`` is one session's history of *marks* -- what it opened,
closed, wrote or drove -- and reads leave no mark, so a session that analysed for
an hour without changing anything shows only its open and its close.
``audit.list`` is the operations log across sessions: which sessions ran, with
what arguments, and how they ended. A caller that mixes the two up -- looking for
a read in the timeline, or a static edit in the audit, or reading the wrong field
name -- silently draws the wrong forensic conclusion.

This pins the split end-to-end over stdio, on a bare box with no backend:

  * Reads leave no mark. After a session opens and then runs pure queries
    (``capabilities.search``, ``session.list``) and records knowledge and
    generates a report, its timeline still shows *only* ``session.created`` and
    its audit shows *only* ``session.create``. Neither the reads nor those
    non-static writes appear.

  * Open and close both leave a mark in both logs, and the timeline is
    chronological (created before closed).

  * The audit carries the arguments and the outcome (``params_summary``, a
    truthy ``ok``, ``result_summary``) -- that is what lets it answer "which
    sessions ran and how they ended". The timeline does not; it answers "what
    changed".

  * The field names are part of the contract: the timeline answers ``events``
    and never ``entries``; the audit answers ``entries`` and never ``events``.

  * The two logs disagree about an unknown session by design. ``timeline.list``
    is a specific session's history, so an id that never existed is
    ``session_not_found`` -- not an empty event list that reads as "existed,
    changed nothing". ``audit.list`` is a filter over a global log, so an unknown
    id simply matches nothing and returns an empty page. The global audit (no
    id) still contains the session's entries.

Pure-stdlib PE fixture, stdio loopback, no backend, any platform.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _envelope(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"expected a structured envelope, got {content!r}"
    return content


def _data(result: object) -> dict[str, Any]:
    envelope = _envelope(result)
    assert envelope.get("ok") is True, envelope
    data = envelope.get("data")
    assert isinstance(data, dict), envelope
    return data


def _code(envelope: dict[str, Any]) -> str | None:
    error = envelope.get("error")
    return error.get("code") if isinstance(error, dict) else None


def _write_pe(path: Path) -> Path:
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\x00\x00"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    opt = 0x98
    image[opt : opt + 2] = (0x20B).to_bytes(2, "little")
    image[opt + 24 : opt + 32] = (0x180000000).to_bytes(8, "little")
    image[opt + 56 : opt + 60] = (0x5000).to_bytes(4, "little")
    path.write_bytes(image)
    return path


@asynccontextmanager
async def _mcp(artifact_root: Path) -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    project_root = Path(__file__).resolve().parents[2]
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=project_root,
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        yield client


async def _session(client: ClientSession, binary: str) -> str:
    data = _data(await client.call_tool("session.create", {"binary": binary}))
    session = data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


@pytest.mark.integration
@pytest.mark.asyncio
async def test_reads_leave_no_mark_but_open_and_close_do(tmp_path: Path) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        sid = await _session(client, str(pe))

        # A working session: pure reads, plus a knowledge fact and a report.
        # None of these is a static edit that the timeline records.
        await client.call_tool("capabilities.search", {"query": "pe"})
        await client.call_tool("session.list", {})
        assert _data(
            await client.call_tool(
                "knowledge.record",
                {"session_id": sid, "kind": "note", "key": "k", "value": {"n": 1}},
            )
        )
        assert _data(await client.call_tool("report.generate", {"session_id": sid}))

        # Timeline: only the open. The field is `events`, never `entries`.
        timeline = _data(await client.call_tool("timeline.list", {"session_id": sid}))
        assert "events" in timeline and "entries" not in timeline, timeline
        assert [e["event"] for e in timeline["events"]] == ["session.created"], timeline

        # Audit: only the open, and it carries the arguments and the outcome.
        # The field is `entries`, never `events`.
        audit = _data(await client.call_tool("audit.list", {"session_id": sid}))
        assert "entries" in audit and "events" not in audit, audit
        assert [e["action"] for e in audit["entries"]] == ["session.create"], audit
        opened = audit["entries"][0]
        assert opened["params_summary"], opened  # the arguments were captured
        assert opened["ok"], opened  # the outcome was captured
        assert isinstance(opened.get("result_summary"), dict), opened

        # Close leaves a mark in both logs; the timeline is chronological.
        assert _data(await client.call_tool("session.close", {"session_id": sid}))

        timeline_after = _data(
            await client.call_tool("timeline.list", {"session_id": sid})
        )
        assert [e["event"] for e in timeline_after["events"]] == [
            "session.created",
            "session.closed",
        ], timeline_after

        audit_after = _data(await client.call_tool("audit.list", {"session_id": sid}))
        assert {e["action"] for e in audit_after["entries"]} == {
            "session.create",
            "session.close",
        }, audit_after


@pytest.mark.integration
@pytest.mark.asyncio
async def test_the_two_logs_answer_an_unknown_session_differently(
    tmp_path: Path,
) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        sid = await _session(client, str(pe))

        # timeline is a specific session's history: an id that never existed is
        # an error, not an empty event list that reads as "existed, no changes".
        unknown_timeline = _envelope(
            await client.call_tool("timeline.list", {"session_id": "no-such-session"})
        )
        assert unknown_timeline.get("ok") is False, unknown_timeline
        assert _code(unknown_timeline) == "session_not_found", unknown_timeline

        # audit is a filter over a global log: an unknown id simply matches
        # nothing and returns an empty page, never an error.
        unknown_audit = _data(
            await client.call_tool("audit.list", {"session_id": "no-such-session"})
        )
        assert unknown_audit["entries"] == [], unknown_audit
        assert unknown_audit["count"] == 0, unknown_audit

        # The global audit (no id) still contains the real session's open, so the
        # empty page above was a filter miss, not an empty log.
        global_audit = _data(await client.call_tool("audit.list", {}))
        real_ids = {e["session_id"] for e in global_audit["entries"]}
        assert sid in real_ids, global_audit
