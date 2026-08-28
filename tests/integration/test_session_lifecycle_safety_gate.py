"""Session-lifecycle misread-safety contract over a real MCP stdio server.

The tools an unattended operator reaches for to decide what to clean up are
honest but easy to misread, and a naive auto-cleaner that trusts them at face
value would delete live work. This gate pins the three traps over stdio, on a
bare box with no backend:

  * ``sessions.unclean`` is *not* a list of sessions that are safe to clean up.
    A session is marked clean only by ``session.close``, so one that is open and
    working right now appears there exactly like one abandoned by a process that
    died -- the very same id is simultaneously live in ``session.list``. Cleaning
    everything ``sessions.unclean`` returns would kill a running session. Closing
    the session is what marks it clean and drops it from the list.

  * ``session.health`` answers ``healthy: null`` when nothing is open, and null
    is not a clean bill of health. A freshly created session that has opened no
    backend is null too -- "no backend to check" is not "all backends healthy".
    A cleaner keying off a truthy ``healthy`` must not read null as true.

  * ``session.recover`` with nothing dead keeps the id: ``replaced`` is false and
    there is no ``previous_session_id``, so a caller that always expects a new id
    would treat a healthy keep as a missing replacement. An unknown id is
    ``session_not_found``, not a silent no-op that reads as success.

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


def _ids(sessions: list[dict[str, Any]]) -> set[str]:
    return {str(s["id"]) for s in sessions}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_unclean_lists_live_sessions_so_it_is_not_safe_to_clean(
    tmp_path: Path,
) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        # A fresh store has nothing unclean.
        fresh = _data(await client.call_tool("sessions.unclean", {}))
        assert fresh["sessions"] == [], fresh

        sid = await _session(client, str(pe))

        # The just-created, live, working session is already "unclean" -- clean
        # is set only by session.close -- and it is flagged closed_cleanly == 0.
        unclean = _data(await client.call_tool("sessions.unclean", {}))
        entry = next((s for s in unclean["sessions"] if str(s["id"]) == sid), None)
        assert entry is not None, unclean
        assert entry["closed_cleanly"] == 0, entry

        # The same id is simultaneously live in session.list. The overlap is the
        # whole point: acting on sessions.unclean without cross-checking
        # session.list would tear down a running session.
        live = _data(await client.call_tool("session.list", {}))
        assert sid in _ids(unclean["sessions"]) & _ids(live["sessions"]), {
            "unclean": _ids(unclean["sessions"]),
            "live": _ids(live["sessions"]),
        }

        # Closing is what marks it clean; only then does it drop off the list.
        assert _data(await client.call_tool("session.close", {"session_id": sid}))
        after = _data(await client.call_tool("sessions.unclean", {}))
        assert sid not in _ids(after["sessions"]), after


@pytest.mark.integration
@pytest.mark.asyncio
async def test_health_is_null_not_true_when_nothing_is_open(tmp_path: Path) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        # Nothing open at all: healthy is null, not a clean bill of health.
        empty = _data(await client.call_tool("session.health", {}))
        assert empty["healthy"] is None, empty
        assert empty["backends"] == [] and empty["count"] == 0, empty

        # A live session that has opened no backend is still null -- "nothing to
        # check" is not "everything healthy". A cleaner keying off a truthy
        # healthy must not read this null as true.
        sid = await _session(client, str(pe))
        health = _data(await client.call_tool("session.health", {"session_id": sid}))
        assert health["healthy"] is None, health
        assert health["healthy"] is not True, health
        assert health["backends"] == [], health


@pytest.mark.integration
@pytest.mark.asyncio
async def test_recover_keeps_the_id_when_nothing_died_and_errors_on_unknown(
    tmp_path: Path,
) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        sid = await _session(client, str(pe))

        # Nothing died, so recover keeps the id: replaced is false, the same id
        # is reused, and there is no previous_session_id. A caller that always
        # expects a fresh id would misread this healthy keep as a lost session.
        recovered = _data(await client.call_tool("session.recover", {"session_id": sid}))
        assert recovered["replaced"] is False, recovered
        assert recovered["session_id"] == sid, recovered
        assert "previous_session_id" not in recovered, recovered
        assert recovered["recovered"] == 0 and recovered["failed"] == 0, recovered

        # An id that never existed is an error, not a silent success no-op.
        unknown = _envelope(
            await client.call_tool("session.recover", {"session_id": "no-such-session"})
        )
        assert unknown.get("ok") is False, unknown
        assert _code(unknown) == "session_not_found", unknown
