"""Persistence across a restart: what one server process leaves for the next.

An unattended deployment restarts -- on purpose or after a crash -- and the
process that comes up is not the one that did the work. What survives that
boundary is load-bearing: an operator (or an agent) arriving at the fresh
process has to be able to account for what happened before it started, and any
artifact a finished analysis produced has to still be exactly the bytes it was.
The store is SQLite plus files under the artifact root, so a second process
pointed at the same root inherits that record; this gate proves the contract
over the real MCP stdio transport by running two server processes in sequence
against one root.

Two paths, because a clean finish and a crash leave different traces and the
server treats them differently:

* A **cleanly finished** session (opened, worked, closed) is gone from the live
  views on restart -- it is not in ``session.list`` and not in
  ``sessions.unclean`` -- but its record persists: ``audit.list`` still shows
  the create and the close, ``timeline.list`` still shows the marks, and the
  report it generated is still listed and still readable byte-for-byte with the
  same sha256 the first process reported. Content addressing that did not
  survive the restart would be a broken promise. Live-scoped reads are honest
  about the gap: ``knowledge.query`` on the now-dead session answers
  ``session_not_found`` rather than pretending.

* A session **abandoned by a crash** (left open, never closed) is hydrated back
  into the fresh registry as a dormant session, so it shows up in *both*
  ``session.list`` and ``sessions.unclean`` with its stored identity intact --
  this is how a rebooted box surfaces work that needs cleaning up. Its health
  is reported honestly: nothing is actually attached, so ``session.health``
  says ``healthy=None`` with no live backends, not a false all-clear.

Pure stdlib, stdio loopback, no backend, any platform.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from headless_re_mcp.core.service import JsonObject
from headless_re_mcp.core.store import SessionStore

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _write_native_pe(path: Path) -> Path:
    """A header-only PE64 so ``session.create`` classifies and opens it without a decompiler."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = b"PE\x00\x00" + struct.pack("<H", 0x8664) + struct.pack("<H", 0) + b"\x00" * 16
    path.write_bytes(bytes(dos) + coff + b"\x00" * 64)
    return path


@asynccontextmanager
async def _serve(root: Path) -> AsyncIterator[ClientSession]:
    """Boot one server process over ``root`` and speak MCP to it, then let it exit.

    Leaving the context closes stdin, which the server sees as EOF and shuts
    down cleanly -- the same as an operator stopping the service. A second
    ``_serve`` over the same root is therefore a genuine restart.
    """
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(root)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=_PROJECT_ROOT,
    )
    async with (
        stdio_client(params) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        yield client


def _ok(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"no structuredContent: {result!r}"
    assert content.get("ok") is True, content
    data = content["data"]
    assert isinstance(data, dict), content
    return data


def _envelope(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"no structuredContent: {result!r}"
    return content


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_finished_analysis_survives_a_restart(tmp_path: Path) -> None:
    root = (tmp_path / "state").resolve()
    binary = _write_native_pe(tmp_path / "sample.exe")
    title = "restart-canary-a91c"
    finding_key = "restart_finding_key"

    # --- First process: do a whole small analysis and close it cleanly. ---
    async with _serve(root) as client:
        session_id = str(
            _ok(await client.call_tool("session.create", {"binary": str(binary)}))["session"]["id"]
        )
        _ok(
            await client.call_tool(
                "knowledge.record",
                {
                    "session_id": session_id,
                    "kind": "function",
                    "key": finding_key,
                    "value": {"addr": "0x1000"},
                },
            )
        )
        report = _ok(
            await client.call_tool("report.generate", {"session_id": session_id, "title": title})
        )
        artifact_id = str(report["artifact_id"])
        described = _ok(await client.call_tool("artifacts.describe", {"artifact_id": artifact_id}))[
            "artifact"
        ]
        sha256 = str(described["sha256"])
        size = int(described["size"])
        _ok(await client.call_tool("session.close", {"session_id": session_id}))

    # --- Second process over the same root: the restart. ---
    async with _serve(root) as client:
        # A cleanly-closed session is in neither live view: not running here,
        # and not an abandoned open row either.
        live_ids = {s["id"] for s in _ok(await client.call_tool("session.list", {}))["sessions"]}
        assert session_id not in live_ids, live_ids
        unclean_ids = {
            s["id"] for s in _ok(await client.call_tool("sessions.unclean", {}))["sessions"]
        }
        assert session_id not in unclean_ids, unclean_ids

        # But the record of what it did survives the restart.
        audit = _ok(await client.call_tool("audit.list", {"session_id": session_id}))
        actions = {entry["action"] for entry in audit["entries"]}
        assert {"session.create", "session.close"} <= actions, audit
        assert audit["total"] >= 2, audit

        timeline = _ok(await client.call_tool("timeline.list", {"session_id": session_id}))
        events = {entry["event"] for entry in timeline["events"]}
        assert {"session.created", "session.closed"} <= events, timeline

        # The artifact it produced is still there and still exactly its bytes.
        listed = _ok(await client.call_tool("artifacts.list", {"session_id": session_id}))
        assert artifact_id in {item["id"] for item in listed["artifacts"]}, listed

        body = bytearray()
        offset = 0
        while offset < size:
            chunk_data = _ok(
                await client.call_tool(
                    "artifacts.read",
                    {"artifact_id": artifact_id, "offset": offset, "limit": 262144},
                )
            )
            chunk = bytes.fromhex(chunk_data["data"])
            if not chunk:
                break
            body.extend(chunk)
            offset += len(chunk)
        assert len(body) == size, (len(body), size)
        assert hashlib.sha256(bytes(body)).hexdigest() == sha256, (
            "artifact bytes changed across restart"
        )
        assert title.encode() in body, "report content lost across restart"

        # A live-scoped read is honest that the session is no longer running,
        # rather than serving stale data or crashing.
        knowledge = _envelope(await client.call_tool("knowledge.query", {"session_id": session_id}))
        assert knowledge["ok"] is False, knowledge
        assert knowledge["error"]["code"] == "session_not_found", knowledge


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_crash_abandoned_session_is_recoverable_after_restart(tmp_path: Path) -> None:
    root = (tmp_path / "state").resolve()
    db_path = root / "meta" / "sessions.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Stand in for a process that was killed before it could close its session:
    # an open row with no clean-close mark is exactly what a crash leaves in the
    # store. Seeding it directly (rather than killing a live server, which the
    # stdio client shuts down cleanly on the way out) keeps the fixture
    # deterministic and cross-platform; the behavior under test is entirely the
    # *fresh server's* recovery view, asserted below over MCP.
    ghost_id = "crash-abandoned-session"
    ghost_binary = str(tmp_path / "victim.exe")
    ghost_sha = "ab" * 32
    SessionStore(db_path).upsert_session(
        session_id=ghost_id,
        binary=ghost_binary,
        sha256=ghost_sha,
        architecture="x64",
        state="open",
        closed_cleanly=False,
    )

    async with _serve(root) as client:
        # Surfaced as work that was never finished: identity intact, still
        # flagged unclean.
        unclean = _ok(await client.call_tool("sessions.unclean", {}))
        ghost_rows = [row for row in unclean["sessions"] if row["id"] == ghost_id]
        assert len(ghost_rows) == 1, unclean
        ghost = ghost_rows[0]
        assert ghost["binary"] == ghost_binary, ghost
        assert ghost["sha256"] == ghost_sha, ghost
        assert ghost["architecture"] == "x64", ghost
        assert int(ghost["closed_cleanly"]) == 0, ghost

        # Hydrated back into the live registry as a dormant session, so the
        # rebooted process can act on it.
        live_ids = {s["id"] for s in _ok(await client.call_tool("session.list", {}))["sessions"]}
        assert ghost_id in live_ids, live_ids

        # Honest health: a hydrated session has nothing attached, and the probe
        # says so rather than reporting a false all-clear.
        health = _ok(await client.call_tool("session.health", {"session_id": ghost_id}))
        assert health["healthy"] is None, health
        assert health["count"] == 0, health
        assert health["backends"] == [], health
