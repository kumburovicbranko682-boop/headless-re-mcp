"""Storage failing under a live MCP server degrades honestly, never fatally.

An unattended agent talks to this server for hours, and its session store can
break in three distinct ways with three distinct right answers -- all of which
were unit-proven but never read back over the real MCP stdio transport:

* the database file goes read-only (scanner quarantine, remounted volume):
  ``session.create`` still works -- the session lives in memory -- but the
  envelope must say ``persisted: false`` and name the cause, because a session
  that silently would not survive a restart is a lie waiting for a reboot;
* the database is corrupted outright: store-backed tools must answer with a
  structured ``storage_unavailable`` envelope marked non-retryable -- the
  fault is the instance's, not the request's, and retrying can never help --
  while everything that does not touch the store keeps serving;
* the whole artifact tree is deleted (disk cleanup): the next call must
  rebuild directory and schema in place rather than failing for the life of
  the process, and the rebuilt ledger must be honest about being new.

In every case the same process heals with no restart and no operator once
storage comes back. POSIX permissions, stdio loopback, pure Python.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import struct
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="breaks the store via POSIX file permissions"
)


def _write_native_pe(path: Path) -> None:
    """A minimal 64-bit PE, enough for session.create to triage."""
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    path.write_bytes(image)


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return content


class _Mcp:
    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return _structured(await self._session.call_tool(name, args))


@asynccontextmanager
async def _mcp(artifact_root: Path) -> AsyncIterator[_Mcp]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=str(_PROJECT_ROOT),
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield _Mcp(session)


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_a_readonly_store_degrades_session_create_honestly(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_native_pe(binary)
    artifact_root = tmp_path / "artifacts"
    db_path = artifact_root / "meta" / "sessions.db"

    async with _mcp(artifact_root) as mcp:
        first = await mcp.call("session.create", {"binary": str(binary)})
        assert first["ok"] is True, first
        assert not (first.get("meta") or {}), first
        assert db_path.is_file()

        os.chmod(db_path, 0o444)
        try:
            # The session is still created -- it lives in memory and is fully
            # usable now -- but the envelope must say it would not survive a
            # restart, and why. Claiming it durable would be the lie.
            degraded = await mcp.call("session.create", {"binary": str(binary)})
            assert degraded["ok"] is True, degraded
            meta = degraded["meta"]
            assert meta["persisted"] is False, degraded
            assert "readonly" in meta["persist_error"], degraded

            # The unpersisted session is served from memory like any other.
            listed = await mcp.call("session.list", {})
            assert listed["ok"] is True, listed
            ids = {str(item["id"]) for item in listed["data"]["sessions"]}
            assert str(degraded["data"]["session"]["id"]) in ids

            # The rest of the process is unhurt.
            metrics = await mcp.call("meta.metrics", {})
            assert metrics["ok"] is True, metrics
        finally:
            os.chmod(db_path, 0o644)

        # Storage came back; the same process persists again on the next call.
        healed = await mcp.call("session.create", {"binary": str(binary)})
        assert healed["ok"] is True, healed
        assert not (healed.get("meta") or {}), healed


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_a_corrupt_store_answers_storage_unavailable_on_the_wire(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_native_pe(binary)
    artifact_root = tmp_path / "artifacts"
    db_path = artifact_root / "meta" / "sessions.db"

    async with _mcp(artifact_root) as mcp:
        created = await mcp.call("session.create", {"binary": str(binary)})
        assert created["ok"] is True, created
        session_id = str(created["data"]["session"]["id"])

        good_bytes = db_path.read_bytes()
        db_path.write_bytes(b"not a database" * 100)

        # Named over the wire, not internal_error: the client must be able to
        # tell an instance fault from a bad request. And non-retryable: a
        # corrupt file will not get better by asking again.
        refused = await mcp.call("artifacts.list", {"session_id": session_id})
        assert refused["ok"] is False, refused
        assert refused["error"]["code"] == "storage_unavailable", refused
        assert refused["error"]["retryable"] is False, refused

        # One subsystem is hurt, not the server: the connection still answers.
        metrics = await mcp.call("meta.metrics", {})
        assert metrics["ok"] is True, metrics

        # An operator replacing the file from backup is all it takes; the
        # same process picks it up on the next call.
        db_path.write_bytes(good_bytes)
        healed = await mcp.call("artifacts.list", {"session_id": session_id})
        assert healed["ok"] is True, healed


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_a_deleted_artifact_root_is_rebuilt_by_the_next_call(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_native_pe(binary)
    artifact_root = tmp_path / "artifacts"

    async with _mcp(artifact_root) as mcp:
        first = await mcp.call("session.create", {"binary": str(binary)})
        assert first["ok"] is True, first
        first_id = str(first["data"]["session"]["id"])

        # The disk-cleanup case: everything under the artifact root vanishes
        # while the server is live -- database, session directories, all of it.
        shutil.rmtree(artifact_root)

        # The connect path rebuilds directory and schema rather than failing
        # every later call for the life of the process.
        rebuilt = await mcp.call("session.create", {"binary": str(binary)})
        assert rebuilt["ok"] is True, rebuilt
        assert (artifact_root / "meta" / "sessions.db").is_file()

        # The server still lists both sessions -- the in-memory registry owns
        # what this process created and losing the disk must not lose the
        # process's own working set.
        listed = await mcp.call("session.list", {})
        assert listed["ok"] is True, listed
        ids = {str(item["id"]) for item in listed["data"]["sessions"]}
        assert str(rebuilt["data"]["session"]["id"]) in ids

        # But the rebuilt ledger on disk is honest about being new: read cold,
        # it holds the post-rebuild session and does not resurrect the one
        # whose rows were destroyed with the tree.
        with sqlite3.connect(artifact_root / "meta" / "sessions.db") as conn:
            stored = {str(row[0]) for row in conn.execute("SELECT id FROM sessions")}
        assert str(rebuilt["data"]["session"]["id"]) in stored
        assert first_id not in stored
