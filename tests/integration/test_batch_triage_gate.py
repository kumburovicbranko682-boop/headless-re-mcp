"""Bulk triage with batch.analyze: one bad sample must not sink the batch.

Unattended triage points ``batch.analyze`` at a folder of samples and walks
away. The load-bearing property is fault isolation: a corpus always has a dud
in it -- a path that moved, a file that is not really a PE -- and the run has to
open everything it can and *report* what it could not, rather than aborting the
whole batch on the first failure. If one bad input could stop the run, the tool
would be useless for the exact job it exists for.

The existing composite-tools gate that covers this is Windows-only, so on Linux
the batch path had no end-to-end coverage. This gate drives the real MCP stdio
server with ``open_static=False`` (so it needs no decompiler) and proves:

* Fault isolation and honest accounting: a mixed batch of two valid PEs, a
  missing path, and a non-PE file returns ``ok`` at the call level with
  ``succeeded=2`` / ``failed=2`` / ``count=4``, one entry per input, each good
  one carrying a session id and each bad one carrying a specific error code
  (``file_not_found`` for the missing path, ``invalid_request`` for the non-PE)
  -- not a single opaque failure for the whole call.
* The successes are real, first-class sessions, not just claims: the ids the
  batch reports are live in ``session.list``, ``session.get`` resolves them, and
  a follow-up ``report.generate`` on one of them produces an artifact.
* A batch in which *every* input is bad still succeeds as a call, with
  ``succeeded=0`` and an error per entry -- "every sample failed" is a
  different, reportable outcome from "the batch call failed".

Pure stdlib, stdio loopback, no backend, any platform.
"""

from __future__ import annotations

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

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _write_native_pe(path: Path) -> Path:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = b"PE\x00\x00" + struct.pack("<H", 0x8664) + struct.pack("<H", 0) + b"\x00" * 16
    path.write_bytes(bytes(dos) + coff + b"\x00" * 64)
    return path


@asynccontextmanager
async def _mcp(tmp_path: Path) -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")
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


def _data(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"no structuredContent: {result!r}"
    assert content.get("ok") is True, content
    data = content["data"]
    assert isinstance(data, dict), content
    return data


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_bad_sample_does_not_sink_the_batch(tmp_path: Path) -> None:
    good_one = _write_native_pe(tmp_path / "good_one.exe")
    good_two = _write_native_pe(tmp_path / "good_two.exe")
    missing = str(tmp_path / "moved_away.exe")
    not_a_pe = tmp_path / "notes.txt"
    not_a_pe.write_bytes(b"this is not a PE at all")

    # Order matters to the assertion: entries are matched back to inputs by path.
    inputs = [str(good_one), str(good_two), missing, str(not_a_pe)]

    async with _mcp(tmp_path) as client:
        batch = _data(
            await client.call_tool(
                "batch.analyze", {"binaries": inputs, "max_workers": 2, "open_static": False}
            )
        )
        assert batch["count"] == 4, batch
        assert batch["succeeded"] == 2, batch
        assert batch["failed"] == 2, batch
        assert batch["max_workers"] == 2, batch

        by_binary = {entry["binary"]: entry for entry in batch["entries"]}
        assert set(by_binary) == set(inputs), by_binary

        # The two real PEs opened, each with its own session id.
        good_ids = []
        for path in (str(good_one), str(good_two)):
            entry = by_binary[path]
            assert entry["ok"] is True, entry
            assert entry["session_id"], entry
            good_ids.append(entry["session_id"])
        assert len(set(good_ids)) == 2, good_ids

        # The duds failed with specific, distinguishable reasons -- not one
        # opaque batch-level error.
        assert by_binary[missing]["ok"] is False, by_binary[missing]
        assert by_binary[missing]["error"]["code"] == "file_not_found", by_binary[missing]
        assert by_binary[str(not_a_pe)]["ok"] is False, by_binary[str(not_a_pe)]
        assert by_binary[str(not_a_pe)]["error"]["code"] == "invalid_request", by_binary[
            str(not_a_pe)
        ]

        # The successes are live sessions the server actually holds, not just
        # ids in a report.
        live_ids = {s["id"] for s in _data(await client.call_tool("session.list", {}))["sessions"]}
        assert set(good_ids) <= live_ids, (good_ids, live_ids)
        for session_id in good_ids:
            fetched = _data(await client.call_tool("session.get", {"session_id": session_id}))
            assert fetched["session"]["target"] == "pe", fetched


@pytest.mark.integration
@pytest.mark.asyncio
async def test_batch_sessions_are_usable_and_all_bad_still_reports(tmp_path: Path) -> None:
    sample = _write_native_pe(tmp_path / "sample.exe")
    async with _mcp(tmp_path) as client:
        batch = _data(
            await client.call_tool(
                "batch.analyze", {"binaries": [str(sample)], "open_static": False}
            )
        )
        assert batch["succeeded"] == 1, batch
        session_id = batch["entries"][0]["session_id"]
        assert session_id, batch

        # A session the batch opened is a first-class session: a follow-up write
        # tool works against it.
        report = _data(await client.call_tool("report.generate", {"session_id": session_id}))
        assert isinstance(report["artifact_id"], str) and report["artifact_id"], report

        # Every input bad is still a successful call that reports each failure,
        # rather than the batch itself erroring out.
        all_bad = _data(
            await client.call_tool(
                "batch.analyze",
                {
                    "binaries": [str(tmp_path / "x.exe"), str(tmp_path / "y.exe")],
                    "open_static": False,
                },
            )
        )
        assert all_bad["succeeded"] == 0, all_bad
        assert all_bad["failed"] == 2, all_bad
        for entry in all_bad["entries"]:
            assert entry["ok"] is False, entry
            assert entry["error"]["code"] == "file_not_found", entry
