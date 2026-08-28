"""The knowledge store: a session's durable memory, and what it promises.

Multi-step analysis -- especially an agent's -- leans on ``knowledge.record`` /
``knowledge.query`` to remember what it has learned: this function is the entry
point, that API is imported, this struct is 16 bytes. For that memory to be
usable it has to behave like a store, not a log: recording the same fact twice
must correct it in place rather than pile up duplicates, facts must group by
kind so a later step can ask "what functions do we know?", one session's notes
must never bleed into another's, and what was learned has to reach the report
the run produces. None of it needs a decompiler, so it should be provable on a
bare box -- and yet there was no end-to-end gate for it. This one drives the
real MCP stdio server and pins the contract.

* Idempotent upsert, grouped by kind: recording ``function/main`` twice leaves
  one row with the second value and the original ``created_at`` (``replaced``
  goes false then true); ``knowledge.query`` totals the distinct facts, groups
  them by kind with counts, filters to one kind on request, and round-trips the
  stored value the recorder was told is not echoed back on write.
* Scoped and reported: facts recorded in one session are invisible in another,
  and the ones a session holds show up in its ``report.generate`` output (both
  the finding count and the rendered Markdown), while a session with no facts
  still reports cleanly with a finding count of zero.

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


async def _open_pe(client: ClientSession, path: Path) -> str:
    return str(
        _data(await client.call_tool("session.create", {"binary": str(path)}))["session"]["id"]
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_knowledge_is_an_idempotent_upsert_grouped_by_kind(tmp_path: Path) -> None:
    async with _mcp(tmp_path) as client:
        session_id = await _open_pe(client, _write_native_pe(tmp_path / "sample.exe"))

        first = _data(
            await client.call_tool(
                "knowledge.record",
                {
                    "session_id": session_id,
                    "kind": "function",
                    "key": "main",
                    "value": {"addr": "0x1000"},
                },
            )
        )
        assert first["replaced"] is False, first
        assert first["created_at"] == first["updated_at"], first

        _data(
            await client.call_tool(
                "knowledge.record",
                {
                    "session_id": session_id,
                    "kind": "api",
                    "key": "CreateFileW",
                    "value": {"dll": "kernel32"},
                },
            )
        )
        _data(
            await client.call_tool(
                "knowledge.record",
                {"session_id": session_id, "kind": "struct", "key": "Foo", "value": {"size": 16}},
            )
        )

        # Recording the same kind+key again corrects the fact in place.
        second = _data(
            await client.call_tool(
                "knowledge.record",
                {
                    "session_id": session_id,
                    "kind": "function",
                    "key": "main",
                    "value": {"addr": "0x2000"},
                },
            )
        )
        assert second["replaced"] is True, second
        assert second["created_at"] == first["created_at"], second  # birth time preserved
        assert second["updated_at"] >= first["updated_at"], second  # touch time advances

        # The re-record did not add a row: three distinct facts, grouped by kind.
        everything = _data(await client.call_tool("knowledge.query", {"session_id": session_id}))
        assert everything["total"] == 3, everything
        assert everything["kinds"] == {"api": 1, "function": 1, "struct": 1}, everything
        by_key = {entry["key"]: entry for entry in everything["entries"]}
        # Values round-trip, and the function reflects the corrected value.
        assert by_key["main"]["value"] == {"addr": "0x2000"}, by_key["main"]
        assert by_key["CreateFileW"]["value"] == {"dll": "kernel32"}, by_key["CreateFileW"]
        assert by_key["Foo"]["value"] == {"size": 16}, by_key["Foo"]

        # Filtering narrows to one kind.
        functions = _data(
            await client.call_tool(
                "knowledge.query", {"session_id": session_id, "kind": "function"}
            )
        )
        assert functions["total"] == 1, functions
        assert functions["kinds"] == {"function": 1}, functions
        assert functions["entries"][0]["value"] == {"addr": "0x2000"}, functions

        # A kind nobody recorded is an empty answer, not an error.
        none = _data(
            await client.call_tool(
                "knowledge.query", {"session_id": session_id, "kind": "nonesuch"}
            )
        )
        assert none["total"] == 0, none
        assert none["entries"] == [], none


@pytest.mark.integration
@pytest.mark.asyncio
async def test_knowledge_is_scoped_per_session_and_reaches_the_report(tmp_path: Path) -> None:
    async with _mcp(tmp_path) as client:
        session_a = await _open_pe(client, _write_native_pe(tmp_path / "a.exe"))
        session_b = await _open_pe(client, _write_native_pe(tmp_path / "b.exe"))

        _data(
            await client.call_tool(
                "knowledge.record",
                {
                    "session_id": session_a,
                    "kind": "api",
                    "key": "VirtualAlloc",
                    "value": {"dll": "kernel32"},
                },
            )
        )
        _data(
            await client.call_tool(
                "knowledge.record",
                {
                    "session_id": session_a,
                    "kind": "function",
                    "key": "decrypt_blob",
                    "value": {"addr": "0x1400"},
                },
            )
        )

        # Session B never learned any of it.
        assert (
            _data(await client.call_tool("knowledge.query", {"session_id": session_b}))["total"]
            == 0
        )

        # Session A's facts reach its report: both the count and the text.
        report_a = _data(
            await client.call_tool("report.generate", {"session_id": session_a, "title": "A"})
        )
        assert report_a["findings"] == 2, report_a
        assert "VirtualAlloc" in report_a["markdown"], "recorded api missing from report"
        assert "decrypt_blob" in report_a["markdown"], "recorded function missing from report"

        # A session with nothing learned still reports cleanly, at zero findings.
        report_b = _data(
            await client.call_tool("report.generate", {"session_id": session_b, "title": "B"})
        )
        assert report_b["findings"] == 0, report_b
        assert isinstance(report_b["artifact_id"], str) and report_b["artifact_id"], report_b
