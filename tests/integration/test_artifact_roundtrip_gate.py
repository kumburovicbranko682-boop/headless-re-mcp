"""Artifact content-addressing: the reference an agent hands around must resolve.

When a reply is too big to inline, the server registers it as an artifact and
answers with an ``artifact_id`` instead. The agent then carries that id around
and passes it to later calls rather than the bytes -- the fault-contract path
literally tells a runaway model to "send a reference such as an artifact_id".
That indirection is only safe if the id resolves back to *exactly* the bytes it
named: same length, same sha256, readable in pieces, and listed under the
session that made it and no other. This gate proves that round trip end to end
over the real MCP stdio transport.

It uses ``report.generate`` as the producer because it makes a real artifact
from pure session state -- findings and audit rendered to Markdown -- so the
whole gate runs without any decompiler or backend. The properties proven:

* The report is a content-addressed artifact: ``report.generate`` returns an
  ``artifact_id`` and byte count, ``artifacts.describe`` gives a matching size
  and a sha256, and the report reflects real state (the title and a recorded
  finding both appear in the bytes).
* Reading resolves the id to the exact bytes: ``artifacts.read`` fetched in
  small offset windows reassembles to content whose length and sha256 match
  what ``describe`` declared, and that content equals the inline preview the
  producer already returned. Reading at EOF yields nothing; an unknown id is
  ``not_found`` rather than a crash or empty success.
* Listing is scoped: ``artifacts.list(session_id=...)`` returns only that
  session's artifacts, while the unscoped list sees every session's -- an
  agent juggling two targets must not have one session's outputs bleed into
  the other's.

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


def _ok(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"no structuredContent: {result!r}"
    assert content.get("ok") is True, content
    data = content["data"]
    assert isinstance(data, dict), content
    return data


async def _open_pe_session(client: ClientSession, path: Path) -> str:
    data = _ok(await client.call_tool("session.create", {"binary": str(path)}))
    session = data["session"]
    assert session["target"] == "pe", session
    return str(session["id"])


async def _read_all(client: ClientSession, artifact_id: str, size: int) -> bytes:
    """Reassemble an artifact from small offset windows to prove paging is exact."""
    collected = bytearray()
    offset = 0
    # A window smaller than the artifact forces several reads, so the test
    # exercises offset arithmetic rather than one convenient whole-file read.
    window = 256
    while offset < size:
        data = _ok(
            await client.call_tool(
                "artifacts.read",
                {"artifact_id": artifact_id, "offset": offset, "limit": window},
            )
        )
        assert data["encoding"] == "hex", data
        chunk = bytes.fromhex(data["data"])
        if not chunk:
            break
        collected.extend(chunk)
        offset += len(chunk)
    return bytes(collected)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_report_is_a_content_addressed_artifact(tmp_path: Path) -> None:
    title = "canary-report-title-7f3a"
    finding_key = "canary_finding_5d21"
    async with _mcp(tmp_path) as client:
        session_id = await _open_pe_session(client, _write_native_pe(tmp_path / "sample.exe"))

        recorded = _ok(
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
        assert recorded["replaced"] is False, recorded

        report = _ok(
            await client.call_tool("report.generate", {"session_id": session_id, "title": title})
        )
        artifact_id = report["artifact_id"]
        assert isinstance(artifact_id, str) and artifact_id, report
        assert report["truncated"] is False, report  # small report is inline in full
        inline = report["markdown"]
        declared_bytes = report["bytes"]

        described = _ok(await client.call_tool("artifacts.describe", {"artifact_id": artifact_id}))
        artifact = described["artifact"]
        assert artifact["id"] == artifact_id, artifact
        assert artifact["session_id"] == session_id, artifact
        assert artifact["kind"] == "report_markdown", artifact
        assert artifact["source"] == "report.generate", artifact
        size = artifact["size"]
        assert size == declared_bytes, (size, declared_bytes)
        sha256 = artifact["sha256"]
        assert isinstance(sha256, str) and len(sha256) == 64, artifact

        body = await _read_all(client, artifact_id, size)
        # The id resolves to exactly the bytes it named: length and digest both.
        assert len(body) == size, (len(body), size)
        assert hashlib.sha256(body).hexdigest() == sha256, "read bytes do not match declared sha256"
        # The inline preview the producer returned is the same content, since a
        # report this small is not truncated.
        assert body.decode("utf-8") == inline, "inline markdown differs from stored artifact"
        # And the report is of real state, not a stub: the title and the finding
        # the session recorded both survive into the rendered bytes.
        assert title.encode() in body, "title missing from report"
        assert finding_key.encode() in body, "recorded finding missing from report"

        # Reading from the end returns nothing rather than an error or a wrap.
        eof = _ok(
            await client.call_tool(
                "artifacts.read", {"artifact_id": artifact_id, "offset": size, "limit": 4096}
            )
        )
        assert bytes.fromhex(eof["data"]) == b"", eof

        # An id that names nothing is a clean not_found on both read paths.
        for tool in ("artifacts.read", "artifacts.describe"):
            missing = await client.call_tool(tool, {"artifact_id": "no-such-artifact"})
            envelope = getattr(missing, "structuredContent", None)
            assert isinstance(envelope, dict) and envelope["ok"] is False, (tool, envelope)
            assert envelope["error"]["code"] == "not_found", (tool, envelope)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_artifact_listing_is_scoped_to_its_session(tmp_path: Path) -> None:
    async with _mcp(tmp_path) as client:
        session_a = await _open_pe_session(client, _write_native_pe(tmp_path / "a.exe"))
        session_b = await _open_pe_session(client, _write_native_pe(tmp_path / "b.exe"))

        artifact_a = _ok(
            await client.call_tool(
                "report.generate", {"session_id": session_a, "title": "report-a"}
            )
        )["artifact_id"]
        artifact_b = _ok(
            await client.call_tool(
                "report.generate", {"session_id": session_b, "title": "report-b"}
            )
        )["artifact_id"]
        assert artifact_a != artifact_b

        listed_a = _ok(await client.call_tool("artifacts.list", {"session_id": session_a}))
        ids_a = {item["id"] for item in listed_a["artifacts"]}
        assert ids_a == {artifact_a}, listed_a
        assert listed_a["count"] == 1 and listed_a["total"] == 1, listed_a
        assert listed_a["has_more"] is False, listed_a

        listed_b = _ok(await client.call_tool("artifacts.list", {"session_id": session_b}))
        ids_b = {item["id"] for item in listed_b["artifacts"]}
        assert ids_b == {artifact_b}, listed_b

        # One session's output never appears under the other's scope.
        assert artifact_b not in ids_a
        assert artifact_a not in ids_b

        # The unscoped list is the union: an operator auditing the whole process
        # sees every session's artifacts in one place.
        listed_all = _ok(await client.call_tool("artifacts.list", {}))
        ids_all = {item["id"] for item in listed_all["artifacts"]}
        assert {artifact_a, artifact_b} <= ids_all, listed_all
        assert listed_all["total"] >= 2, listed_all
