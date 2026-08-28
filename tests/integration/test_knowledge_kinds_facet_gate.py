"""knowledge.query kind-facet honesty gate over a real MCP stdio server.

``knowledge.query`` is paged, and it answers with a ``kinds`` map beside the
session-wide ``total``. An agent reads ``kinds`` to decide what a session holds
and what to page in next. The facet must therefore describe the whole session,
not whichever kinds happened to land on the returned page: entries are ordered
by kind, so a small page can be entirely one kind, and a per-page tally would
report ``{"aaa": 3}`` for a session that also holds ``bbb`` -- hiding a whole
kind on a later page, the same partial-read-as-complete that ``total`` guards
against.

This pins the contract at the tool surface, over stdio, on a bare box:

  * A first page that is entirely one kind still reports every kind in the
    session, and the facet counts sum to ``total``.
  * A later page reports the identical facet.
  * A kind-filtered query reports only that kind, with ``total`` matching.

Pure-stdlib fixture, stdio loopback, no backend, any platform.
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


def _write_pe(path: Path) -> Path:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    optional = 0x98
    image[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    image[optional + 24 : optional + 32] = (0x180000000).to_bytes(8, "little")
    image[optional + 56 : optional + 60] = (0x5000).to_bytes(4, "little")
    path.write_bytes(image)
    return path


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


@pytest.mark.integration
@pytest.mark.asyncio
async def test_knowledge_kinds_describe_the_session_not_the_page(tmp_path: Path) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        created = _data(await client.call_tool("session.create", {"binary": str(pe)}))
        session_id = created["session"]["id"]

        # Two kinds; "aaa" outnumbers a page so the first page is all "aaa".
        for index in range(3):
            recorded = _envelope(
                await client.call_tool(
                    "knowledge.record",
                    {
                        "session_id": session_id,
                        "kind": "aaa",
                        "key": f"a{index}",
                        "value": {"i": index},
                    },
                )
            )
            assert recorded.get("ok") is True, recorded
        for index in range(2):
            recorded = _envelope(
                await client.call_tool(
                    "knowledge.record",
                    {
                        "session_id": session_id,
                        "kind": "bbb",
                        "key": f"b{index}",
                        "value": {"i": index},
                    },
                )
            )
            assert recorded.get("ok") is True, recorded

        first = _data(
            await client.call_tool(
                "knowledge.query", {"session_id": session_id, "offset": 0, "limit": 3}
            )
        )
        assert [entry["kind"] for entry in first["entries"]] == ["aaa", "aaa", "aaa"]
        assert first["total"] == 5
        assert first["kinds"] == {"aaa": 3, "bbb": 2}
        assert sum(first["kinds"].values()) == first["total"]

        second = _data(
            await client.call_tool(
                "knowledge.query", {"session_id": session_id, "offset": 3, "limit": 3}
            )
        )
        assert second["kinds"] == {"aaa": 3, "bbb": 2}

        only_bbb = _data(
            await client.call_tool(
                "knowledge.query", {"session_id": session_id, "kind": "bbb"}
            )
        )
        assert only_bbb["kinds"] == {"bbb": 2}
        assert only_bbb["total"] == 2
