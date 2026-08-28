"""dex.summary over real MCP stdio: a standalone .dex is a first-class thing to read.

The apk.* tools drive androguard against an APK container; a lone .dex had no
reader here, and androguard is not always installed. The DEX header and string
table are an exact binary format that reads with the stdlib alone. This gate
drives the real stdio server end to end on a hand-assembled DEX and pins the
round trip: dex.summary is advertised, it returns the section counts and a
paginated string page, and a file that is not a DEX fails with invalid_params
rather than an internal fault. It needs no analysis backend, so it always runs.
"""

from __future__ import annotations

import asyncio
import os
import struct
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.integration


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _build_dex(strings: list[str]) -> bytes:
    header_size = 0x70
    string_ids_off = header_size
    data_start = string_ids_off + len(strings) * 4
    blobs = bytearray()
    offsets: list[int] = []
    for text in strings:
        offsets.append(data_start + len(blobs))
        blobs += _uleb(len(text)) + text.encode("utf-8") + b"\x00"
    string_ids = b"".join(struct.pack("<I", off) for off in offsets)
    body = string_ids + bytes(blobs)
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x08, 0x1234ABCD)
    header[0x0C:0x20] = bytes(range(20))
    fields = [
        header_size + len(body), header_size, 0x12345678, 0, 0, 0,
        len(strings), string_ids_off,
        3, 0, 2, 0, 4, 0, 5, 0, 1, 0, 0, 0,
    ]
    struct.pack_into("<20I", header, 0x20, *fields)
    return bytes(header) + body


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return {str(key): item for key, item in content.items()}


async def _call(client: ClientSession, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    return _structured(await asyncio.wait_for(client.call_tool(tool, args), timeout=60))


@pytest.mark.asyncio
async def test_mcp_stdio_dex_summary(tmp_path: Path) -> None:
    strings = ["Lcom/example/Foo;", "hello", "<init>", "https://evil.example/c2"]
    dex = tmp_path / "classes.dex"
    dex.write_bytes(_build_dex(strings))
    junk = tmp_path / "bad.dex"
    junk.write_bytes(b"not a dalvik executable at all")

    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=os.environ.copy(),
        cwd=str(_PROJECT_ROOT),
    )

    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        tools = {tool.name for tool in (await client.list_tools()).tools}
        assert "dex.summary" in tools

        full = await _call(client, "dex.summary", {"path": str(dex)})
        assert full["ok"] is True, full
        data = full["data"]
        assert data["version"] == "035"
        assert data["counts"]["strings"] == 4
        assert data["counts"]["methods"] == 5
        assert "Lcom/example/Foo;" in data["strings"]

        page = await _call(client, "dex.summary", {"path": str(dex), "offset": 0, "limit": 2})
        assert page["data"]["strings_count"] == 2
        assert page["data"]["strings_total"] == 4
        assert page["data"]["has_more"] is True

        bad = await _call(client, "dex.summary", {"path": str(junk)})
        assert bad["ok"] is False
        assert bad["error"]["code"] == "invalid_params"
