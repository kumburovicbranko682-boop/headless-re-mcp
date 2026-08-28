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


def _build_dex(
    strings: list[str],
    types: list[int] | None = None,
    classes: list[dict[str, int | None]] | None = None,
) -> bytes:
    """A DEX with a string table and, optionally, real type and class_def tables."""
    types = types or []
    classes = classes or []
    no_index = 0xFFFFFFFF
    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + len(strings) * 4
    class_defs_off = type_ids_off + len(types) * 4
    data_start = class_defs_off + len(classes) * 32
    blobs = bytearray()
    offsets: list[int] = []
    for text in strings:
        offsets.append(data_start + len(blobs))
        blobs += _uleb(len(text)) + text.encode("utf-8") + b"\x00"
    string_ids = b"".join(struct.pack("<I", off) for off in offsets)
    type_ids = b"".join(struct.pack("<I", t) for t in types)
    class_defs = bytearray()
    for cls in classes:
        super_type = cls.get("super_type")
        source = cls.get("source")
        class_defs += struct.pack(
            "<8I",
            int(cls["class_type"] or 0),
            int(cls.get("access") or 0),
            no_index if super_type is None else int(super_type),
            0,
            no_index if source is None else int(source),
            0,
            0,
            0,
        )
    body = string_ids + type_ids + bytes(class_defs) + bytes(blobs)
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x08, 0x1234ABCD)
    header[0x0C:0x20] = bytes(range(20))
    fields = [
        header_size + len(body), header_size, 0x12345678, 0, 0, 0,
        len(strings), string_ids_off,
        len(types), type_ids_off,
        0, 0, 0, 0, 0, 0,
        len(classes), class_defs_off,
        0, 0,
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
    strings = [
        "Lcom/example/Foo;",
        "Landroid/app/Activity;",
        "Foo.java",
        "https://evil.example/c2",
    ]
    types = [0, 1]
    classes: list[dict[str, int | None]] = [
        {"class_type": 0, "access": 0x1 | 0x10, "super_type": 1, "source": 2},
    ]
    dex = tmp_path / "classes.dex"
    dex.write_bytes(_build_dex(strings, types, classes))
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
        assert "dex.classes" in tools

        full = await _call(client, "dex.summary", {"path": str(dex)})
        assert full["ok"] is True, full
        data = full["data"]
        assert data["version"] == "035"
        assert data["counts"]["strings"] == 4
        assert data["counts"]["classes"] == 1
        assert "Lcom/example/Foo;" in data["strings"]

        page = await _call(client, "dex.summary", {"path": str(dex), "offset": 0, "limit": 2})
        assert page["data"]["strings_count"] == 2
        assert page["data"]["strings_total"] == 4
        assert page["data"]["has_more"] is True

        listing = await _call(client, "dex.classes", {"path": str(dex)})
        assert listing["ok"] is True, listing
        klass = listing["data"]["classes"][0]
        assert klass["name"] == "com.example.Foo"
        assert klass["superclass"] == "Landroid/app/Activity;"
        assert "public" in klass["access_flags"]
        assert klass["source_file"] == "Foo.java"

        bad = await _call(client, "dex.summary", {"path": str(junk)})
        assert bad["ok"] is False
        assert bad["error"]["code"] == "invalid_params"

        bad_classes = await _call(client, "dex.classes", {"path": str(junk)})
        assert bad_classes["ok"] is False
        assert bad_classes["error"]["code"] == "invalid_params"
