"""wasm.summary over real MCP stdio: WASM structure without wabt.

wasm.info / wasm.wat drive the wabt CLI, so the WebAssembly surface is
capability_unavailable on a host without wabt. wasm.summary parses the module
format with the stdlib alone, so it always answers. This gate drives the real
stdio server end to end on a hand-assembled module and pins the round trip: the
tool is advertised, it returns the section layout with import/export tables and
custom section names, a non-module fails with invalid_params rather than an
internal fault, and none of it needs an analysis backend, so it always runs.
"""

from __future__ import annotations

import asyncio
import os
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


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _module() -> bytes:
    header = b"\x00asm\x01\x00\x00\x00"
    types = _section(1, _vec([b"\x60\x00\x00"]))
    imports = _section(
        2,
        _vec(
            [
                _name("wasi_snapshot_preview1") + _name("fd_write") + b"\x00" + _uleb(0),
                _name("env") + _name("memory") + b"\x02" + b"\x00" + _uleb(1),
            ]
        ),
    )
    functions = _section(3, _vec([_uleb(0)]))
    exports = _section(7, _vec([_name("_start") + b"\x00" + _uleb(1)]))
    code = _section(10, _vec([_uleb(2) + b"\x00\x0b"]))
    custom = _section(0, _name("name"))
    return header + types + imports + functions + exports + code + custom


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return {str(key): item for key, item in content.items()}


async def _call(client: ClientSession, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    return _structured(await asyncio.wait_for(client.call_tool(tool, args), timeout=60))


@pytest.mark.asyncio
async def test_mcp_stdio_wasm_summary(tmp_path: Path) -> None:
    module = tmp_path / "app.wasm"
    module.write_bytes(_module())
    junk = tmp_path / "not.wasm"
    junk.write_text("<html>not a module</html>", encoding="utf-8")

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
        assert "wasm.summary" in tools

        good = await _call(client, "wasm.summary", {"path": str(module)})
        assert good["ok"] is True, good
        data = good["data"]
        assert data["version"] == 1
        assert data["counts"]["imports"] == 2
        assert {i["name"] for i in data["imports"]} == {"fd_write", "memory"}
        assert data["exports"][0]["name"] == "_start"
        assert data["has_names_section"] is True

        bad = await _call(client, "wasm.summary", {"path": str(junk)})
        assert bad["ok"] is False
        assert bad["error"]["code"] == "invalid_params"
