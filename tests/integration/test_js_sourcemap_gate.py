"""js.sourcemap over real MCP stdio: a source map is a first-class thing to read.

js.deobfuscate / js.beautify / js.unpack_bundle drive the webcrack (Node) CLI,
so the JS surface is capability_unavailable on a host without it. A source map
is plain JSON and reads with the stdlib alone, yet nothing here could open one.
This gate drives the real stdio server end to end and pins the round trip:
js.sourcemap is advertised, it summarises a flat map (naming the original file
tree and flagging which sources embed their content), it aggregates a v3 index
map's sections, and a file that is not a source map fails with invalid_params
rather than an internal fault. It needs no analysis backend, so it always runs.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.integration


def _flat_map() -> str:
    return json.dumps(
        {
            "version": 3,
            "file": "app.min.js",
            "sourceRoot": "webpack://app/",
            "sources": ["src/index.ts", "src/util.ts", "node_modules/lib/x.js"],
            "sourcesContent": ["export const a = 1\n", None, "module.exports = {}"],
            "names": ["a", "b", "c"],
            "mappings": "AAAA,SAASA;;AACT,MAAMC",
            "x_google_ignoreList": [2],
        }
    )


def _index_map() -> str:
    return json.dumps(
        {
            "version": 3,
            "file": "bundle.js",
            "sections": [
                {
                    "offset": {"line": 0, "column": 0},
                    "map": {"version": 3, "sources": ["a.ts"], "sourcesContent": ["x"],
                            "names": [], "mappings": "AAAA"},
                },
                {
                    "offset": {"line": 10, "column": 0},
                    "map": {"version": 3, "sources": ["b.ts", "c.ts"],
                            "sourcesContent": [None, "y"], "names": ["n"], "mappings": "AAAA;AACA"},
                },
            ],
        }
    )


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return {str(key): item for key, item in content.items()}


async def _call(client: ClientSession, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    return _structured(await asyncio.wait_for(client.call_tool(tool, args), timeout=60))


@pytest.mark.asyncio
async def test_mcp_stdio_js_sourcemap(tmp_path: Path) -> None:
    flat = tmp_path / "app.js.map"
    flat.write_text(_flat_map(), encoding="utf-8")
    index = tmp_path / "bundle.js.map"
    index.write_text(_index_map(), encoding="utf-8")
    junk = tmp_path / "bad.map"
    junk.write_text("<<not json>>", encoding="utf-8")

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
        assert "js.sourcemap" in tools

        good = await _call(client, "js.sourcemap", {"path": str(flat)})
        assert good["ok"] is True, good
        data = good["data"]
        assert data["version"] == 3
        assert data["is_index_map"] is False
        assert data["sources_total"] == 3
        assert data["sources_content_embedded"] == 2
        assert data["generated_lines"] == 3
        assert data["ignore_list"] == [2]
        embedded = {d["source"]: d["has_content"] for d in data["sources_detail"]}
        assert embedded["src/index.ts"] is True
        assert embedded["src/util.ts"] is False

        idx = await _call(client, "js.sourcemap", {"path": str(index)})
        assert idx["ok"] is True, idx
        assert idx["data"]["is_index_map"] is True
        assert idx["data"]["section_count"] == 2
        assert idx["data"]["sources"] == ["a.ts", "b.ts", "c.ts"]

        bad = await _call(client, "js.sourcemap", {"path": str(junk)})
        assert bad["ok"] is False
        assert bad["error"]["code"] == "invalid_params"
