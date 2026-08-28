"""js.webext over real MCP stdio: a browser extension is a first-class thing to read.

Browser extensions are a real Web-RE target (a common malware vector), yet
nothing here could open one. A Chrome .crx is a small header plus a ZIP and a
Firefox .xpi is a plain ZIP; both carry a manifest.json permission surface. This
gate drives the real stdio server end to end and pins the round trip: js.webext
is advertised, it reads a .crx's manifest and file listing, it reads a plain-zip
.xpi, and a file that is not a readable archive fails with invalid_params rather
than an internal fault. It needs no analysis backend, so it always runs.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.integration

_MANIFEST = {
    "manifest_version": 3,
    "name": "Gate Ext",
    "version": "2.0.0",
    "permissions": ["storage", "webRequest"],
    "host_permissions": ["*://*/*"],
    "background": {"service_worker": "sw.js"},
    "content_scripts": [{"matches": ["*://*/*"], "js": ["cs.js"]}],
}


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(_MANIFEST))
        archive.writestr("sw.js", "self.addEventListener('install', () => {})")
        archive.writestr("cs.js", "// content script")
        archive.writestr("mod.wasm", b"\x00asm\x01\x00\x00\x00")
    return buf.getvalue()


def _crx3(zip_bytes: bytes) -> bytes:
    header = b"\x0a\x04demo"
    return b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", len(header)) + header + zip_bytes


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return {str(key): item for key, item in content.items()}


async def _call(client: ClientSession, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    return _structured(await asyncio.wait_for(client.call_tool(tool, args), timeout=60))


@pytest.mark.asyncio
async def test_mcp_stdio_js_webext(tmp_path: Path) -> None:
    zip_bytes = _zip_bytes()
    crx = tmp_path / "demo.crx"
    crx.write_bytes(_crx3(zip_bytes))
    xpi = tmp_path / "demo.xpi"
    xpi.write_bytes(zip_bytes)
    junk = tmp_path / "bad.crx"
    junk.write_bytes(b"not an archive")

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
        assert "js.webext" in tools

        crx_out = await _call(client, "js.webext", {"path": str(crx)})
        assert crx_out["ok"] is True, crx_out
        data = crx_out["data"]
        assert data["format"] == "crx"
        assert data["crx_version"] == 3
        assert data["is_extension"] is True
        assert data["manifest"]["name"] == "Gate Ext"
        assert data["manifest"]["permissions"] == ["storage", "webRequest"]
        assert data["manifest"]["background"] == {"type": "service_worker", "value": "sw.js"}
        assert data["suffix_counts"]["wasm"] == 1

        xpi_out = await _call(client, "js.webext", {"path": str(xpi)})
        assert xpi_out["ok"] is True, xpi_out
        assert xpi_out["data"]["format"] == "zip"
        assert xpi_out["data"]["is_extension"] is True

        bad = await _call(client, "js.webext", {"path": str(junk)})
        assert bad["ok"] is False
        assert bad["error"]["code"] == "invalid_params"
