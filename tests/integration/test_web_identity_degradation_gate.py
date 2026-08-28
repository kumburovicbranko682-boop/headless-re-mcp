"""Web line over the wire: it stands up, and it degrades honestly, without a browser.

The existing Web gate is real only when Chrome, webcrack, and wabt are present;
on a bare machine all of it skips, so the behaviour an agent actually meets on a
box without those backends -- the common case for a first contact with a web
target -- is unproven. That behaviour is the whole contract: a web session opens
with nothing installed, and every heavier tool answers with a structured
envelope an agent can reason about rather than a crash, a protocol error, or a
tool that quietly vanished.

This gate drives the real MCP stdio transport against a server with no browser
and no JS/WASM backends, and pins:

* Identity needs no backend: a ``.js`` file and an ``http`` URL each open as a
  ``web`` session, no network and no Chrome required.
* The static file tools degrade to a structured envelope: ``js.*`` and
  ``wasm.*`` report ``capability_unavailable`` when webcrack / wabt are absent,
  never a raise, and a non-WebAssembly input is still handled cleanly.
* The browser tools tell an agent to open a browser first: ``web.scripts`` and
  its siblings return ``invalid_state`` (not a crash) when nothing is open, this
  being independent of whether Chrome is installed; ``web.open`` degrades to a
  structured envelope; and ``web.close`` on an idle session is a clean no-op.
* Foreign-target tools refuse a web session both ways: the PE-only
  ``static.open`` and the APK-only ``apk.open`` each answer ``target_mismatch``.

Pure stdlib fixtures, stdio loopback, no backend required, any platform.
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

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# With the backend absent these are the honest degradation codes; when a backend
# happens to be installed an ok envelope is equally acceptable, so the gate
# asserts a structured envelope always and this code set only when not ok.
_DEGRADE_CODES = {"capability_unavailable", "backend_error", "backend_unavailable"}


@asynccontextmanager
async def _mcp() -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=str(_PROJECT_ROOT),
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as client,
    ):
        await client.initialize()
        yield client


def _envelope(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"expected a structured envelope, got {result!r}"
    return content


def _assert_degrades(envelope: dict[str, Any], *, allow: set[str] = _DEGRADE_CODES) -> None:
    """A structured envelope either succeeded or failed with an expected code."""
    assert isinstance(envelope.get("ok"), bool), envelope
    if envelope["ok"] is False:
        assert envelope["error"]["code"] in allow, envelope


@pytest.mark.integration
@pytest.mark.asyncio
async def test_web_session_identity_and_static_tools_degrade(tmp_path: Path) -> None:
    js_file = tmp_path / "app.js"
    js_file.write_text("var a=function(b){return b+1};console.log(a(1));\n")
    wasm_file = tmp_path / "module.wasm"
    wasm_file.write_bytes(b"\x00asm\x01\x00\x00\x00")

    async with _mcp() as client:
        # Identity with nothing installed: a local script is a web session.
        from_file = _envelope(await client.call_tool("session.create", {"binary": str(js_file)}))
        assert from_file["ok"] is True, from_file
        assert from_file["data"]["session"]["target"] == "web", from_file
        assert isinstance(from_file["data"]["session"]["metadata"], dict), from_file

        # And a URL is a web session too, with no network reached to create it.
        from_url = _envelope(
            await client.call_tool(
                "session.create", {"binary": "https://example.com/app.js", "target": "web"}
            )
        )
        assert from_url["ok"] is True, from_url
        assert from_url["data"]["session"]["target"] == "web", from_url

        # The JS file tools degrade to a structured envelope without webcrack.
        for tool in ("js.deobfuscate", "js.beautify", "js.unpack_bundle"):
            _assert_degrades(_envelope(await client.call_tool(tool, {"path": str(js_file)})))

        # The WASM file tools degrade without wabt, for a valid module...
        for tool in ("wasm.wat", "wasm.info"):
            _assert_degrades(_envelope(await client.call_tool(tool, {"path": str(wasm_file)})))

        # ...and for a non-WebAssembly input, which is either rejected as
        # invalid_params (backend present) or degraded (backend absent), never a
        # crash.
        for tool in ("wasm.wat", "wasm.info"):
            _assert_degrades(
                _envelope(await client.call_tool(tool, {"path": str(js_file)})),
                allow=_DEGRADE_CODES | {"invalid_params"},
            )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_web_browser_tools_need_a_browser_and_refuse_foreign_targets() -> None:
    async with _mcp() as client:
        created = _envelope(
            await client.call_tool(
                "session.create", {"binary": "https://example.com/", "target": "web"}
            )
        )
        assert created["ok"] is True, created
        session_id = created["data"]["session"]["id"]

        # Reading the browser before opening one is a clear invalid_state, not a
        # crash -- and this holds whether or not Chrome is installed, because no
        # browser was opened.
        for tool in (
            "web.scripts",
            "web.network.list",
            "web.console",
            "web.dom.snapshot",
            "web.screenshot",
        ):
            envelope = _envelope(await client.call_tool(tool, {"session_id": session_id}))
            assert envelope["ok"] is False, (tool, envelope)
            assert envelope["error"]["code"] == "invalid_state", (tool, envelope)

        # Launching a browser degrades to a structured envelope without Chrome.
        _assert_degrades(_envelope(await client.call_tool("web.open", {"session_id": session_id})))

        # Closing an idle session is a clean no-op, not an error.
        closed = _envelope(await client.call_tool("web.close", {"session_id": session_id}))
        assert closed["ok"] is True, closed
        assert "closed" in closed["data"], closed

        # A PE-only tool and an APK-only tool each refuse the web session.
        static_open = _envelope(await client.call_tool("static.open", {"session_id": session_id}))
        assert static_open["ok"] is False, static_open
        assert static_open["error"]["code"] == "target_mismatch", static_open

        apk_open = _envelope(await client.call_tool("apk.open", {"session_id": session_id}))
        assert apk_open["ok"] is False, apk_open
        assert apk_open["error"]["code"] == "target_mismatch", apk_open
