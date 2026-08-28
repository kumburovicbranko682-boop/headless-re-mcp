"""A web target opens without a browser, and browser tools degrade honestly.

The Web line makes the same promise the Android line does, and it had the same
gap: a target must *open* on a box with no browser driver, and the tools that
genuinely need one must say so precisely rather than crashing or pretending.
A downloaded asset (.js / .wasm) is a web session bound to real bytes; a URL
is a browserless web session with nothing on disk. Neither needs Chrome to be
created -- only web.open (which launches the browser) does, and when the
Playwright driver is absent it must answer capability_unavailable, not an
incident.

Proven over the real MCP stdio server, the direct analog of the APK identity
gate:

* a .js file and a .wasm file each open as a ``web`` session with a bound
  binary and a sha256; an http(s) URL opens as a ``web`` session with no
  binary and the URL as its locator;
* web.open degrades to capability_unavailable when the browser driver is
  missing (skipped when Playwright is installed, where launching is allowed);
* a browser-scoped tool (web.navigate, web.screenshot) called before any
  browser is open answers invalid_state -- an honest ordering error, never
  target_mismatch and never a crash;
* the cross-backend guard still holds: apk.open on a web session is
  target_mismatch, because a web target is not an Android one.

Pure Python, loopback stdio, any platform.
"""

from __future__ import annotations

import importlib.util
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
_PLAYWRIGHT_PRESENT = importlib.util.find_spec("playwright") is not None


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return content


class _Mcp:
    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return _structured(await self._session.call_tool(name, args))

    async def open_web(self, locator: str) -> dict[str, Any]:
        created = await self.call("session.create", {"binary": locator})
        assert created["ok"] is True, created
        return dict(created["data"]["session"])


@asynccontextmanager
async def _mcp(artifact_root: Path) -> AsyncIterator[_Mcp]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=str(_PROJECT_ROOT),
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield _Mcp(session)


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_downloaded_assets_and_urls_open_as_web_sessions(tmp_path: Path) -> None:
    js = tmp_path / "app.js"
    js.write_text("const answer = 42;\n", encoding="utf-8")
    wasm = tmp_path / "module.wasm"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")

    async with _mcp(tmp_path / "artifacts") as mcp:
        # A saved asset is a web session bound to the bytes on disk.
        js_session = await mcp.open_web(str(js))
        assert js_session["target"] == "web", js_session
        assert js_session["binary"], js_session
        assert js_session["sha256"], js_session

        wasm_session = await mcp.open_web(str(wasm))
        assert wasm_session["target"] == "web", wasm_session
        assert wasm_session["binary"], wasm_session

        # A URL is a browserless web session: created without touching a
        # browser, with no binary and the URL preserved as the locator.
        url_session = await mcp.open_web("https://example.com/app.js")
        assert url_session["target"] == "web", url_session
        assert not url_session["binary"], url_session
        assert url_session["locator"] == "https://example.com/app.js", url_session


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_browser_tools_degrade_honestly_without_a_browser(tmp_path: Path) -> None:
    js = tmp_path / "app.js"
    js.write_text("const answer = 42;\n", encoding="utf-8")

    async with _mcp(tmp_path / "artifacts") as mcp:
        session = await mcp.open_web(str(js))
        session_id = session["id"]

        # web.open launches the browser. Without the Playwright driver it is
        # capability_unavailable -- the "opened, but cannot drive a browser"
        # degradation. With the driver present, launching is allowed, so the
        # capability claim is only asserted where the capability is missing.
        opened = await mcp.call("web.open", {"session_id": session_id})
        if _PLAYWRIGHT_PRESENT:
            assert isinstance(opened["ok"], bool), opened
        else:
            assert opened["ok"] is False, opened
            assert opened["error"]["code"] == "capability_unavailable", opened

        # Browser-scoped tools called before a browser is open are an ordering
        # error, not a missing capability or a crash: invalid_state, and never
        # target_mismatch (this *is* a web target).
        for tool, args in (
            ("web.navigate", {"session_id": session_id, "url": "https://example.com"}),
            ("web.screenshot", {"session_id": session_id}),
        ):
            answer = await mcp.call(tool, args)
            assert answer["ok"] is False, (tool, answer)
            assert answer["error"]["code"] == "invalid_state", (tool, answer)

        # The cross-backend guard still holds: a web session is not an Android
        # target, so the apk-only tool refuses it as target_mismatch rather
        # than reaching for a decompiler.
        apk_on_web = await mcp.call("apk.open", {"session_id": session_id})
        assert apk_on_web["ok"] is False, apk_on_web
        assert apk_on_web["error"]["code"] == "target_mismatch", apk_on_web
