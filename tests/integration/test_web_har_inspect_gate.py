"""web.har.inspect over real MCP stdio: a .har is a first-class target to read.

The web and proxy captures could write a HAR (web.har.export, proxy.export_har)
but nothing here could read one back: an analyst holding a .har had no offline
way to ask which hosts it talked to or what failed without standing a browser or
proxy back up. This gate drives the real stdio server end to end and pins the
round trip: session.create on a .har opens a web target, web.har.inspect
summarises the log, its host/method/status filters narrow it, pagination is
honest, and a file that is not a HAR -- or a live web session with no local
file -- fails with a precise envelope rather than an internal fault. It needs no
analysis backend, so it always runs.
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


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return {str(key): item for key, item in content.items()}


def _entry(method: str, url: str, status: int, mime: str) -> dict[str, Any]:
    return {
        "startedDateTime": "2026-08-28T00:00:00Z",
        "time": 1,
        "request": {"method": method, "url": url},
        "response": {"status": status, "content": {"size": 42, "mimeType": mime}},
        "cache": {},
        "timings": {"send": -1, "wait": -1, "receive": -1},
    }


def _har_bytes() -> str:
    return json.dumps(
        {
            "log": {
                "version": "1.2",
                "creator": {"name": "headless-re-mcp", "version": "test"},
                "entries": [
                    _entry("GET", "https://api.example.com/v1/a", 200, "application/json"),
                    _entry("POST", "https://api.example.com/v1/login", 403, "application/json"),
                    _entry("GET", "https://cdn.example.com/app.js", 200, "application/javascript"),
                    _entry("GET", "https://cdn.example.com/main.css", 200, "text/css"),
                    _entry("GET", "https://tracker.ads.net/p.gif", 404, "image/gif"),
                ],
            }
        }
    )


async def _call(client: ClientSession, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    return _structured(await asyncio.wait_for(client.call_tool(tool, args), timeout=60))


def _session_id(envelope: dict[str, Any]) -> str:
    assert envelope["ok"] is True, envelope
    return str(envelope["data"]["session"]["id"])


@pytest.mark.asyncio
async def test_mcp_stdio_web_har_inspect_round_trip(tmp_path: Path) -> None:
    good = tmp_path / "capture.har"
    good.write_text(_har_bytes(), encoding="utf-8")
    junk = tmp_path / "bad.har"
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
        assert "web.har.inspect" in tools

        # A .har opens as a web target.
        created = await _call(client, "session.create", {"binary": str(good)})
        assert created["ok"] is True, created
        assert created["data"]["session"]["target"] == "web"
        session_id = _session_id(created)

        # Full summary: every entry, whole-log host histogram.
        full = await _call(client, "web.har.inspect", {"session_id": session_id})
        assert full["ok"] is True, full
        data = full["data"]
        assert data["total"] == 5
        assert data["entries_total"] == 5
        assert data["hosts"] == {
            "api.example.com": 2,
            "cdn.example.com": 2,
            "tracker.ads.net": 1,
        }
        assert data["distinct_hosts"] == 3

        # Host filter.
        by_host = await _call(
            client, "web.har.inspect", {"session_id": session_id, "host": "cdn.example.com"}
        )
        assert by_host["data"]["total"] == 2
        assert {e["url"] for e in by_host["data"]["entries"]} == {
            "https://cdn.example.com/app.js",
            "https://cdn.example.com/main.css",
        }

        # Status filter.
        failing = await _call(
            client, "web.har.inspect", {"session_id": session_id, "status": 404}
        )
        assert failing["data"]["total"] == 1
        assert failing["data"]["entries"][0]["url"] == "https://tracker.ads.net/p.gif"

        # Method filter is case-insensitive.
        posts = await _call(
            client, "web.har.inspect", {"session_id": session_id, "method": "post"}
        )
        assert posts["data"]["total"] == 1
        assert posts["data"]["entries"][0]["status"] == 403

        # Pagination is honest: a filled page is not the whole log.
        page = await _call(
            client, "web.har.inspect", {"session_id": session_id, "offset": 0, "limit": 2}
        )
        assert page["data"]["count"] == 2
        assert page["data"]["total"] == 5
        assert page["data"]["has_more"] is True

        # A file that is not a HAR is invalid_params, not an internal fault.
        bad_session = await _call(client, "session.create", {"binary": str(junk)})
        bad = await _call(
            client, "web.har.inspect", {"session_id": _session_id(bad_session)}
        )
        assert bad["ok"] is False
        assert bad["error"]["code"] == "invalid_params"

        # A live web session on a remote URL has no local file: target_mismatch.
        url_session = await _call(client, "session.create", {"binary": "https://example.com/app"})
        url = await _call(
            client, "web.har.inspect", {"session_id": _session_id(url_session)}
        )
        assert url["ok"] is False
        assert url["error"]["code"] == "target_mismatch"
