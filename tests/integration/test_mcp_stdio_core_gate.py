"""Live Gate for the MCP stdio layer itself, with no backend attached.

The two existing protocol gates prove the MCP adapter only when a heavyweight
backend happens to be present: ``test_mcp_static_idalib`` needs IDA and
``test_mcp_dynamic_xdbg`` needs Windows plus x64dbg. Everything the adapter
itself does -- spawning ``python -m headless_re_mcp serve``, the initialize
handshake, tool listing, argument decoding, and packing every ``Result`` into
the structured envelope -- is pure Python, yet on a machine without those
backends it never ran end to end. A regression in the envelope shape or in a
tool binding would pass every unit test and only surface in a real client.

This gate speaks the real protocol through the official ``mcp`` client against
a real spawned server process, isolated to a per-test artifact root. One test
walks a whole analysis round trip over stdio -- create a session on the
committed PE fixture, record and query knowledge, generate a report, read the
artifact back hex-page by hex-page and check it byte-for-byte against the
described sha256, list the timeline, close the session, and see both lifecycle
actions in the audit log. The other proves hostility stays inside the
envelope: unknown ids, a nonexistent binary, and a traversal-shaped session id
each answer ``ok=False`` with the documented error code as a structured
result, never as a protocol failure. Requires only the checkout and the
installed package, so it never skips.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_REPO = Path(__file__).resolve().parents[2]
_PE = _REPO / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"

_CORE_TOOLS = frozenset(
    {
        "session.create",
        "session.close",
        "artifacts.list",
        "artifacts.describe",
        "artifacts.read",
        "knowledge.record",
        "knowledge.query",
        "report.generate",
        "timeline.list",
        "audit.list",
    }
)


def _parameters(tmp_path: Path) -> StdioServerParameters:
    env = os.environ.copy()
    # Isolate the spawned server's store from any config.json on the machine.
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=_REPO,
    )


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"no structured content: {result!r}"
    return content


def _ok(envelope: dict[str, Any]) -> dict[str, Any]:
    assert envelope["ok"] is True, envelope.get("error")
    data = envelope["data"]
    assert isinstance(data, dict)
    return data


def _err(envelope: dict[str, Any]) -> dict[str, Any]:
    assert envelope["ok"] is False, envelope.get("data")
    error = envelope["error"]
    assert isinstance(error, dict)
    return error


@pytest.mark.integration
@pytest.mark.asyncio
async def test_mcp_stdio_core_analysis_round_trip(tmp_path: Path) -> None:
    if not _PE.is_file():
        pytest.skip(f"fixture missing: {_PE}")

    async with (
        stdio_client(_parameters(tmp_path)) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        tools = await client.list_tools()
        names = {tool.name for tool in tools.tools}
        assert names >= _CORE_TOOLS, sorted(_CORE_TOOLS - names)

        created = _ok(
            _structured(await client.call_tool("session.create", {"binary": str(_PE)}))
        )
        session_id = str(created["session"]["id"])

        recorded = _ok(
            _structured(
                await client.call_tool(
                    "knowledge.record",
                    {
                        "session_id": session_id,
                        "kind": "function",
                        "key": "main",
                        "value": {"addr": "0x401000"},
                    },
                )
            )
        )
        assert recorded["replaced"] is False

        queried = _ok(
            _structured(
                await client.call_tool("knowledge.query", {"session_id": session_id})
            )
        )
        assert queried["total"] == 1
        assert queried["entries"][0]["value"] == {"addr": "0x401000"}

        report = _ok(
            _structured(
                await client.call_tool(
                    "report.generate",
                    {"session_id": session_id, "title": "MCP stdio gate"},
                )
            )
        )
        artifact_id = str(report["artifact_id"])
        report_path = Path(str(report["path"]))
        assert report_path.is_file()
        raw = report_path.read_bytes()

        described = _ok(
            _structured(
                await client.call_tool("artifacts.describe", {"artifact_id": artifact_id})
            )
        )["artifact"]
        assert described["kind"] == "report_markdown"
        assert described["size"] == len(raw)
        assert described["sha256"] == hashlib.sha256(raw).hexdigest()

        # Read the artifact back through the protocol in two pages and prove
        # the reassembled bytes are exactly the file the server wrote.
        half = max(1, len(raw) // 2)
        first = _ok(
            _structured(
                await client.call_tool(
                    "artifacts.read",
                    {"artifact_id": artifact_id, "offset": 0, "limit": half},
                )
            )
        )
        second = _ok(
            _structured(
                await client.call_tool(
                    "artifacts.read",
                    {"artifact_id": artifact_id, "offset": half, "limit": len(raw)},
                )
            )
        )
        assert first["encoding"] == "hex"
        assert bytes.fromhex(str(first["data"])) + bytes.fromhex(str(second["data"])) == raw

        timeline = _ok(
            _structured(
                await client.call_tool("timeline.list", {"session_id": session_id})
            )
        )
        assert [event["event"] for event in timeline["events"]] == ["session.created"]

        closed = _structured(
            await client.call_tool("session.close", {"session_id": session_id})
        )
        assert closed["ok"] is True

        audited = _ok(
            _structured(await client.call_tool("audit.list", {"session_id": session_id}))
        )
        assert [entry["action"] for entry in audited["entries"]] == [
            "session.close",
            "session.create",
        ]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_mcp_stdio_hostile_input_stays_in_envelope(tmp_path: Path) -> None:
    if not _PE.is_file():
        pytest.skip(f"fixture missing: {_PE}")

    async with (
        stdio_client(_parameters(tmp_path)) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()

        # A binary that does not exist is a structured refusal, not a crash.
        missing = _err(
            _structured(
                await client.call_tool(
                    "session.create", {"binary": str(tmp_path / "nope.exe")}
                )
            )
        )
        assert missing["code"]

        unknown_artifact = _err(
            _structured(
                await client.call_tool("artifacts.describe", {"artifact_id": "f" * 32})
            )
        )
        assert unknown_artifact["code"] == "not_found"

        unknown_session = _err(
            _structured(
                await client.call_tool("timeline.list", {"session_id": "0" * 32})
            )
        )
        assert unknown_session["code"] == "session_not_found"

        traversal = _err(
            _structured(
                await client.call_tool("timeline.list", {"session_id": "../escape"})
            )
        )
        assert traversal["code"] == "invalid_request"

        # The connection survives all of the hostility above: a normal call
        # on the same session still answers.
        tools = await client.list_tools()
        assert "session.create" in {tool.name for tool in tools.tools}
