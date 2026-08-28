"""Read-only deployment: every write is refused with a reason, every read works.

An operator can run this server read-only -- a triage box that opens samples
and answers questions but is not allowed to change anything on disk or in a
session. That guarantee is only worth having if it holds at the transport an
autonomous agent actually drives: the agent will *try* to write (it does not
know the deployment's policy), and what it gets back has to be an honest,
actionable refusal rather than a silently missing tool, a crash, or -- worst --
a write that goes through anyway.

The flag is ``local_full_access`` (env ``HEADLESS_RE_LOCAL_FULL_ACCESS``), read
per call, and the guard lives at the one place every transport's binding passes
through, so the MCP server, the agent route, and the OpenAI bridge cannot drift
to different policies. This gate proves the MCP end of it:

* A read-only server still serves reads: metrics, session and artifact
  listings, audit, capability search all answer ``ok``.
* Every state-changing or file-writing tool is refused with the same envelope:
  ``ok=False``, ``error.code="write_disabled"``, ``retryable=False``,
  ``details.setting="local_full_access"``. Not a schema error, not a vanished
  tool -- the tools stay advertised in ``tools/list`` so the agent can see what
  it *would* be able to do, and learns why it cannot.
* The guard runs before the operation: ``report.generate`` against a session
  that does not exist is ``write_disabled``, not ``session_not_found`` -- the
  refusal never reaches the code that would touch state.
* Nothing leaks through: after a barrage of refused writes the store is still
  empty, and flipping the flag on lets the *same* ``session.create`` succeed
  over the same artifact root, proving it was policy holding it back and not a
  broken tool.

Pure stdlib, stdio loopback, no backend, any platform.
"""

from __future__ import annotations

import os
import struct
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from headless_re_mcp.core.service import JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Schema-valid arguments for each write tool. The values do not have to resolve:
# the write guard wraps the whole handler, so a syntactically valid call is
# refused before anything looks at whether the session or path exists.
_WRITE_CALLS: tuple[tuple[str, JsonObject], ...] = (
    ("session.create", {"binary": "/nonexistent/sample.exe"}),
    ("report.generate", {"session_id": "no-such-session"}),
    ("knowledge.record", {"session_id": "no-such-session", "kind": "note", "key": "k"}),
    ("artifacts.gc", {}),
    ("session.close", {"session_id": "no-such-session"}),
)

# Reads that need no session and no backend, so they are a clean check that the
# read surface is untouched by the write policy.
_READ_CALLS: tuple[tuple[str, JsonObject], ...] = (
    ("meta.metrics", {}),
    ("session.list", {}),
    ("sessions.unclean", {}),
    ("artifacts.list", {}),
    ("audit.list", {}),
    ("capabilities.search", {"query": "static"}),
)


def _write_native_pe(path: Path) -> Path:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = b"PE\x00\x00" + struct.pack("<H", 0x8664) + struct.pack("<H", 0) + b"\x00" * 16
    path.write_bytes(bytes(dos) + coff + b"\x00" * 64)
    return path


@asynccontextmanager
async def _serve(root: Path, *, writable: bool) -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(root)
    env["HEADLESS_RE_LOCAL_FULL_ACCESS"] = "1" if writable else "0"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=_PROJECT_ROOT,
    )
    async with (
        stdio_client(params) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        yield client


def _envelope(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"no structuredContent: {result!r}"
    return content


def _data(result: object) -> JsonObject:
    envelope = _envelope(result)
    assert envelope.get("ok") is True, envelope
    data = envelope["data"]
    assert isinstance(data, dict), envelope
    return data


@pytest.mark.integration
@pytest.mark.asyncio
async def test_read_only_deployment_serves_reads_and_refuses_writes(tmp_path: Path) -> None:
    root = (tmp_path / "state").resolve()
    async with _serve(root, writable=False) as client:
        # The tools do not vanish under read-only: the agent can still see the
        # whole surface and learn which parts are refused, rather than guessing.
        advertised = {tool.name for tool in (await client.list_tools()).tools}
        for name, _args in _WRITE_CALLS:
            assert name in advertised, f"{name} should stay advertised under read-only"

        # Reads answer normally.
        for name, args in _READ_CALLS:
            envelope = _envelope(await client.call_tool(name, args))
            assert envelope.get("ok") is True, (name, envelope)

        # Writes are refused with one consistent, actionable envelope.
        for name, args in _WRITE_CALLS:
            envelope = _envelope(await client.call_tool(name, args))
            assert envelope.get("ok") is False, (name, envelope)
            error = envelope["error"]
            assert error["code"] == "write_disabled", (name, error)
            assert error["retryable"] is False, (name, error)
            assert error["details"]["setting"] == "local_full_access", (name, error)

        # The guard precedes the operation: a write against a missing session is
        # refused for the policy, never reaching the session lookup that would
        # otherwise answer session_not_found.
        report = _envelope(await client.call_tool("report.generate", {"session_id": "ghost"}))
        assert report["error"]["code"] == "write_disabled", report

        # Nothing the refused writes touched actually landed.
        assert _data(await client.call_tool("session.list", {}))["sessions"] == []
        assert _data(await client.call_tool("sessions.unclean", {}))["sessions"] == []
        assert _data(await client.call_tool("artifacts.list", {}))["artifacts"] == []


@pytest.mark.integration
@pytest.mark.asyncio
async def test_flipping_the_flag_lets_the_same_write_succeed(tmp_path: Path) -> None:
    root = (tmp_path / "state").resolve()
    binary = _write_native_pe(tmp_path / "sample.exe")

    # Read-only first: the create is refused and leaves the root untouched.
    async with _serve(root, writable=False) as client:
        refused = _envelope(await client.call_tool("session.create", {"binary": str(binary)}))
        assert refused["error"]["code"] == "write_disabled", refused
        assert _data(await client.call_tool("session.list", {}))["sessions"] == []

    # Same root, write allowed: the identical call goes through, so it was the
    # policy gating it -- not a missing capability or a broken tool.
    async with _serve(root, writable=True) as client:
        created = _data(await client.call_tool("session.create", {"binary": str(binary)}))
        session = created["session"]
        assert session["target"] == "pe", session
        session_id = str(session["id"])

        # A file-writing tool works too, not just the session open.
        report = _data(await client.call_tool("report.generate", {"session_id": session_id}))
        assert isinstance(report["artifact_id"], str) and report["artifact_id"], report
        listed = _data(await client.call_tool("artifacts.list", {"session_id": session_id}))
        assert report["artifact_id"] in {item["id"] for item in listed["artifacts"]}, listed
