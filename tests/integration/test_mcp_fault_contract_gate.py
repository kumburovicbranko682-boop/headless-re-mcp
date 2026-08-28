"""MCP fault contract: honest structured failures, contained protocol errors.

An autonomous agent drives this server over the MCP stdio transport, so what
comes back when a call goes wrong is load-bearing: the agent has to read the
failure and correct itself, and one bad call must never wedge the connection
that carries every other call. The unit suite proves the fault contract by
calling bound handlers directly (``tests/unit/test_tool_fault_contract.py``);
this gate proves it across the real transport, where FastMCP sits between the
client and the handler and can turn a failure into something the handler never
sees.

There are two distinct layers, and the gate pins both because they demand
different handling from the caller:

* An operation that is *shaped* correctly but *fails* -- a missing file, an
  unknown session, an id that resolves to nothing -- is caught by the handler's
  error boundary and returned as a structured envelope: ``isError`` is false,
  ``structuredContent`` carries ``ok=False`` with a named ``error.code`` and a
  ``retryable`` flag. The agent branches on the code. This is the surface the
  model spends all its time in, so it must be structured every time.

* A call that is *malformed* -- a missing required argument, a wrong-typed
  argument, a tool that does not exist -- is rejected by FastMCP's own schema
  validation before the handler runs, so it cannot produce an envelope. It
  comes back as an MCP protocol error: ``isError`` is true, no structured
  content, a readable validation message in the text. That is acceptable only
  because it is *contained*: the connection survives, so the next call works.

The third property ties them together: after a barrage of both kinds of
failure the same session still serves a real request. A transport that dies on
the first bad argument is unusable to an agent that will, over a long run,
send many. Pure stdlib, stdio loopback, no backend, any platform.
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


def _write_native_pe(path: Path) -> Path:
    """A minimal but genuine PE64 so ``session.create`` classifies and opens it.

    The gate needs a target that opens without a decompiler installed; the
    identity path reads the DOS stub and COFF machine word and nothing more, so
    a header-only image is enough to reach ``target='pe'``.
    """
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = b"PE\x00\x00" + struct.pack("<H", 0x8664) + struct.pack("<H", 0) + b"\x00" * 16
    path.write_bytes(bytes(dos) + coff + b"\x00" * 64)
    return path


@asynccontextmanager
async def _mcp(tmp_path: Path) -> AsyncIterator[ClientSession]:
    """Spawn the real server over stdio with an isolated artifact root."""
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")
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


def _structured(result: object) -> JsonObject | None:
    content = getattr(result, "structuredContent", None)
    return content if isinstance(content, dict) else None


def _text(result: object) -> str:
    """First text block of a result, or empty string when there is none."""
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            return text
    return ""


# Shaped-correctly-but-failing calls and the code each must name. Every one is
# a real operation the agent could issue: a path that is not there, an id that
# resolves to nothing. None of them needs a backend to reach its failure.
_INTERNAL_FAILURES: tuple[tuple[str, JsonObject, str], ...] = (
    ("session.create", {"binary": "@@MISSING@@"}, "file_not_found"),
    ("static.strings", {"session_id": "deadbeef"}, "session_not_found"),
    ("static.decompile", {"session_id": "deadbeef"}, "session_not_found"),
    ("apk.open", {"session_id": "deadbeef"}, "session_not_found"),
    ("report.generate", {"session_id": "deadbeef"}, "session_not_found"),
    ("timeline.list", {"session_id": "deadbeef"}, "session_not_found"),
    ("session.close", {"session_id": "deadbeef"}, "session_not_found"),
    ("capabilities.describe", {"capability_id": "no.such.capability"}, "not_found"),
    ("artifacts.describe", {"artifact_id": "no.such.artifact"}, "not_found"),
)

# Malformed calls FastMCP rejects before the handler runs: a missing required
# argument, a wrong-typed argument, a tool that is not registered.
_MALFORMED_CALLS: tuple[tuple[str, JsonObject], ...] = (
    ("static.strings", {}),
    ("session.list", {"limit": "not-an-int"}),
    ("no.such.tool", {}),
)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_internal_failures_return_structured_envelopes(tmp_path: Path) -> None:
    missing = str(tmp_path / "does-not-exist.bin")
    async with _mcp(tmp_path) as client:
        for name, raw_args, expected_code in _INTERNAL_FAILURES:
            args = {k: (missing if v == "@@MISSING@@" else v) for k, v in raw_args.items()}
            result = await client.call_tool(name, args)

            # A failed operation is not a transport error: the envelope is the
            # answer, so isError stays false and structured content is present.
            assert result.isError is False, (name, _text(result))
            envelope = _structured(result)
            assert envelope is not None, (name, "no structuredContent")

            assert envelope["ok"] is False, (name, envelope)
            assert envelope["data"] is None, (name, envelope)

            error = envelope["error"]
            assert isinstance(error, dict), (name, envelope)
            assert error.get("code") == expected_code, (name, error)
            assert isinstance(error.get("message"), str) and error["message"], (name, error)
            # Every structured failure states whether retrying could help; the
            # agent needs a bool here, not a missing key it has to guess about.
            assert isinstance(error.get("retryable"), bool), (name, error)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_malformed_calls_are_contained_not_envelopes(tmp_path: Path) -> None:
    async with _mcp(tmp_path) as client:
        for name, args in _MALFORMED_CALLS:
            result = await client.call_tool(name, args)

            # Schema validation happens above the handler, so there is no
            # envelope to return: the protocol error is the honest answer.
            assert result.isError is True, (name, _structured(result))
            assert _structured(result) is None, (name, "unexpected structuredContent")
            # It still has to be readable -- the agent reads the text to learn
            # what it got wrong -- so the message is not allowed to be empty.
            assert _text(result).strip(), (name, "empty error text")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_the_connection_survives_a_barrage_of_bad_calls(tmp_path: Path) -> None:
    async with _mcp(tmp_path) as client:
        # Fire every failure mode, structured and protocol-level alike, down the
        # one connection before asking it to do real work.
        missing = str(tmp_path / "does-not-exist.bin")
        for name, raw_args, _code in _INTERNAL_FAILURES:
            args = {k: (missing if v == "@@MISSING@@" else v) for k, v in raw_args.items()}
            await client.call_tool(name, args)
        for name, args in _MALFORMED_CALLS:
            await client.call_tool(name, args)

        # A read that never touches a backend still answers on the same session.
        metrics = await client.call_tool("meta.metrics", {})
        assert metrics.isError is False, _text(metrics)
        metrics_env = _structured(metrics)
        assert metrics_env is not None and metrics_env["ok"] is True, metrics_env

        # And a real operation opens a fresh session, proving the transport was
        # never left in a half-broken state by anything above.
        pe = _write_native_pe(tmp_path / "sample.exe")
        created = await client.call_tool("session.create", {"binary": str(pe)})
        assert created.isError is False, _text(created)
        created_env = _structured(created)
        assert created_env is not None and created_env["ok"] is True, created_env
        session = created_env["data"]["session"]
        assert session["target"] == "pe", session
        session_id = session["id"]

        closed = await client.call_tool("session.close", {"session_id": session_id})
        closed_env = _structured(closed)
        assert closed_env is not None and closed_env["ok"] is True, closed_env
