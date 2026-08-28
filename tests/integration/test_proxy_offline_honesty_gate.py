"""Proxy offline-honesty gate over a real MCP stdio server.

The live gate (`test_proxy_lifecycle_gate`) proves the positive path -- start
means listening, stop frees the port -- but it drives ``ProxyBackend`` directly
and *skips entirely* when mitmproxy is not installed. That leaves the contract
an unattended, bare-box deployment actually meets every time it boots without
mitmproxy: what does the interception surface say when there is no backend and
no proxy has ever run? "Nothing captured" and "no backend to start" are two
different facts, and only one of them tells an operator to go install mitmproxy.

This gate pins that split across the real stdio transport, and it *runs* on the
box where the live gate skips:

  * The query surface that describes the *absence* of a proxy needs no backend
    at all. ``proxy.status`` answers ``running: false`` and nothing else -- not
    a missing-capability error, not an empty capture. ``proxy.stop`` on a
    session that never started one is an idempotent, honest no-op
    (``stopped: false`` with a note), not an error and not a false claim that it
    tore something down.

  * The reads that would hand back *captured data* refuse with ``invalid_state``
    when no proxy ran -- ``proxy.flows`` and ``proxy.export_har`` never fabricate
    an empty capture or an empty HAR. "No proxy" is not "nothing was captured".

  * Only ``proxy.start`` consults the backend, so only it degrades to
    ``capability_unavailable`` when mitmproxy is absent. The failure names the
    one thing an operator can fix, and only for the one call that needs it.

  * The proxy is session-scoped runtime state, not a target-typed tool: the
    query surface behaves identically on PE, APK and web sessions and never
    answers ``target_mismatch`` (the deliberate contrast with the PE-only
    unpackers, which refuse non-PE targets before anything else).

Pure-stdlib fixtures, stdio loopback, no real backend, any platform.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import zipfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_MITMPROXY_INSTALLED = importlib.util.find_spec("mitmproxy") is not None


def _envelope(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"expected a structured envelope, got {content!r}"
    return content


def _data(result: object) -> dict[str, Any]:
    envelope = _envelope(result)
    assert envelope.get("ok") is True, envelope
    data = envelope.get("data")
    assert isinstance(data, dict), envelope
    return data


def _code(envelope: dict[str, Any]) -> str | None:
    error = envelope.get("error")
    return error.get("code") if isinstance(error, dict) else None


def _write_pe(path: Path) -> Path:
    """A minimal but well-formed PE32+ so the session classifies as ``pe``."""
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\x00\x00"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")  # machine: x64
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")  # size of optional header
    opt = 0x98
    image[opt : opt + 2] = (0x20B).to_bytes(2, "little")  # PE32+ magic
    image[opt + 24 : opt + 32] = (0x180000000).to_bytes(8, "little")  # image base
    image[opt + 56 : opt + 60] = (0x5000).to_bytes(4, "little")  # size of image
    path.write_bytes(image)
    return path


def _write_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


def _write_js(path: Path) -> Path:
    path.write_text("(function(){var flag=1;return flag;})();\n")
    return path


@asynccontextmanager
async def _mcp(artifact_root: Path) -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    project_root = Path(__file__).resolve().parents[2]
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=project_root,
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        yield client


async def _session(client: ClientSession, binary: str, target: str | None = None) -> str:
    args: dict[str, Any] = {"binary": binary}
    if target is not None:
        args["target"] = target
    data = _data(await client.call_tool("session.create", args))
    session = data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


@pytest.mark.integration
@pytest.mark.asyncio
async def test_query_surface_is_honest_when_no_proxy_has_run(tmp_path: Path) -> None:
    """status/stop/flows/export_har without a running proxy -- no backend needed."""
    web = _write_js(tmp_path / "app.js")
    async with _mcp(tmp_path / "artifacts") as client:
        sid = await _session(client, str(web), target="web")

        # status: describes the *absence* of a proxy. Exactly running=false and
        # nothing else -- not a capability error, and not an empty capture that
        # a reader could mistake for "a proxy ran and saw no traffic".
        status = _data(await client.call_tool("proxy.status", {"session_id": sid}))
        assert status == {"running": False}, status

        # stop on a session that never started one: an honest, idempotent no-op.
        # Not an error, and not a false claim that something was torn down.
        stopped = _data(await client.call_tool("proxy.stop", {"session_id": sid}))
        assert stopped.get("stopped") is False, stopped
        assert stopped.get("note"), stopped
        # Idempotent: stopping nothing twice reads the same, still not an error.
        stopped_again = _data(await client.call_tool("proxy.stop", {"session_id": sid}))
        assert stopped_again.get("stopped") is False, stopped_again

        # flows would hand back captured data, so with no proxy it refuses with
        # invalid_state -- it never fabricates an empty list. "No proxy" is a
        # different fact from "a capture with zero flows".
        flows = _envelope(await client.call_tool("proxy.flows", {"session_id": sid}))
        assert flows.get("ok") is False, flows
        assert _code(flows) == "invalid_state", flows
        assert flows.get("data") is None, flows

        # export_har likewise refuses rather than writing an empty HAR artifact.
        har = _envelope(await client.call_tool("proxy.export_har", {"session_id": sid}))
        assert har.get("ok") is False, har
        assert _code(har) == "invalid_state", har


@pytest.mark.integration
@pytest.mark.asyncio
async def test_only_start_needs_the_backend_and_state_is_target_agnostic(
    tmp_path: Path,
) -> None:
    """Only start consults mitmproxy; the query surface is target-agnostic."""
    pe = _write_pe(tmp_path / "sample.exe")
    apk = _write_apk(tmp_path / "app.apk")
    js = _write_js(tmp_path / "app.js")

    async with _mcp(tmp_path / "artifacts") as client:
        sessions = {
            "pe": await _session(client, str(pe)),
            "apk": await _session(client, str(apk)),
            "web": await _session(client, str(js), target="web"),
        }

        for kind, sid in sessions.items():
            # The runtime-state query surface is identical regardless of the
            # target kind -- a proxy is session-scoped state, not a PE/APK/web
            # tool. It never answers target_mismatch (the deliberate contrast
            # with the PE-only unpackers that refuse non-PE targets outright).
            status = _envelope(await client.call_tool("proxy.status", {"session_id": sid}))
            assert status.get("ok") is True, (kind, status)
            assert status.get("data") == {"running": False}, (kind, status)
            assert _code(status) != "target_mismatch", (kind, status)

            stop = _envelope(await client.call_tool("proxy.stop", {"session_id": sid}))
            assert stop.get("ok") is True, (kind, stop)
            assert _code(stop) != "target_mismatch", (kind, stop)

            # start is the one op that consults the backend. Absent mitmproxy it
            # degrades to capability_unavailable -- naming the single fixable
            # thing -- and it still does not answer target_mismatch on any kind.
            start = _envelope(await client.call_tool("proxy.start", {"session_id": sid}))
            assert _code(start) != "target_mismatch", (kind, start)
            if _MITMPROXY_INSTALLED:
                # The live gate covers the positive path; here we only require
                # start is not mis-reported as a missing backend when it exists.
                # Whatever it bound, release it so the box is left clean.
                assert _code(start) != "capability_unavailable", (kind, start)
                await client.call_tool("proxy.stop", {"session_id": sid})
            else:
                assert start.get("ok") is False, (kind, start)
                assert _code(start) == "capability_unavailable", (kind, start)
