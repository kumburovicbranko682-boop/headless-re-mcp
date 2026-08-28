"""Frida offline-honesty gate over a real MCP stdio server.

The live Frida gate (`test_m11_frida_live_gate`) needs a device and a
frida-server and skips on a bare box. That leaves the contract an unattended
Android deployment actually meets when it boots without frida installed and with
no device attached: what does the Frida surface say, and does it tell the caller
the *right* thing to do next? "Install a backend" and "you have not reached the
state this needs yet" are different problems with different fixes, and a tool
that blurs them sends an operator to install software that would not have helped.

This gate runs where the live gate skips and pins that Frida keeps the two apart
across the real stdio transport, identically on PE and APK sessions (the layer
is decided by the tool and the session state, not the target kind):

  * The ops that genuinely need a backend fail with ``capability_unavailable``
    and name the fixable dependency. ``frida.devices`` and
    ``frida.device.connect`` name the frida Python module; ``frida.server.ensure``
    names *adbutils* -- its own dependency -- rather than frida, so the operator
    installs the thing that unblocks that call.

  * The device-scoped reads fail with ``invalid_state`` and tell the caller to
    connect a device first (``frida.device.connect``) -- a workflow step, not an
    install. A caller told this must not go install frida.

  * The debuggee probes fail with ``invalid_state`` too: they read the session's
    live target, and without one that is a state error, not a missing install.

Pure-stdlib fixtures, stdio loopback, no frida/adbutils, any platform.
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

_FRIDA_INSTALLED = importlib.util.find_spec("frida") is not None
_ADBUTILS_INSTALLED = importlib.util.find_spec("adbutils") is not None

# Device-scoped reads: they need a bound frida device, so with none connected
# they are a workflow step ("connect first"), never a missing install.
_DEVICE_SCOPED: dict[str, dict[str, Any]] = {
    "frida.applications": {},
    "frida.spawn": {"package": "com.example.app"},
    "frida.java.classes": {},
    "frida.java.methods": {"class_name": "java.lang.String"},
}

# Debuggee probes: they read the session's live target, so with no dynamic
# backend up they are a state error, never a missing install.
_DEBUGGEE_PROBES: dict[str, dict[str, Any]] = {
    "frida.attach": {},
    "frida.modules": {},
    "frida.exports": {"module_name": "libc.so"},
    "frida.memory.read": {"address": 0x1000, "size": 16},
    "frida.hook.template": {"template": "noop"},
}


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


def _err(envelope: dict[str, Any]) -> tuple[str | None, str]:
    error = envelope.get("error")
    if not isinstance(error, dict):
        return None, ""
    return error.get("code"), str(error.get("message") or "")


def _write_pe(path: Path) -> Path:
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\x00\x00"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    opt = 0x98
    image[opt : opt + 2] = (0x20B).to_bytes(2, "little")
    image[opt + 24 : opt + 32] = (0x180000000).to_bytes(8, "little")
    image[opt + 56 : opt + 60] = (0x5000).to_bytes(4, "little")
    path.write_bytes(image)
    return path


def _write_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
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


async def _session(client: ClientSession, binary: str) -> str:
    data = _data(await client.call_tool("session.create", {"binary": binary}))
    session = data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


@pytest.mark.integration
@pytest.mark.asyncio
async def test_frida_names_the_missing_backend_only_where_a_backend_is_needed(
    tmp_path: Path,
) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    apk = _write_apk(tmp_path / "app.apk")
    async with _mcp(tmp_path / "artifacts") as client:
        pe_sid = await _session(client, str(pe))
        apk_sid = await _session(client, str(apk))

        for sid in (pe_sid, apk_sid):
            # Enumerating devices genuinely needs the frida module.
            code, msg = _err(_envelope(await client.call_tool("frida.devices", {})))
            if not _FRIDA_INSTALLED:
                assert code == "capability_unavailable", (code, msg)
                assert "frida" in msg and "installed" in msg, msg

            # Binding a device likewise needs the frida module.
            code, msg = _err(
                _envelope(
                    await client.call_tool("frida.device.connect", {"session_id": sid})
                )
            )
            if not _FRIDA_INSTALLED:
                assert code == "capability_unavailable", (code, msg)
                assert "frida" in msg and "installed" in msg, msg

            # frida.server.ensure depends on adb, so it names *adbutils* -- not
            # frida -- pointing the operator at the dependency that unblocks it.
            code, msg = _err(
                _envelope(
                    await client.call_tool(
                        "frida.server.ensure",
                        {"session_id": sid, "serial": "emulator-5554"},
                    )
                )
            )
            if not _ADBUTILS_INSTALLED:
                assert code == "capability_unavailable", (code, msg)
                assert "adbutils" in msg, msg


@pytest.mark.integration
@pytest.mark.asyncio
async def test_device_scoped_reads_ask_to_connect_first_not_to_install(
    tmp_path: Path,
) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    apk = _write_apk(tmp_path / "app.apk")
    async with _mcp(tmp_path / "artifacts") as client:
        for binary in (str(pe), str(apk)):
            sid = await _session(client, binary)
            for tool, extra in _DEVICE_SCOPED.items():
                code, msg = _err(
                    _envelope(await client.call_tool(tool, {"session_id": sid, **extra}))
                )
                # A workflow step, not a missing install: never capability_unavailable.
                assert code == "invalid_state", (tool, binary, code, msg)
                assert "frida.device.connect" in msg, (tool, binary, msg)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_debuggee_probes_need_a_live_target_not_an_install(
    tmp_path: Path,
) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    apk = _write_apk(tmp_path / "app.apk")
    async with _mcp(tmp_path / "artifacts") as client:
        for binary in (str(pe), str(apk)):
            sid = await _session(client, binary)
            for tool, extra in _DEBUGGEE_PROBES.items():
                code, msg = _err(
                    _envelope(await client.call_tool(tool, {"session_id": sid, **extra}))
                )
                # No live target is a state error, not a missing backend.
                assert code == "invalid_state", (tool, binary, code, msg)
                assert code != "capability_unavailable", (tool, binary, code, msg)
