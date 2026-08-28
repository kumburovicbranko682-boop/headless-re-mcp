"""Optional native backends tell the truth: absent is not broken, broken is not absent.

radare2 and Ghidra are optional. On the boxes these gates run on they are not
installed, and the whole point of an optional backend is that its tools stay
honest about why they cannot run: an agent that asks radare2 for functions on a
host without radare2 must get "the backend is not installed", and one whose
radare2 is installed but crashes must get "the backend ran and failed" -- two
different answers a caller acts on differently (install it, versus look at why
it broke). Collapsing them, or raising instead of either, strands the agent.

Neither answer needs the real tool, so the gate forces both deterministically
over the real MCP stdio transport, independent of what the host happens to have:

* Absent is ``capability_unavailable``. Pointing the backend at a path that is
  not a file makes it unavailable no matter what is on PATH, so every r2.* and
  ghidra.* tool reports a clean ``capability_unavailable`` -- on a PE session
  and, because the availability check comes first, on an APK session too.
* Present-but-broken is ``backend_error``. Pointing radare2 at a real
  executable that exits non-zero makes it available but failing, so the r2.*
  tools report ``backend_error`` -- distinctly, never ``capability_unavailable``
  and never a raise.
* Backends are independent. With radare2 configured (if broken) and Ghidra
  still absent, Ghidra keeps reporting ``capability_unavailable``: configuring
  one optional backend does not make another claim it is there.

Pure stdlib fixtures, stdio loopback, no real backend, POSIX for the broken
-executable half; any platform for the absent half.
"""

from __future__ import annotations

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

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# r2.* tools keyed by the extra arguments they need beyond session_id.
_R2_TOOLS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("r2.info", {}),
    ("r2.open", {}),
    ("r2.functions", {}),
    ("r2.strings", {}),
    ("r2.imports", {}),
    ("r2.exports", {}),
    ("r2.disasm", {"address": 0}),
    ("r2.xrefs", {"address": 0}),
)
_GHIDRA_TOOLS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("ghidra.analyze", {}),
    ("ghidra.functions", {}),
    ("ghidra.symbols", {}),
    ("ghidra.xrefs", {"address": "0x1000"}),
    ("ghidra.decompile", {"address": "0x1000"}),
)


def _write_pe(path: Path) -> Path:
    """A minimal but well-formed x64 PE the session layer accepts."""
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    optional = 0x98
    image[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    image[optional + 24 : optional + 32] = (0x180000000).to_bytes(8, "little")
    image[optional + 56 : optional + 60] = (0x5000).to_bytes(4, "little")
    path.write_bytes(image)
    return path


def _write_failing_executable(path: Path) -> Path:
    """A real, runnable program that always exits non-zero (POSIX)."""
    path.write_text("#!/bin/sh\nexit 7\n")
    path.chmod(0o755)
    return path


@asynccontextmanager
async def _mcp(env_extra: dict[str, str]) -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
    env.update(env_extra)
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


async def _create_session(client: ClientSession, binary: str) -> str:
    created = _envelope(await client.call_tool("session.create", {"binary": binary}))
    assert created["ok"] is True, created
    session_id = created["data"]["session"]["id"]
    assert isinstance(session_id, str), created
    return session_id


@pytest.mark.integration
@pytest.mark.asyncio
async def test_optional_native_backends_are_absent_not_broken(tmp_path: Path) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")

    # Point both backends at paths that are not files: unavailable regardless of
    # whatever radare2 / Ghidra the host may have on PATH.
    env_extra = {
        "HEADLESS_RE_R2": str(tmp_path / "no_such_r2"),
        "HEADLESS_RE_GHIDRA_HOME": str(tmp_path / "no_such_ghidra_home"),
    }

    async with _mcp(env_extra) as client:
        pe_session = await _create_session(client, str(pe))

        for tool, extra in _R2_TOOLS:
            envelope = _envelope(await client.call_tool(tool, {"session_id": pe_session, **extra}))
            assert envelope["ok"] is False, (tool, envelope)
            assert envelope["error"]["code"] == "capability_unavailable", (tool, envelope)
            assert envelope["error"]["message"], (tool, envelope)

        for tool, extra in _GHIDRA_TOOLS:
            envelope = _envelope(await client.call_tool(tool, {"session_id": pe_session, **extra}))
            assert envelope["ok"] is False, (tool, envelope)
            assert envelope["error"]["code"] == "capability_unavailable", (tool, envelope)

        # The availability check comes before the target check: an APK session
        # gets the same capability_unavailable, not a target complaint.
        apk_session = await _create_session(client, str(apk))
        for tool in ("r2.open", "ghidra.analyze"):
            envelope = _envelope(await client.call_tool(tool, {"session_id": apk_session}))
            assert envelope["ok"] is False, (tool, envelope)
            assert envelope["error"]["code"] == "capability_unavailable", (tool, envelope)


@pytest.mark.integration
@pytest.mark.skipif(
    os.name != "posix", reason="the broken-executable fixture is a POSIX shell script"
)
@pytest.mark.asyncio
async def test_a_configured_backend_that_fails_reports_backend_error(tmp_path: Path) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    broken_r2 = _write_failing_executable(tmp_path / "broken_r2")

    # radare2 is now present (a real, runnable file) but fails; Ghidra stays
    # absent, so the two backends' answers must diverge.
    env_extra = {
        "HEADLESS_RE_R2": str(broken_r2),
        "HEADLESS_RE_GHIDRA_HOME": str(tmp_path / "no_such_ghidra_home"),
    }

    async with _mcp(env_extra) as client:
        pe_session = await _create_session(client, str(pe))

        for tool, extra in _R2_TOOLS:
            envelope = _envelope(await client.call_tool(tool, {"session_id": pe_session, **extra}))
            assert envelope["ok"] is False, (tool, envelope)
            # Present-but-failing is a runtime error, never "not installed".
            assert envelope["error"]["code"] == "backend_error", (tool, envelope)

        # Configuring radare2 did not make Ghidra claim to exist.
        ghidra = _envelope(await client.call_tool("ghidra.analyze", {"session_id": pe_session}))
        assert ghidra["ok"] is False, ghidra
        assert ghidra["error"]["code"] == "capability_unavailable", ghidra
