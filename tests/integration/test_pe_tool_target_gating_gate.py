"""PE-only tools refuse the wrong target before they blame a missing CLI.

UPX, XVLKC, Scylla, VMPDump, de4dot and the detect/auto-unpack routers are PE
tools. Point one at an APK or a web session and there are two ways to say no,
and only one of them is useful. "This backend is not installed" tells an
operator on a box without UPX to go install UPX -- useless advice when the
target is an APK that UPX could never touch. "This tool does not apply to this
target" tells them the truth: use an Android tool. The fix these tools carry is
that the target check runs first, so a non-PE session is refused with
``target_mismatch`` regardless of whether the CLI is installed, and a caller is
never sent to install a tool that would not have helped.

That ordering is the whole contract, and it is host-independent: the non-PE
answer does not depend on what the box has, so this gate can pin it on a bare
machine over the real MCP stdio transport.

* Every PE-only unpacker / deobfuscator / detector refuses an APK session and a
  web session with ``target_mismatch``.
* The target check precedes the capability check: even with a radare-style CLI
  override pointing UPX at a real, runnable executable -- so the backend is
  genuinely available -- an APK session is still ``target_mismatch``, the CLI
  never consulted; while a PE session gets past the target gate to a
  tool/analysis outcome that is never ``target_mismatch``.

Pure stdlib fixtures, stdio loopback, no real backend, any platform.
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

# Every PE-only tool, keyed by the args it needs beyond session_id.
_PE_ONLY_TOOLS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("unpack.upx.test", {}),
    ("unpack.upx.unpack", {}),
    ("unpack.xvlkc.unpack", {}),
    ("unpack.scylla.rebuild", {}),
    ("dotnet.deobfuscate", {}),
    ("detect.scan", {}),
    ("unpack.auto", {}),
)


@asynccontextmanager
async def _mcp(
    artifact_root: Path, env_extra: dict[str, str] | None = None
) -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    if env_extra:
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


def _code(envelope: dict[str, Any]) -> str | None:
    error = envelope.get("error")
    return error.get("code") if isinstance(error, dict) else None


def _write_pe(path: Path) -> Path:
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


def _write_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
    return path


async def _session(client: ClientSession, binary: str, target: str | None = None) -> str:
    args: dict[str, Any] = {"binary": binary}
    if target is not None:
        args["target"] = target
    created = _envelope(await client.call_tool("session.create", args))
    assert created["ok"] is True, created
    return str(created["data"]["session"]["id"])


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pe_only_tools_refuse_non_pe_sessions_with_target_mismatch(tmp_path: Path) -> None:
    apk = _write_apk(tmp_path / "app.apk")
    js_file = tmp_path / "app.js"
    js_file.write_text("var a = 1;\n")

    async with _mcp(tmp_path / "artifacts") as client:
        apk_session = await _session(client, str(apk))
        web_session = await _session(client, str(js_file), target="web")

        for label, session_id in (("apk", apk_session), ("web", web_session)):
            for tool, extra in _PE_ONLY_TOOLS:
                envelope = _envelope(
                    await client.call_tool(tool, {"session_id": session_id, **extra})
                )
                assert envelope["ok"] is False, (label, tool, envelope)
                # The refusal names the target, not a missing CLI, so an operator
                # is not sent to install a tool that could not have helped.
                assert _code(envelope) == "target_mismatch", (label, tool, envelope)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_target_check_runs_before_the_capability_check(tmp_path: Path) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    apk = _write_apk(tmp_path / "app.apk")

    # A real, runnable executable so UPX is genuinely "available": if the
    # capability check ran first, an APK session would consult it and answer
    # something other than target_mismatch. It must not.
    fake_upx = tmp_path / "fake_upx"
    fake_upx.write_text("#!/bin/sh\nexit 0\n")
    fake_upx.chmod(0o755)

    async with _mcp(tmp_path / "artifacts", {"HEADLESS_RE_UPX": str(fake_upx)}) as client:
        apk_session = await _session(client, str(apk))
        pe_session = await _session(client, str(pe))

        for tool in ("unpack.upx.test", "unpack.upx.unpack"):
            # Non-PE: refused for the target, with the available CLI never run.
            apk_envelope = _envelope(await client.call_tool(tool, {"session_id": apk_session}))
            assert apk_envelope["ok"] is False, (tool, apk_envelope)
            assert _code(apk_envelope) == "target_mismatch", (tool, apk_envelope)

            # PE: past the target gate -- whatever happens next, it is a
            # tool/analysis outcome, never a target complaint.
            pe_envelope = _envelope(await client.call_tool(tool, {"session_id": pe_session}))
            assert _code(pe_envelope) != "target_mismatch", (tool, pe_envelope)
