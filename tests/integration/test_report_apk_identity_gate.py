"""Report identity gate over a real MCP stdio server.

``report.generate`` renders the one durable artifact a reviewer keeps. For an
Android target the interesting facts -- which native ABIs ship, how many dex
files there are, whether the package carries a v1 signature -- are read cheaply
by ``describe_apk`` at ``session.create`` and stored on the session, with no
decompiler required. The contract this gate pins is that those facts reach the
report, over the wire, so an APK report is not silently indistinguishable from a
PE report with a blank architecture.

Three fixtures, built with the stdlib, make the facts falsifiable rather than
decorative:

  * A signed, multi-ABI APK's report names its ``Target`` as ``apk``, carries an
    ``apk identity`` table, lists both ABIs, counts two dex files, and reads
    ``signed_v1`` as ``yes``.
  * An unsigned, single-ABI APK's report reads ``signed_v1`` as ``no`` and counts
    one dex and one ABI -- the numbers track the package, they are not constants.
  * A PE's report states its ``Target`` as ``pe`` and carries *no* identity
    section: the surfacing is target-driven, not noise stapled onto every report.

Pure-stdlib fixtures, stdio loopback, no backend, any platform.
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


def _write_apk(path: Path, *, abis: list[str], dex: int, signed: bool) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        for index in range(dex):
            name = "classes.dex" if index == 0 else f"classes{index + 1}.dex"
            archive.writestr(name, b"dex\n035\x00body")
        for abi in abis:
            archive.writestr(f"lib/{abi}/libnative.so", b"\x7fELF")
        archive.writestr("resources.arsc", b"arsc")
        if signed:
            archive.writestr("META-INF/CERT.RSA", b"pkcs7-signature-block")
    return path


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


def _envelope(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"expected a structured envelope, got {content!r}"
    return content


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


async def _report_markdown(client: ClientSession, binary: str) -> str:
    created = _envelope(await client.call_tool("session.create", {"binary": binary}))
    assert created.get("ok") is True, created
    session_id = created["data"]["session"]["id"]

    generated = _envelope(await client.call_tool("report.generate", {"session_id": session_id}))
    assert generated.get("ok") is True, generated
    data = generated["data"]
    markdown = data.get("markdown")
    if not isinstance(markdown, str) or data.get("truncated"):
        # Large reports spill to an artifact; read it back rather than trust the
        # inline copy. The gate fixtures are tiny, so this is belt-and-braces.
        artifact_id = data.get("artifact_id")
        assert isinstance(artifact_id, str), data
        read = _envelope(await client.call_tool("artifacts.read", {"artifact_id": artifact_id}))
        assert read.get("ok") is True, read
        markdown = bytes.fromhex(read["data"]["data"]).decode("utf-8", errors="replace")
    assert isinstance(markdown, str)
    return markdown


@pytest.mark.integration
@pytest.mark.asyncio
async def test_signed_multi_abi_apk_report_carries_its_identity(tmp_path: Path) -> None:
    apk = _write_apk(
        tmp_path / "signed.apk",
        abis=["arm64-v8a", "x86_64"],
        dex=2,
        signed=True,
    )
    async with _mcp(tmp_path / "artifacts") as client:
        markdown = await _report_markdown(client, str(apk))

    assert "| Target | apk |" in markdown, markdown
    assert "### apk identity" in markdown, markdown
    assert "| native_abis | arm64-v8a, x86_64 |" in markdown, markdown
    assert "| dex_count | 2 |" in markdown, markdown
    assert "| signed_v1 | yes |" in markdown, markdown


@pytest.mark.integration
@pytest.mark.asyncio
async def test_unsigned_single_abi_apk_report_tracks_the_package(tmp_path: Path) -> None:
    apk = _write_apk(
        tmp_path / "unsigned.apk",
        abis=["armeabi-v7a"],
        dex=1,
        signed=False,
    )
    async with _mcp(tmp_path / "artifacts") as client:
        markdown = await _report_markdown(client, str(apk))

    assert "### apk identity" in markdown, markdown
    assert "| native_abis | armeabi-v7a |" in markdown, markdown
    assert "| dex_count | 1 |" in markdown, markdown
    assert "| signed_v1 | no |" in markdown, markdown


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pe_report_states_its_target_and_has_no_identity_noise(tmp_path: Path) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        markdown = await _report_markdown(client, str(pe))

    assert "| Target | pe |" in markdown, markdown
    assert "identity" not in markdown, markdown
    assert "arm64-v8a" not in markdown, markdown
    assert "signed_v1" not in markdown, markdown
