"""APK signing-scheme identity gate: v2/v3 are seen, over real MCP stdio.

"Is this APK signed?" is a first-order triage question, and describe_apk --
the stdlib identity read that runs at session creation without androguard --
used to answer it from META-INF alone. That is the v1 (JAR) scheme. Every APK
built for Android 7 or later is signed with Signature Scheme v2/v3, whose data
lives in the APK Signing Block between the ZIP entries and the central
directory, not under META-INF. So a modern, properly signed package reported
signed_v1 false and nothing else -- indistinguishable, to an operator reading
session.get, from a genuinely unsigned one.

This gate builds packages whose bytes carry a real APK Signing Block (the same
structure apksigner writes) and drives session.create / session.get over the
real MCP stdio server:

- A v2+v3 signed package: session metadata reports signed_v2 and signed_v3
  true (and signed_v1 false, since it carries no META-INF signature).
- A genuinely unsigned package: all three signed_* flags false, so the new
  signals do not cry wolf.
"""

from __future__ import annotations

import io
import os
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

mcp = pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

JsonObject = dict[str, Any]

_V2_ID = 0x7109871A
_V3_ID = 0xF05368C0


def _apk_with_signing_block(path: Path, block_ids: list[int]) -> Path:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
    data = bytearray(buffer.getvalue())
    eocd = data.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    if not block_ids:
        path.write_bytes(bytes(data))
        return path
    pairs = b"".join(
        struct.pack("<Q", 4 + 48) + struct.pack("<I", scheme_id) + b"\x00" * 48
        for scheme_id in block_ids
    )
    block_size = len(pairs) + 8 + 16
    block = (
        struct.pack("<Q", block_size)
        + pairs
        + struct.pack("<Q", block_size)
        + b"APK Sig Block 42"
    )
    spliced = data[:cd_offset] + block + data[cd_offset:]
    struct.pack_into("<I", spliced, eocd + len(block) + 16, cd_offset + len(block))
    path.write_bytes(bytes(spliced))
    return path


def _structured(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return content


def _server_env(tmp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    config_home = tmp_path / "config"
    config_home.mkdir(exist_ok=True)
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")
    return env


async def _apk_metadata(client: ClientSession, apk: Path) -> JsonObject:
    created = _structured(await client.call_tool("session.create", {"binary": str(apk)}))
    assert created["ok"] is True, created
    session = created["data"]["session"]
    assert session["target"] == "apk"
    session_id = str(session["id"])
    fetched = _structured(
        await client.call_tool("session.get", {"session_id": session_id})
    )
    assert fetched["ok"] is True, fetched
    metadata = fetched["data"]["session"]["metadata"]["apk"]
    await client.call_tool("session.close", {"session_id": session_id})
    assert isinstance(metadata, dict)
    return metadata


@pytest.mark.integration
@pytest.mark.asyncio
async def test_apk_v2_v3_signatures_surface_over_mcp(tmp_path: Path) -> None:
    signed = _apk_with_signing_block(tmp_path / "modern.apk", [_V2_ID, _V3_ID])
    unsigned = _apk_with_signing_block(tmp_path / "bare.apk", [])

    project_root = Path(__file__).resolve().parents[2]
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=_server_env(tmp_path),
        cwd=str(project_root),
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()

        modern = await _apk_metadata(client, signed)
        assert modern["signed_v1"] is False, modern
        assert modern["signed_v2"] is True, modern
        assert modern["signed_v3"] is True, modern

        bare = await _apk_metadata(client, unsigned)
        assert bare["signed_v1"] is False, bare
        assert bare["signed_v2"] is False, bare
        assert bare["signed_v3"] is False, bare
