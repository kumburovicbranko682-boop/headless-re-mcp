"""Android bundle/container formats create sessions, over real MCP stdio.

classify_target accepts four Android packagings -- .apk, .aab, .apks, .xapk --
but describe_apk (the stdlib identity read that runs at session creation)
required AndroidManifest.xml at the archive root. Only a plain .apk keeps it
there: an app bundle stores it under base/manifest/, and .apks/.xapk are
containers of real APKs. So three of the four advertised formats failed
session creation outright with "archive has no AndroidManifest.xml" -- an
error that reads as a corrupt file, blocking every downstream tool on a
perfectly valid Android artifact.

This gate drives session.create / session.get over the real MCP stdio server
for each container format and pins that a session is created with honest,
format-aware identity:

- .aab: session with target=apk, metadata format=aab, the native ABIs read
  from base/lib, and signed_v1 from the bundle's jar signature.
- .apks and .xapk: session created, format marked, apk_count reporting how
  many APKs the container holds, and no invented ABI/signature for the outer
  archive.
- A plain zip that is not an Android package still fails creation, so the
  looser acceptance did not turn into "any zip is an APK".
"""

from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

mcp = pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

JsonObject = dict[str, Any]


def _zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
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


async def _create(client: ClientSession, path: Path) -> JsonObject:
    return _structured(
        await client.call_tool("session.create", {"binary": str(path)})
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_android_bundle_formats_create_sessions_over_mcp(tmp_path: Path) -> None:
    aab = _zip(
        tmp_path / "app.aab",
        {
            "BundleConfig.pb": b"\x08\x01",
            "base/manifest/AndroidManifest.xml": b"proto",
            "base/dex/classes.dex": b"dex\n035\x00",
            "base/lib/arm64-v8a/libnative.so": b"\x7fELF",
            "base/lib/x86_64/libnative.so": b"\x7fELF",
            "META-INF/BNDLTOOL.RSA": b"sig",
        },
    )
    apks = _zip(
        tmp_path / "app.apks",
        {
            "toc.pb": b"\x08\x01",
            "splits/base-master.apk": b"PK\x03\x04",
            "splits/base-arm64_v8a.apk": b"PK\x03\x04",
        },
    )
    xapk = _zip(
        tmp_path / "app.xapk",
        {
            "manifest.json": b'{"package_name":"com.x"}',
            "com.x.apk": b"PK\x03\x04",
            "config.arm64_v8a.apk": b"PK\x03\x04",
        },
    )
    not_android = _zip(tmp_path / "random.apk", {"readme.txt": b"hello"})

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

        # App bundle: created, identified, not failed.
        created = await _create(client, aab)
        assert created["ok"] is True, created
        session = created["data"]["session"]
        assert session["target"] == "apk"
        session_id = str(session["id"])
        fetched = _structured(
            await client.call_tool("session.get", {"session_id": session_id})
        )
        identity = fetched["data"]["session"]["metadata"]["apk"]
        assert identity["format"] == "aab", identity
        assert set(identity["native_abis"]) == {"arm64-v8a", "x86_64"}, identity
        assert identity["signed_v1"] is True, identity
        await client.call_tool("session.close", {"session_id": session_id})

        # Containers: created, with an honest embedded count and no false ABIs.
        for container, fmt in ((apks, "apks"), (xapk, "xapk")):
            created = await _create(client, container)
            assert created["ok"] is True, created
            identity = created["data"]["session"]["metadata"]["apk"]
            assert identity["format"] == fmt, identity
            assert identity["apk_count"] == 2, identity
            assert identity["native_abis"] == [], identity
            await client.call_tool(
                "session.close",
                {"session_id": str(created["data"]["session"]["id"])},
            )

        # A plain zip is still not an Android package.
        rejected = await _create(client, not_android)
        assert rejected["ok"] is False, rejected
        assert rejected["error"] is not None
