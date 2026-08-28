"""An APK opens on its contents, from the stdlib, with no decompiler installed.

The Android line rests on a promise the reference machine (which had
androguard) could never test: a package must *open* on a bare box, carrying
the identity facts a triage needs -- native ABIs, dex count, v1 signing --
read with nothing but the standard library, and degrade to "opened, but
cannot decompile" rather than refusing the whole target when androguard is
absent. If session creation needed androguard, one missing optional dependency
would take the entire Android surface down instead of one tool.

Three properties, proven over the real MCP stdio server against a synthetic
package built in the test (no fixtures, no external tooling):

* a well-formed APK opens as an ``apk`` session whose metadata carries the
  exact stdlib-derived identity -- ABIs from ``lib/<abi>/``, a ``.dex`` count,
  a v1-signature flag from ``META-INF``;
* that recognition is by *contents*, not the file name: the same bytes with no
  ``.apk`` extension still open as an APK, because a ZIP that holds an
  ``AndroidManifest.xml`` is one, and a plain ZIP that does not is refused as
  the not-a-PE it falls back to -- the manifest is the deciding fact;
* with androguard absent, ``apk.open`` (its decompiler-backed identity parse)
  answers ``capability_unavailable``, never ``target_mismatch`` and never a
  crash: the target is understood, only the optional tool is missing.

Pure Python, loopback stdio, any platform.
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

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ANDROGUARD_PRESENT = importlib.util.find_spec("androguard") is not None


def _write_synthetic_apk(path: Path) -> None:
    """A ZIP with exactly the entries stdlib identity reads, and nothing real.

    None of these need to be valid Android artifacts: ``describe_apk`` keys off
    entry names alone -- the manifest's presence, ``lib/<abi>/`` paths, ``.dex``
    suffixes, ``META-INF`` certificate files -- so a triage can answer before a
    decompiler is anywhere in the picture.
    """
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00not-real-axml")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
        archive.writestr("classes2.dex", b"dex\n035\x00" + b"\x00" * 32)
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF")
        archive.writestr("lib/armeabi-v7a/libnative.so", b"\x7fELF")
        archive.writestr("resources.arsc", b"\x00" * 16)
        archive.writestr("META-INF/CERT.RSA", b"\x00" * 16)
        archive.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\n")


def _write_plain_zip(path: Path) -> None:
    """A valid ZIP with ZIP magic but no AndroidManifest.xml."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("readme.txt", b"just a zip, not an app")
        archive.writestr("data/inner.bin", b"\x00\x01\x02\x03")


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return content


class _Mcp:
    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return _structured(await self._session.call_tool(name, args))


@asynccontextmanager
async def _mcp(artifact_root: Path) -> AsyncIterator[_Mcp]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=str(_PROJECT_ROOT),
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield _Mcp(session)


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_apk_opens_with_stdlib_identity_and_degrades_without_androguard(
    tmp_path: Path,
) -> None:
    apk = tmp_path / "app.apk"
    _write_synthetic_apk(apk)

    async with _mcp(tmp_path / "artifacts") as mcp:
        created = await mcp.call("session.create", {"binary": str(apk)})
        assert created["ok"] is True, created
        session = created["data"]["session"]
        assert session["target"] == "apk", session

        # The identity a triage needs, read with the standard library only.
        identity = session["metadata"]["apk"]
        assert identity["native_abis"] == ["arm64-v8a", "armeabi-v7a"], identity
        assert identity["dex_count"] == 2, identity
        assert identity["signed_v1"] is True, identity
        assert identity["entry_count"] == 8, identity

        # The decompiler-backed parse degrades honestly. Absent androguard it
        # is capability_unavailable -- not target_mismatch (this *is* an apk)
        # and not a crash. Present, it is allowed to succeed; either way the
        # session already opened, which is the property under test.
        opened = await mcp.call("apk.open", {"session_id": session["id"]})
        if _ANDROGUARD_PRESENT:
            assert isinstance(opened["ok"], bool), opened
        else:
            assert opened["ok"] is False, opened
            assert opened["error"]["code"] == "capability_unavailable", opened


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_apk_is_recognized_by_contents_not_by_name(tmp_path: Path) -> None:
    async with _mcp(tmp_path / "artifacts") as mcp:
        # Same bytes, no .apk extension: a ZIP holding AndroidManifest.xml is
        # an APK regardless of what it is called.
        unnamed = tmp_path / "download.bin"
        _write_synthetic_apk(unnamed)
        created = await mcp.call("session.create", {"binary": str(unnamed)})
        assert created["ok"] is True, created
        session = created["data"]["session"]
        assert session["target"] == "apk", session
        assert session["metadata"]["apk"]["dex_count"] == 2, session

        # A plain ZIP with no manifest is not an APK. It falls back to the PE
        # path and is refused as the not-a-PE it is -- the manifest, not the
        # ZIP magic, is what promotes an archive to an Android target. A false
        # apk classification here would be the bug this asserts against.
        plain = tmp_path / "notes.zip"
        _write_plain_zip(plain)
        refused = await mcp.call("session.create", {"binary": str(plain)})
        assert refused["ok"] is False, refused
        assert refused["error"]["code"] == "invalid_request", refused
        assert "not a PE file" in refused["error"]["message"], refused
