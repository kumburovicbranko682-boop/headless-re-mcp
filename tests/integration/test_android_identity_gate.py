"""Android identity over the wire: the APK line stands up without a decompiler.

The Android surface must not collapse to "unavailable" just because androguard
or jadx is not installed. Session creation reads cheap identity facts from the
package with nothing but the standard library -- which ABIs ship native code,
how many dex files, whether it carries a v1 signature -- so an agent can open an
APK, learn what it is, and get an honest "opened, but cannot decompile" from the
heavier tools rather than a crash or a vanished tool.

The existing Android gate proves this against the in-process service. This gate
proves the same contract across the real MCP stdio transport -- the surface an
agent actually drives -- where the adapter, the tool guard, and the JSON
envelope all sit between the caller and the parser:

* An APK is classified as ``apk`` and its stdlib metadata is exact and computed,
  not constant: native ABIs are de-duplicated and sorted, dex files counted,
  a v1 signature detected -- and a bare APK reports the empty/zero/false side of
  each so the fields are proven to move.
* A PE-only tool refuses an APK session with ``target_mismatch``, and the
  androguard-backed tools degrade to a structured ``capability_unavailable``
  envelope (never a protocol error or a raise) when the backend is absent.
* Target kind is inferred from content, not trust: a WebAssembly module is
  recognised by magic even with the wrong name, a package named ``.apk`` that
  is not a readable archive fails with a clear message, and an ordinary zip
  falls back to the original "not a PE file" error rather than a vaguer one.

Pure stdlib fixtures, stdio loopback, no backend, any platform.
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

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import classify_target

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# androguard is optional; when it is absent the backend tools must degrade to
# one of these codes rather than raise. When it is present a structured
# envelope (ok either way) is still the contract.
_DEGRADE_CODES = {"capability_unavailable", "backend_error", "backend_unavailable"}


@asynccontextmanager
async def _mcp() -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
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


def _rich_apk(path: Path) -> Path:
    """A package whose identity fields all have something to report."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00a")
        archive.writestr("classes2.dex", b"dex\n035\x00b")
        # Two libs under the same ABI must collapse to one; ABIs come back sorted.
        archive.writestr("lib/x86_64/libnative.so", b"\x7fELF64")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFa")
        archive.writestr("lib/arm64-v8a/libextra.so", b"\x7fELFb")
        archive.writestr("META-INF/CERT.RSA", b"signature-block")
        archive.writestr("resources.arsc", b"\x02\x00res")
    return path


def _bare_apk(path: Path) -> Path:
    """A package with the false/empty/zero side of every identity field."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
    return path


@pytest.mark.integration
@pytest.mark.asyncio
async def test_apk_identity_is_read_without_a_decompiler(tmp_path: Path) -> None:
    rich = _rich_apk(tmp_path / "rich.apk")
    bare = _bare_apk(tmp_path / "bare.apk")
    assert classify_target(rich) is TargetKind.APK
    assert classify_target(bare) is TargetKind.APK

    async with _mcp() as client:
        created = _envelope(await client.call_tool("session.create", {"binary": str(rich)}))
        assert created["ok"] is True, created
        session = created["data"]["session"]
        assert session["target"] == "apk", session
        meta = session["metadata"]["apk"]
        # Exact and computed: ABIs de-duplicated and sorted, dex counted, v1 seen.
        assert meta["native_abis"] == ["arm64-v8a", "x86_64"], meta
        assert meta["dex_count"] == 2, meta
        assert meta["entry_count"] == 8, meta
        assert meta["signed_v1"] is True, meta
        session_id = session["id"]

        # session.get is the same identity read back over the wire.
        fetched = _envelope(await client.call_tool("session.get", {"session_id": session_id}))
        assert fetched["data"]["session"]["metadata"]["apk"] == meta, fetched

        # A PE-only tool refuses the APK session -- a clear target_mismatch, not
        # a crash and not a tool that quietly does the wrong thing.
        refused = _envelope(await client.call_tool("static.open", {"session_id": session_id}))
        assert refused["ok"] is False, refused
        assert refused["error"]["code"] == "target_mismatch", refused

        # The androguard-backed tools answer with a structured envelope whether
        # or not the backend is installed; absent, that is capability_unavailable.
        for tool in ("apk.open", "apk.manifest", "apk.permissions", "apk.classes"):
            envelope = _envelope(await client.call_tool(tool, {"session_id": session_id}))
            assert isinstance(envelope.get("ok"), bool), (tool, envelope)
            if envelope["ok"] is False:
                assert envelope["error"]["code"] in _DEGRADE_CODES, (tool, envelope)

        # The bare package proves the fields move: everything is the empty side.
        bare_created = _envelope(await client.call_tool("session.create", {"binary": str(bare)}))
        assert bare_created["ok"] is True, bare_created
        bare_meta = bare_created["data"]["session"]["metadata"]["apk"]
        assert bare_meta["native_abis"] == [], bare_meta
        assert bare_meta["dex_count"] == 0, bare_meta
        assert bare_meta["entry_count"] == 1, bare_meta
        assert bare_meta["signed_v1"] is False, bare_meta


@pytest.mark.integration
@pytest.mark.asyncio
async def test_target_kind_is_inferred_from_content_over_mcp(tmp_path: Path) -> None:
    # A WebAssembly module recognised by magic despite a non-web name: the web
    # line claims it, not the PE fallback.
    wasm = tmp_path / "module.bin"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00" + b"\x00" * 32)

    # Named .apk but not a readable archive: a clear failure, not a raise.
    fake_apk = tmp_path / "broken.apk"
    fake_apk.write_bytes(b"this is not a zip")

    # An ordinary zip is neither APK nor PE; the fallback keeps the original
    # "not a PE file" error rather than inventing a vaguer one.
    plain_zip = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain_zip, "w") as archive:
        archive.writestr("hello.txt", b"hi")

    async with _mcp() as client:
        wasm_created = _envelope(await client.call_tool("session.create", {"binary": str(wasm)}))
        assert wasm_created["ok"] is True, wasm_created
        assert wasm_created["data"]["session"]["target"] == "web", wasm_created

        broken = _envelope(await client.call_tool("session.create", {"binary": str(fake_apk)}))
        assert broken["ok"] is False, broken
        assert broken["error"]["code"] == "invalid_request", broken
        assert "not a readable Android package" in broken["error"]["message"], broken

        zip_created = _envelope(
            await client.call_tool("session.create", {"binary": str(plain_zip)})
        )
        assert zip_created["ok"] is False, zip_created
        assert zip_created["error"]["code"] == "invalid_request", zip_created
        assert "not a PE file" in zip_created["error"]["message"], zip_created

    # The extension/URL branches of the classifier are pure functions, so pin
    # them directly: a URL and web suffixes are web, an .apk suffix is apk.
    assert classify_target("https://example.com/app.js") is TargetKind.WEB
    assert classify_target("http://example.com/") is TargetKind.WEB
    assert classify_target("/tmp/bundle.js") is TargetKind.WEB
    assert classify_target("/tmp/module.wasm") is TargetKind.WEB
    assert classify_target("/tmp/app.apk") is TargetKind.APK
