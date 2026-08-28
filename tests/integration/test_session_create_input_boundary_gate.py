"""session.create input-boundary contract over a real MCP stdio server.

``session.create`` is the first call every deployment makes, and it is the one
tool a caller reaches with arbitrary, possibly hostile paths. The contract is
that every bad input comes back as a *structured* envelope naming what was
wrong -- never an ``internal_error`` incident, which is the catch-all for a
defect in this process, not for a caller handing over a path that cannot be
opened.

This pins the boundary end-to-end over stdio, pure-stdlib fixtures:

  * A path that does not exist is ``file_not_found``.
  * A directory, an empty file, and a file whose contents are not a recognised
    format are ``invalid_request`` with a message that says which check failed.
  * A target that exists but cannot be *read at all* (permission denied) is a
    structured ``invalid_request`` -- "cannot read session target" -- not an
    ``internal_error`` incident. This is a regression guard: the unreadable path
    used to escape as an unexpected ``PermissionError`` because ``classify_target``
    swallows the read error and falls back to PE, after which the architecture
    probe reopened the file and threw.
  * A valid PE opens as ``pe``; an explicit ``target`` override is honoured over
    the sniffed content (a PE opened as ``web``); an ``http`` URL opens as
    ``web``; and forcing ``target=apk`` on non-APK bytes fails cleanly rather
    than crashing.

No bad input, anywhere in the table, is allowed to answer ``internal_error``.
Pure-stdlib fixtures, stdio loopback, no backend, any platform.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _envelope(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"expected a structured envelope, got {content!r}"
    return content


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


def _make_unreadable(path: Path, data: bytes) -> bool:
    """Write a file then drop all permissions; return whether it is truly unreadable.

    Running as root (or on a filesystem that ignores mode bits) can still read a
    0-mode file, in which case the caller should skip -- the path under test
    cannot be exercised there.
    """
    path.write_bytes(data)
    os.chmod(path, 0)
    try:
        with open(path, "rb") as handle:
            handle.read(1)
    except OSError:
        return True
    return False


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


async def _create(client: ClientSession, args: dict[str, Any]) -> dict[str, Any]:
    return _envelope(await client.call_tool("session.create", args))


@pytest.mark.integration
@pytest.mark.asyncio
async def test_session_create_refuses_bad_inputs_with_structured_errors(
    tmp_path: Path,
) -> None:
    (tmp_path / "empty.bin").write_bytes(b"")
    (tmp_path / "text.txt").write_text("plain ascii, not any binary format\n")
    (tmp_path / "tiny.bin").write_bytes(b"MZ")  # too short to be a real PE
    directory = tmp_path / "adir"
    directory.mkdir()

    cases: list[tuple[dict[str, Any], str, str]] = [
        ({"binary": str(tmp_path / "does_not_exist.bin")}, "file_not_found", ""),
        ({"binary": "relative/missing/path.bin"}, "file_not_found", ""),
        ({"binary": str(directory)}, "invalid_request", "not a regular file"),
        ({"binary": str(tmp_path / "empty.bin")}, "invalid_request", "not a PE file"),
        ({"binary": str(tmp_path / "text.txt")}, "invalid_request", "not a PE file"),
        ({"binary": str(tmp_path / "tiny.bin")}, "invalid_request", "not a PE file"),
        (
            {"binary": str(tmp_path / "text.txt"), "target": "apk"},
            "invalid_request",
            "not a readable Android package",
        ),
    ]
    async with _mcp(tmp_path / "artifacts") as client:
        for args, expected_code, needle in cases:
            envelope = await _create(client, args)
            code, msg = _err(envelope)
            assert envelope.get("ok") is False, (args, envelope)
            # The headline invariant: a bad input is never an incident.
            assert code != "internal_error", (args, code, msg)
            assert code == expected_code, (args, code, msg)
            if needle:
                assert needle in msg, (args, needle, msg)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_an_unreadable_target_is_structured_not_an_incident(
    tmp_path: Path,
) -> None:
    pe = tmp_path / "noperm.exe"
    if not _make_unreadable(pe, b"MZ\x00\x00padding-bytes"):
        pytest.skip("cannot create an unreadable file here (running as root?)")
    web_asset = tmp_path / "noperm.js"
    assert _make_unreadable(web_asset, b"(function(){})();")

    async with _mcp(tmp_path / "artifacts") as client:
        # Sniffed as PE (classify_target falls back to PE when it cannot read),
        # so the architecture probe reopens the file -- the old incident path.
        pe_env = await _create(client, {"binary": str(pe)})
        code, msg = _err(pe_env)
        assert pe_env.get("ok") is False, pe_env
        assert code == "invalid_request", (code, msg)
        assert "cannot read session target" in msg, msg
        assert "incident" not in msg, msg

        # The web local-asset branch reads the file for its digest; same guard.
        web_env = await _create(client, {"binary": str(web_asset), "target": "web"})
        code, msg = _err(web_env)
        assert web_env.get("ok") is False, web_env
        assert code == "invalid_request", (code, msg)
        assert "cannot read session target" in msg, msg
        assert "incident" not in msg, msg


@pytest.mark.integration
@pytest.mark.asyncio
async def test_valid_targets_and_explicit_overrides_are_accepted(
    tmp_path: Path,
) -> None:
    pe = _write_pe(tmp_path / "ok.exe")

    async with _mcp(tmp_path / "artifacts") as client:
        # A valid PE opens as pe with a detected architecture and a digest.
        ok = _envelope(await client.call_tool("session.create", {"binary": str(pe)}))
        assert ok.get("ok") is True, ok
        session = ok["data"]["session"]
        assert session["target"] == "pe", session
        assert session["architecture"] == "x64", session
        assert session["sha256"], session

        # An explicit target override is honoured over the sniffed content.
        forced_web = _envelope(
            await client.call_tool(
                "session.create", {"binary": str(pe), "target": "web"}
            )
        )
        assert forced_web.get("ok") is True, forced_web
        assert forced_web["data"]["session"]["target"] == "web", forced_web

        # A remote URL opens as a web session with no local binary.
        url = _envelope(
            await client.call_tool(
                "session.create", {"binary": "https://example.com/app.js"}
            )
        )
        assert url.get("ok") is True, url
        assert url["data"]["session"]["target"] == "web", url
