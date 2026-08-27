"""Live Gate for capability discovery, driven through a real MCP server.

Before an agent can plan it has to know what this install can actually do:
``capabilities.search`` and ``capabilities.describe`` are how it discovers which
backends exist (IDA, x64dbg, radare2, Ghidra, Frida, androguard/jadx/apktool,
Playwright, webcrack, wabt, mitmproxy, ADB), which tools each exposes, and
whether each is ``ready`` or ``missing`` on this machine. The catalog itself is
unit-pinned to the real tool names and doctor probes, but that its two lookups
are actually reachable over the transport, filter honestly, and refuse an
unknown id -- rather than answering an empty object -- had no end-to-end gate.

This gate spawns the real ``python -m headless_re_mcp serve`` process and drives
the two tools over stdio. It pins the discovery surface (the non-PE lines the
project is maturing -- radare2, Ghidra, Android, Web -- are all advertised),
checks every entry's shape and that status is one of the doctor's own status
values, proves the backend filter narrows to exactly one backend's capabilities
and the status filter is self-consistent (both strict subsets of the whole),
and proves ``describe`` returns one capability by id while an unknown id fails
with ``not_found``. It asserts the *contract*, not which backends happen to be
installed, so it is always green regardless of toolchain. Requires only the
checkout and the installed package, so it never skips.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_REPO = Path(__file__).resolve().parents[2]

# Doctor's own status vocabulary (headless_re_mcp.doctor.ProbeStatus).
_STATUS_VALUES = {"ready", "detected", "missing", "blocked", "unsupported_on_platform"}

# A stable subset of the fixed catalog. These ids are literals in
# capabilities_catalog._CORE_CAPABILITIES; the non-PE lines are called out
# explicitly because advertising them is what lets an agent reach them.
_EXPECTED_IDS = {
    "ida.idalib",
    "x64dbg.headless",
    "r2.pipe",
    "ghidra.headless",
    "frida.session",
    "apk.androguard",
    "apk.jadx",
    "apk.apktool",
    "web.cdp",
    "jsre.webcrack",
    "wasm.wabt",
    "proxy.mitmproxy",
}
_REQUIRED_KEYS = {"id", "backend", "status", "status_probe", "summary", "tools"}


def _parameters(tmp_path: Path) -> StdioServerParameters:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=_REPO,
    )


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"no structured content: {result!r}"
    return content


def _ok(envelope: dict[str, Any]) -> dict[str, Any]:
    assert envelope["ok"] is True, envelope.get("error")
    data = envelope["data"]
    assert isinstance(data, dict)
    return data


@pytest.mark.integration
@pytest.mark.asyncio
async def test_capabilities_search_advertises_the_backend_surface(tmp_path: Path) -> None:
    async with (
        stdio_client(_parameters(tmp_path)) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()

        data = _ok(_structured(await client.call_tool("capabilities.search", {})))
        capabilities = data["capabilities"]
        assert isinstance(capabilities, list) and capabilities
        assert data["count"] == len(capabilities)

        by_id = {entry["id"]: entry for entry in capabilities}
        assert len(by_id) == len(capabilities), "capability ids must be unique"
        # The non-PE lines under active maturation are all discoverable.
        assert set(by_id) >= _EXPECTED_IDS, sorted(_EXPECTED_IDS - set(by_id))

        for entry in capabilities:
            assert set(entry) >= _REQUIRED_KEYS, (entry["id"], sorted(_REQUIRED_KEYS - set(entry)))
            assert entry["status"] in _STATUS_VALUES, entry
            assert isinstance(entry["tools"], list) and entry["tools"]
            assert entry["summary"]

        # r2.pipe advertises the radare2 tool line an agent would call.
        assert "r2.open" in by_id["r2.pipe"]["tools"]
        assert by_id["r2.pipe"]["backend"] == "radare2"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_capabilities_filters_are_honest_subsets(tmp_path: Path) -> None:
    async with (
        stdio_client(_parameters(tmp_path)) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()

        everything = _ok(_structured(await client.call_tool("capabilities.search", {})))
        total = everything["count"]

        # The web backend has more than one capability, so a backend filter is
        # a real narrowing, and every row it returns is that backend.
        web = _ok(_structured(await client.call_tool("capabilities.search", {"backend": "web"})))
        web_caps = web["capabilities"]
        assert web_caps and web["count"] == len(web_caps)
        assert 0 < len(web_caps) < total
        assert {entry["backend"] for entry in web_caps} == {"web"}
        assert {"web.cdp", "jsre.webcrack", "wasm.wabt"} <= {entry["id"] for entry in web_caps}

        # A status filter, using a status actually present, returns only that
        # status and is a strict subset of the whole.
        present_status = everything["capabilities"][0]["status"]
        filtered = _ok(
            _structured(await client.call_tool("capabilities.search", {"status": present_status}))
        )
        rows = filtered["capabilities"]
        assert rows and {entry["status"] for entry in rows} == {present_status}
        assert filtered["count"] <= total

        # A backend nobody advertises is an empty page, not an error.
        none = _ok(
            _structured(
                await client.call_tool("capabilities.search", {"backend": "no-such-backend"})
            )
        )
        assert none["capabilities"] == []
        assert none["count"] == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_capabilities_describe_by_id_and_unknown(tmp_path: Path) -> None:
    async with (
        stdio_client(_parameters(tmp_path)) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()

        described = _ok(
            _structured(
                await client.call_tool(
                    "capabilities.describe", {"capability_id": "ghidra.headless"}
                )
            )
        )
        capability = described["capability"]
        assert capability["id"] == "ghidra.headless"
        assert capability["backend"] == "ghidra"
        assert "ghidra.analyze" in capability["tools"]
        assert capability["status"] in _STATUS_VALUES
        # The payload is nested under "capability"; those keys are not top-level.
        assert "backend" not in described

        missing = _structured(
            await client.call_tool("capabilities.describe", {"capability_id": "does.not.exist"})
        )
        assert missing["ok"] is False
        assert missing["error"]["code"] == "not_found"
