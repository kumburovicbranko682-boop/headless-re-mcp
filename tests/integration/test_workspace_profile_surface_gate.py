"""Workspace-profile tool-surface gate over a real MCP stdio server.

A workspace profile is the operator's way of telling the server which work
direction a deployment is for, and the promise is concrete: it shrinks the tool
surface the *client* (an LLM) actually sees over ``tools/list``. An Android
deployment must not advertise the PE unpackers or a web-only DOM tool to the
model, and a PE deployment must not advertise the Android device bridge. A unit
test can check the prefix table; only a gate over the real transport proves the
served ``tools/list`` genuinely shrinks per profile.

This pins the contract end-to-end, spawning one stdio server per profile:

  * ``full`` hides nothing -- it is the single authority and a strict superset
    of every other profile.

  * Each non-full profile removes *exactly* the tools under its hidden prefixes
    and nothing else: ``pe`` hides the Android + Web + shared-proxy surface;
    ``android`` hides only the Web-static surface; ``web`` hides only the
    Android surface. The served set equals full minus those prefixes, so
    trimming never grazes a core tool.

  * The interception proxy is shared by Android and Web (it captures browser
    traffic in a web session and, via ``proxy.ca.install_android``, a device's
    TLS in an android session), so ``proxy.*`` stays visible in both android and
    web and is hidden only in pe. This is a deliberate regression guard: proxy
    was once grouped under the web prefixes, which wrongly hid the whole proxy
    surface -- including the android-only ``proxy.ca.install_android`` -- from
    the android work direction.

  * Core tools (session/static/artifacts/report/capabilities/meta) survive every
    profile, because trimming is by optional-direction prefix only.

The expected hidden prefixes are written out here as an independent spec rather
than imported from the code under test, so the gate fails if the table drifts.
Pure stdio loopback, no backend, any platform.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# The contract, restated independently of the implementation's prefix table.
_ANDROID = ("apk.", "device.")
_WEB = ("web.", "js.", "wasm.")
_PROXY = ("proxy.",)
_EXPECTED_HIDDEN: dict[str, tuple[str, ...]] = {
    "full": (),
    "pe": _ANDROID + _WEB + _PROXY,
    "android": _WEB,
    "web": _ANDROID,
}


async def _surface(profile: str, artifact_root: Path) -> frozenset[str]:
    env = os.environ.copy()
    env["HEADLESS_RE_WORKSPACE_PROFILE"] = profile
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root / profile)
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
        listed = await client.list_tools()
        return frozenset(tool.name for tool in listed.tools)


@pytest.fixture(scope="module")
def surfaces() -> dict[str, frozenset[str]]:
    """The served tools/list for every profile, collected once over real stdio."""

    async def _collect() -> dict[str, frozenset[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result: dict[str, frozenset[str]] = {}
            for profile in _EXPECTED_HIDDEN:
                result[profile] = await _surface(profile, root)
            return result

    return asyncio.run(_collect())


def _under(names: frozenset[str], prefixes: tuple[str, ...]) -> set[str]:
    return {n for n in names if n.startswith(prefixes)}


@pytest.mark.integration
def test_each_profile_trims_exactly_its_prefixes_and_full_is_the_superset(
    surfaces: dict[str, frozenset[str]],
) -> None:
    full = surfaces["full"]

    # The gate is only meaningful if full actually carries every family it may
    # trim; otherwise "hidden" would be vacuously satisfied.
    for prefix in _ANDROID + _WEB + _PROXY:
        assert _under(full, (prefix,)), f"full profile has no {prefix}* tool to hide"

    for profile, hidden in _EXPECTED_HIDDEN.items():
        served = surfaces[profile]
        # Trimming removes exactly the hidden-prefix tools -- no more, no less.
        expected = frozenset(n for n in full if not n.startswith(hidden))
        assert served == expected, {
            "profile": profile,
            "unexpectedly_hidden": sorted(expected - served),
            "unexpectedly_present": sorted(served - expected),
        }
        # And nothing under a hidden prefix survives.
        assert not _under(served, hidden), (profile, sorted(_under(served, hidden)))
        # Every profile is a subset of full; non-full ones are strictly smaller.
        assert served <= full
        if profile != "full":
            assert served < full, profile


@pytest.mark.integration
def test_proxy_is_shared_by_android_and_web_and_hidden_only_in_pe(
    surfaces: dict[str, frozenset[str]],
) -> None:
    # Visible wherever it is meaningful...
    for profile in ("full", "android", "web"):
        assert _under(surfaces[profile], _PROXY), f"proxy.* missing from {profile}"
    # ...including the android-only CA push, the exact tool the old regression
    # hid from the android work direction.
    assert "proxy.ca.install_android" in surfaces["android"]
    assert "proxy.ca.install_android" in surfaces["web"]
    # Hidden only in the PE direction.
    assert not _under(surfaces["pe"], _PROXY), sorted(_under(surfaces["pe"], _PROXY))


@pytest.mark.integration
def test_core_tools_survive_every_profile(
    surfaces: dict[str, frozenset[str]],
) -> None:
    core = (
        "session.create",
        "session.list",
        "static.functions",
        "artifacts.list",
        "report.generate",
        "capabilities.search",
        "meta.metrics",
    )
    for profile, served in surfaces.items():
        missing = [name for name in core if name not in served]
        assert not missing, {"profile": profile, "missing_core_tools": missing}
