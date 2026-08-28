"""The capability catalog is the agent's map, and it may not lie by drifting.

``capabilities.search`` / ``capabilities.describe`` are how the agent learns
what this build can do and where to reach for it. Each entry ties a capability
to a doctor probe (``status_probe``) that decides its readiness and to the
tools it unlocks. Two silent drifts break that map without any test noticing:

* a ``status_probe`` that names no real doctor probe. ``_probe_status``
  returns the literal ``"missing"`` for an unknown probe name -- the same
  string a genuinely-absent tool reports -- so a typo'd or renamed probe pins
  a capability to "unavailable" forever, even on a host where the tool is
  installed. The status string cannot tell the two apart, so this must be
  checked against the doctor's actual probe set.
* a ``tools`` entry that names no bound tool. ``capabilities.describe`` would
  then point the agent at a phantom tool name it can never call.

Both invariants pass today; this gate exists to fail the moment the catalog
drifts from the doctor probes or the tool surface it claims. The phantom-tool
half is proven against the real MCP ``tools/list`` -- the exact surface a
client sees -- and the probe half against ``run_doctor``'s real probe set.
Pure Python, loopback stdio, any platform.
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

from headless_re_mcp.config import Settings
from headless_re_mcp.core.capabilities_catalog import _CORE_CAPABILITIES
from headless_re_mcp.doctor import ProbeStatus, run_doctor

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_KNOWN_STATUSES = {status.value for status in ProbeStatus}


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return content


class _Mcp:
    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return _structured(await self._session.call_tool(name, args))

    async def tool_names(self) -> set[str]:
        listed = await self._session.list_tools()
        return {tool.name for tool in listed.tools}


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
async def test_no_capability_points_at_a_phantom_tool(tmp_path: Path) -> None:
    async with _mcp(tmp_path / "artifacts") as mcp:
        advertised = await mcp.tool_names()
        assert advertised, "the server advertised no tools"

        searched = await mcp.call("capabilities.search", {})
        assert searched["ok"] is True, searched
        capabilities = searched["data"]["capabilities"]
        assert capabilities, "capabilities.search returned nothing"

        seen_ids: set[str] = set()
        for entry in capabilities:
            cap_id = entry["id"]
            assert cap_id not in seen_ids, f"duplicate capability id {cap_id}"
            seen_ids.add(cap_id)

            # Status is always one the doctor can actually produce, never a
            # free-form string a client would have to guess at.
            assert entry["status"] in _KNOWN_STATUSES, entry

            # Every tool a capability advertises is a tool a client can call.
            # A phantom name here is an agent sent to a dead end.
            assert entry["tools"], f"{cap_id} advertises no tools"
            phantom = [name for name in entry["tools"] if name not in advertised]
            assert not phantom, f"{cap_id} points at unbound tools: {phantom}"

            # describe(id) is the same record search returned -- the two views
            # of the catalog cannot disagree about what a capability unlocks.
            described = await mcp.call("capabilities.describe", {"capability_id": cap_id})
            assert described["ok"] is True, described
            detail = described["data"]["capability"]
            assert detail["id"] == cap_id
            assert detail["tools"] == entry["tools"], (cap_id, detail, entry)
            assert detail["status_probe"] == entry["status_probe"]

        # An unknown id is a not_found error, not an empty object a caller
        # might read as "exists but has nothing".
        unknown = await mcp.call("capabilities.describe", {"capability_id": "no.such.capability"})
        assert unknown["ok"] is False, unknown
        assert unknown["error"]["code"] == "not_found", unknown


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_every_status_probe_is_a_real_doctor_probe(tmp_path: Path) -> None:
    # The doctor's probe set is the authority for readiness. A capability whose
    # status_probe is not in it silently resolves to "missing" forever, which
    # the status string cannot be distinguished from a genuinely absent tool --
    # so the check is against the probe names themselves, not the status.
    report = run_doctor(Settings.load())
    probe_names = {probe.name for probe in report.probes}
    assert probe_names, "doctor produced no probes"

    orphans: list[tuple[str, str | None]] = []
    for capability in _CORE_CAPABILITIES:
        probe = capability.get("status_probe")
        # None is legitimate (an always-ready capability); a named probe must
        # exist.
        if probe is not None and probe not in probe_names:
            orphans.append((str(capability["id"]), probe))
    assert not orphans, f"capabilities name doctor probes that do not exist: {orphans}"

    # Well-formedness the search/describe views rely on: unique ids, and no
    # entry missing the fields a client reads.
    ids = [str(capability["id"]) for capability in _CORE_CAPABILITIES]
    assert len(ids) == len(set(ids)), f"duplicate capability ids: {ids}"
    for capability in _CORE_CAPABILITIES:
        assert str(capability.get("backend") or "").strip(), capability
        assert str(capability.get("summary") or "").strip(), capability
        assert capability.get("tools"), capability
