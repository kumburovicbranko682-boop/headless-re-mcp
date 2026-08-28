"""Artifact GC: an unattended server reclaims disk without eating fresh results.

A long-running deployment writes artifacts -- reports, decompilations, captures
-- and its disk must not grow without bound. ``artifacts.gc`` is the tool that
holds the line: it deletes registered artifacts oldest-first until the tree fits
a byte budget. Two properties make it safe to run unattended, and both are
easy to break silently:

* it evicts oldest-first and stops at the budget, so the space it reclaims and
  the artifacts it keeps are exactly what the budget implies; and
* it never deletes the newest artifact, even when the budget is smaller than
  that artifact -- reclaiming space must not strand the result a caller just
  produced and is about to read.

Both are observable at the MCP boundary with nothing but ``report.generate`` to
mint artifacts, so this gate drives the real stdio transport: it generates
several report artifacts of known size, reads their sizes and newest-first
order back from ``artifacts.list``, and then pins what ``artifacts.gc`` removes,
keeps, and reports for a budget that spares everything, a budget that clips the
oldest, and a budget below a single artifact.

Pure stdlib, stdio loopback, no analysis backend, any platform.
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

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


@asynccontextmanager
async def _mcp(artifact_root: Path) -> AsyncIterator[ClientSession]:
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
        ClientSession(read, write) as client,
    ):
        await client.initialize()
        yield client


def _data(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"no structuredContent: {result!r}"
    assert content.get("ok") is True, content
    data = content["data"]
    assert isinstance(data, dict), content
    return data


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


async def _mint_reports(client: ClientSession, pe: Path, count: int) -> list[dict[str, Any]]:
    """Generate `count` report artifacts, one per session, oldest first."""
    for index in range(count):
        session_id = _data(await client.call_tool("session.create", {"binary": str(pe)}))[
            "session"
        ]["id"]
        # A recorded fact makes the report a real document rather than a stub.
        await client.call_tool(
            "knowledge.record",
            {"session_id": session_id, "kind": "note", "key": f"n{index}", "value": {"i": index}},
        )
        await client.call_tool("report.generate", {"session_id": session_id})
    listed = _data(await client.call_tool("artifacts.list", {}))
    artifacts = [dict(artifact) for artifact in listed["artifacts"]]
    assert listed["total"] == count, listed
    assert len(artifacts) == count, listed
    return artifacts


def _ids(listed: dict[str, Any]) -> list[str]:
    return [artifact["id"] for artifact in listed["artifacts"]]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_gc_evicts_oldest_first_and_respects_the_budget(tmp_path: Path) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        artifacts = await _mint_reports(client, pe, 4)
        # artifacts.list is newest-first; identify age by that order.
        created = [artifact["created_at"] for artifact in artifacts]
        assert len(set(created)) == len(created), created  # distinct timestamps
        sizes = [artifact["size"] for artifact in artifacts]
        total = sum(sizes)
        oldest = artifacts[-1]
        newest_three = {artifact["id"] for artifact in artifacts[:3]}

        # A budget above the tree removes nothing and reports the full size.
        spare = _data(await client.call_tool("artifacts.gc", {"max_total_bytes": total + 4096}))
        assert spare["count"] == 0, spare
        assert spare["skipped_count"] == 0 and spare["invalid_path_count"] == 0, spare
        assert spare["bytes_remaining_estimate"] == total, spare
        assert _data(await client.call_tool("artifacts.list", {}))["total"] == 4

        # A budget one artifact short of the tree clips exactly the oldest.
        clip = _data(
            await client.call_tool("artifacts.gc", {"max_total_bytes": total - oldest["size"]})
        )
        assert clip["count"] == 1, clip
        assert clip["bytes_remaining_estimate"] == total - oldest["size"], clip
        after = _data(await client.call_tool("artifacts.list", {}))
        assert after["total"] == 3, after
        # The oldest is gone; the three newest survived.
        assert oldest["id"] not in _ids(after), after
        assert set(_ids(after)) == newest_three, after


@pytest.mark.integration
@pytest.mark.asyncio
async def test_gc_always_keeps_the_newest_artifact(tmp_path: Path) -> None:
    pe = _write_pe(tmp_path / "sample.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        artifacts = await _mint_reports(client, pe, 3)
        newest = artifacts[0]

        # A budget far below a single artifact still spares the newest one:
        # reclaiming space must not strand the freshest result.
        swept = _data(await client.call_tool("artifacts.gc", {"max_total_bytes": 1}))
        assert swept["count"] == 2, swept
        assert swept["bytes_remaining_estimate"] == newest["size"], swept
        assert swept["invalid_path_count"] == 0, swept
        remaining = _data(await client.call_tool("artifacts.list", {}))
        assert remaining["total"] == 1, remaining
        assert _ids(remaining) == [newest["id"]], remaining

        # Running it again cannot drop below that floor: the newest stays.
        again = _data(await client.call_tool("artifacts.gc", {"max_total_bytes": 1}))
        assert again["count"] == 0, again
        assert again["bytes_remaining_estimate"] == newest["size"], again
        assert _ids(_data(await client.call_tool("artifacts.list", {}))) == [newest["id"]]
