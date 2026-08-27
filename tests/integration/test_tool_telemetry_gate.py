"""Live Gate for tool-call telemetry, driven through a real MCP server.

An unattended deployment reads its own health from ``meta.metrics`` and the
Prometheus ``/metrics`` scrape: per-tool call counts, failure counts, and
latency percentiles. Those numbers are only produced when a tool is dispatched
through the transport instrumentation (``telemetry.instrument``), which the MCP
server applies in ``register_tool`` -- the direct ``service.*`` path and the
agent ``catalog.invoke`` path deliberately do not record, so unit tests that
call the ring in isolation never prove the dispatch wiring. A regression that
stopped recording, double-counted, or mislabelled a failure as a success would
pass every unit test and quietly blind an operator.

This gate spawns the real ``python -m headless_re_mcp serve`` process (isolated
to a per-test artifact root, so the telemetry ring starts empty and only the
calls this test makes are counted) and drives a deterministic set of tools over
stdio: one session create, one knowledge query, two artifact lists, and one
deliberately failing ``artifacts.describe``. It then reads ``meta.metrics``
twice -- the second read captures the first metrics call -- and asserts the
counts are exact (not merely present): each tool's ``calls_total`` matches how
many times it was invoked, the failing tool alone carries ``failures_total==1``,
the process totals add up, latency percentiles are ordered floats, and the
``recent`` ring reflects the failure's error code and the session id on
session-scoped calls. It also pins the ``limit`` guard. Requires only the
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
_PE = _REPO / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _parameters(tmp_path: Path) -> StdioServerParameters:
    env = os.environ.copy()
    # A fresh artifact root means a fresh process and a telemetry ring that
    # starts empty, so the counts below are exact rather than "at least".
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


@pytest.mark.integration
@pytest.mark.asyncio
async def test_meta_metrics_counts_dispatched_tool_calls_exactly(tmp_path: Path) -> None:
    if not _PE.is_file():
        pytest.skip(f"fixture missing: {_PE}")

    async with (
        stdio_client(_parameters(tmp_path)) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()

        created = _structured(await client.call_tool("session.create", {"binary": str(_PE)}))
        assert created["ok"] is True
        session_id = str(created["data"]["session"]["id"])

        async def _call_ok(name: str, args: dict[str, Any]) -> None:
            assert _structured(await client.call_tool(name, args))["ok"]

        await _call_ok("knowledge.query", {"session_id": session_id})
        await _call_ok("artifacts.list", {"session_id": session_id})
        await _call_ok("artifacts.list", {"session_id": session_id})

        failed = _structured(
            await client.call_tool("artifacts.describe", {"artifact_id": "f" * 32})
        )
        assert failed["ok"] is False
        assert failed["error"]["code"] == "not_found"

        # First read is itself recorded but returns before its own record lands;
        # the second read is where that first meta.metrics call shows up, which
        # is what makes the meta.metrics count below exactly one.
        assert _structured(await client.call_tool("meta.metrics", {"limit": 0}))["ok"]
        metrics = _structured(await client.call_tool("meta.metrics", {"limit": 200}))
        assert metrics["ok"] is True
        data = metrics["data"]

        by_tool = {row["tool"]: row for row in data["tools"]}
        expected_calls = {
            "session.create": 1,
            "knowledge.query": 1,
            "artifacts.list": 2,
            "artifacts.describe": 1,
            "meta.metrics": 1,
        }
        for name, count in expected_calls.items():
            assert name in by_tool, f"{name} missing from metrics"
            assert by_tool[name]["calls_total"] == count, (name, by_tool[name])

        # Only the describe miss is a failure; every other tool succeeded.
        assert by_tool["artifacts.describe"]["failures_total"] == 1
        for name in ("session.create", "knowledge.query", "artifacts.list", "meta.metrics"):
            assert by_tool[name]["failures_total"] == 0, name

        # Process totals are the sum of the per-tool counters, not a separate
        # tally that could drift from them.
        assert data["calls_total"] == sum(expected_calls.values())
        assert data["failures_total"] == 1
        assert data["distinct_tools"] == len(expected_calls)
        assert data["capacity"] >= data["sampled_calls"] >= 1

        # Latency percentiles are real, ordered floats.
        row = by_tool["artifacts.list"]
        for field in ("p50_ms", "p95_ms", "max_ms"):
            assert isinstance(row[field], float)
        assert row["max_ms"] >= row["p95_ms"] >= row["p50_ms"] >= 0.0

        # The recent ring carries the failure's error code and the session id
        # for session-scoped calls -- the detail an operator triages from.
        recent = data["recent"]
        assert isinstance(recent, list) and recent
        describe_records = [item for item in recent if item["tool"] == "artifacts.describe"]
        assert describe_records and describe_records[0]["ok"] is False
        assert describe_records[0]["error_code"] == "not_found"
        query_records = [item for item in recent if item["tool"] == "knowledge.query"]
        assert query_records and query_records[0]["session_id"] == session_id


@pytest.mark.integration
@pytest.mark.asyncio
async def test_meta_metrics_limit_is_guarded(tmp_path: Path) -> None:
    async with (
        stdio_client(_parameters(tmp_path)) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()

        # Out-of-range limit is rejected by the tool's own input schema before
        # dispatch -- 0..200 is the contract, enforced at the protocol edge, so
        # the call comes back flagged as an error rather than a normal result.
        too_big = await client.call_tool("meta.metrics", {"limit": 201})
        assert too_big.isError is True
        assert too_big.structuredContent is None

        # limit=0 is valid and means "totals only, no recent sample".
        totals_only = _structured(await client.call_tool("meta.metrics", {"limit": 0}))
        assert totals_only["ok"] is True
        assert totals_only["data"]["recent"] == []
