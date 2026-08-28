"""Telemetry accounting: the numbers an operator watches must be true.

``meta.metrics`` is what an unattended deployment scrapes to know how much
work happened and how much of it failed -- per-tool call counts, a failure
tally, and latency percentiles, plus lifetime ``*_total`` counters that are
safe to build an alert rate on. If those numbers drift from what actually
happened, every dashboard and every error-budget alarm built on them is
quietly wrong, and nobody finds out until an incident.

The contract has sharp edges worth pinning, and none of them need a backend:

* Every call is counted against the right tool and the right outcome. A tool
  that returns an ``ok=False`` envelope is a failure, an ``ok=True`` one is not,
  and the totals add up across tools to the aggregate.
* A freshly started process reports honest zeros -- empty ``tools``, zero
  counters, a real ``capacity`` -- not ``null`` and not an error.
* The lifetime ``*_total`` counters are cumulative and never fall between
  snapshots, and ``meta.metrics`` counts its own earlier calls (it is an
  instrumented tool like any other), so a rate computed from them is monotone.
* ``limit`` only truncates the ``recent`` window; it never changes the
  aggregate counts, and ``recent`` is newest-first.

A subtlety the gate relies on: a ``meta.metrics`` call is recorded *after* its
handler reads the ring, so a snapshot never counts itself -- only the calls
that finished before it. Everything runs over the real MCP stdio transport
against a fresh server whose ring starts empty; pure stdlib, any platform.
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

from headless_re_mcp.telemetry import DEFAULT_CAPACITY

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


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
    assert isinstance(content, dict), f"no structuredContent: {result!r}"
    return content


def _data(result: object) -> dict[str, Any]:
    content = _envelope(result)
    assert content.get("ok") is True, content
    data = content["data"]
    assert isinstance(data, dict), content
    return data


async def _metrics(client: ClientSession, **kwargs: Any) -> dict[str, Any]:
    return _data(await client.call_tool("meta.metrics", kwargs))


def _by_tool(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["tool"]: entry for entry in snapshot["tools"]}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_metrics_account_for_every_call_by_tool_and_outcome() -> None:
    successes, failures = 3, 2
    async with _mcp() as client:
        # A tool that always succeeds, and one that always returns an ok=False
        # envelope (unknown id -> not_found), so the outcome split is known.
        for _ in range(successes):
            ok = _envelope(await client.call_tool("capabilities.search", {"query": ""}))
            assert ok["ok"] is True, ok
        for _ in range(failures):
            bad = _envelope(
                await client.call_tool(
                    "capabilities.describe", {"capability_id": "no.such.capability"}
                )
            )
            assert bad["ok"] is False, bad

        # This snapshot does not count itself: only the five calls before it.
        snap = await _metrics(client)

    assert snap["capacity"] == DEFAULT_CAPACITY, snap
    assert snap["sampled_calls"] == successes + failures, snap
    assert snap["calls_total"] == successes + failures, snap
    assert snap["failures"] == failures, snap
    assert snap["failures_total"] == failures, snap
    assert snap["distinct_tools"] == 2, snap

    tools = _by_tool(snap)
    # The metrics call is recorded only after it reads the ring, so it is not
    # in its own first snapshot.
    assert set(tools) == {"capabilities.search", "capabilities.describe"}, tools

    search = tools["capabilities.search"]
    assert search["calls"] == successes and search["calls_total"] == successes, search
    assert search["failures"] == 0 and search["failures_total"] == 0, search

    describe = tools["capabilities.describe"]
    assert describe["calls"] == failures and describe["calls_total"] == failures, describe
    assert describe["failures"] == failures and describe["failures_total"] == failures, describe

    # Per-tool totals reconcile with the aggregate, and percentiles are ordered
    # and non-negative for every tool that has samples.
    assert sum(t["calls_total"] for t in snap["tools"]) == snap["calls_total"], snap
    assert sum(t["failures_total"] for t in snap["tools"]) == snap["failures_total"], snap
    for entry in snap["tools"]:
        assert 0.0 <= entry["p50_ms"] <= entry["p95_ms"] <= entry["max_ms"], entry

    # recent is newest-first and carries the outcome of each call: the last
    # thing before the snapshot was a failing describe.
    recent = snap["recent"]
    assert len(recent) == successes + failures, recent
    assert recent[0]["tool"] == "capabilities.describe", recent[0]
    assert recent[0]["ok"] is False and recent[0]["error_code"] == "not_found", recent[0]
    search_records = [r for r in recent if r["tool"] == "capabilities.search"]
    assert all(r["ok"] is True and r["error_code"] is None for r in search_records), recent
    for record in recent:
        assert set(record) >= {"tool", "ok", "duration_ms", "at", "error_code", "session_id"}, (
            record
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_totals_are_cumulative_and_count_the_metrics_call_itself() -> None:
    async with _mcp() as client:
        # A brand-new process reports honest zeros, not null and not an error.
        zero = await _metrics(client)
        assert zero["tools"] == [], zero
        assert zero["recent"] == [], zero
        for field in (
            "sampled_calls",
            "distinct_tools",
            "failures",
            "calls_total",
            "failures_total",
        ):
            assert zero[field] == 0, (field, zero)
        assert zero["capacity"] == DEFAULT_CAPACITY, zero

        for _ in range(2):
            await client.call_tool("capabilities.search", {"query": ""})
        await client.call_tool("capabilities.describe", {"capability_id": "no.such.capability"})

        # The ring now holds the first (zero) metrics call plus 2 + 1 = 3 more.
        first = await _metrics(client, limit=50)
        assert first["calls_total"] == 1 + 2 + 1, first
        assert first["failures_total"] == 1, first
        # meta.metrics counts its own earlier call: exactly the zero snapshot.
        assert _by_tool(first)["meta.metrics"]["calls_total"] == 1, first

        await client.call_tool("capabilities.search", {"query": ""})

        # limit=1 truncates recent to the single newest record without touching
        # the aggregate counts.
        second = await _metrics(client, limit=1)
        assert len(second["recent"]) == 1, second
        assert second["recent"][0]["tool"] == "capabilities.search", second["recent"][0]
        assert second["calls_total"] == 1 + 2 + 1 + 1 + 1, second
        assert second["failures_total"] == 1, second
        # Two metrics calls have now finished before this one.
        assert _by_tool(second)["meta.metrics"]["calls_total"] == 2, second

    # Lifetime totals only ever climb; a rate built on them is monotone.
    assert zero["calls_total"] < first["calls_total"] < second["calls_total"], (
        zero["calls_total"],
        first["calls_total"],
        second["calls_total"],
    )
    assert zero["failures_total"] <= first["failures_total"] <= second["failures_total"], (
        zero["failures_total"],
        first["failures_total"],
        second["failures_total"],
    )
