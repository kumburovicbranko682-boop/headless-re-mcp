"""Provider response limits must apply while the stream is arriving."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile
from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.agent.orchestrator import AgentOrchestrator
from headless_re_mcp.agent.providers.base import ProviderEvent
from headless_re_mcp.agent.store import AgentStore
from headless_re_mcp.tools.catalog import CommandCatalog

JsonObject = dict[str, Any]


class RunawayTextProvider:
    """A peer that keeps producing text well past the message-store ceiling."""

    def __init__(self) -> None:
        self.emitted = 0

    def stream_chat(
        self,
        *,
        messages: Sequence[JsonObject],
        tools: Sequence[JsonObject],
        model: str,
        enable_thinking: bool = False,
        reasoning_effort: str | None = None,
    ) -> AsyncIterator[ProviderEvent]:
        del messages, tools, model, enable_thinking, reasoning_effort
        return self._events()

    async def _events(self) -> AsyncIterator[ProviderEvent]:
        chunk = "x" * (256 * 1024)
        for _ in range(32):
            self.emitted += 1
            yield ProviderEvent("text_delta", text=chunk)
        yield ProviderEvent("completed")

    async def list_models(self) -> list[str]:
        return ["fake"]


async def _terminal_status(store: AgentStore, run_id: str) -> RunStatus:
    for _ in range(500):
        run = store.get_run(run_id)
        assert run is not None
        if run.status in {RunStatus.COMPLETED, RunStatus.FAILED}:
            return run.status
        await asyncio.sleep(0.01)
    raise AssertionError("run status timeout")


@pytest.mark.asyncio
async def test_provider_text_is_bounded_before_the_whole_stream_is_buffered(
    tmp_path: Path,
) -> None:
    """The 1 MiB message ceiling must also be the streaming memory ceiling.

    The store rejects an oversized assistant message, but that check used to
    run only after all 32 chunks (8 MiB) were retained and the stream ended.
    The fifth 256 KiB chunk is the first one over the existing 1 MiB ceiling,
    so the peer must be stopped there and the run must name that boundary.
    """
    configs = ProviderConfigStore(tmp_path / "providers.json")
    configs.save(
        ProviderProfile(
            "default",
            "https://example.invalid",
            "fake",
            api_key="not-used",
        )
    )
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    provider = RunawayTextProvider()
    runner = AgentOrchestrator(
        store,
        CommandCatalog([]),
        configs,
        provider_factory=lambda _profile: provider,
    )

    run_data = await runner.start_run(thread.id)
    status = await _terminal_status(store, str(run_data["id"]))
    run = store.get_run(str(run_data["id"]))

    assert status is RunStatus.FAILED
    assert provider.emitted <= 5, (
        f"the 1 MiB limit was known but the provider emitted {provider.emitted * 256} KiB"
    )
    assert run is not None
    assert "provider_response_too_large" in str(run.error)
