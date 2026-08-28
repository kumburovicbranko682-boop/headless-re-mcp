"""Pin what a non-positive retry budget does before it spends anything.

``test_provider_retry.py`` drives every path with a real budget -- success on
the first token, retry-then-succeed, the attempt-limit raise, the no-replay
rule -- so the one arm it never reaches is the loop that never runs at all:
``max_attempts <= 0`` makes ``range(1, max_attempts + 1)`` empty, so
``stream_chat`` returns without ever calling the wrapped provider. The property
worth pinning is that the retry count also bounds the *first* attempt: a zero
budget means zero calls, not one silent call whose output is dropped. Pinning
it documents that a mis-set budget yields an empty stream having spent no
request, rather than looking like a provider that returned nothing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.agent.providers.retrying import RetryingProvider

JsonObject = dict[str, Any]


class _CountingProvider:
    """Records whether it was ever asked to stream."""

    def __init__(self) -> None:
        self.calls = 0

    def stream_chat(self, **_kwargs: Any) -> AsyncIterator[ProviderEvent]:
        self.calls += 1
        return self._events()

    async def _events(self) -> AsyncIterator[ProviderEvent]:
        yield ProviderEvent("text_delta", text="hi")
        yield ProviderEvent("completed", tool_calls=(ProviderToolCall("c1", "t", {}),))

    async def list_models(self) -> list[str]:
        return ["fake"]


@pytest.mark.parametrize("budget", [0, -1])
@pytest.mark.asyncio
async def test_a_non_positive_budget_streams_nothing_and_never_calls_the_provider(
    budget: int,
) -> None:
    inner = _CountingProvider()
    provider = RetryingProvider(inner, max_attempts=budget)

    events = [event async for event in provider.stream_chat(messages=[], tools=[], model="m")]

    # The loop body never runs: no events, no attempt recorded, and -- the
    # point -- the wrapped provider was never asked, so no request was spent.
    assert events == []
    assert inner.calls == 0
    assert provider.attempts_made == 0


@pytest.mark.asyncio
async def test_a_budget_of_one_still_makes_exactly_one_attempt() -> None:
    # The boundary the other case is measured against: one is the smallest
    # budget that actually calls the provider, and it calls it exactly once.
    inner = _CountingProvider()
    provider = RetryingProvider(inner, max_attempts=1)

    events = [event async for event in provider.stream_chat(messages=[], tools=[], model="m")]

    assert [event.type for event in events] == ["text_delta", "completed"]
    assert inner.calls == 1
    assert provider.attempts_made == 1
