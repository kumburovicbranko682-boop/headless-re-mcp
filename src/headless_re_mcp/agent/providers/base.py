"""Provider streaming port."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

JsonObject = dict[str, Any]


@dataclass(frozen=True, slots=True)
class ProviderToolCall:
    id: str
    name: str
    arguments: JsonObject


@dataclass(frozen=True, slots=True)
class ProviderEvent:
    type: str
    text: str | None = None
    tool_calls: tuple[ProviderToolCall, ...] = ()
    finish_reason: str | None = None
    output_tokens: int | None = None


class ProviderPort(Protocol):
    def stream_chat(
        self,
        *,
        messages: Sequence[JsonObject],
        tools: Sequence[JsonObject],
        model: str,
        enable_thinking: bool = False,
        reasoning_effort: str | None = None,
    ) -> AsyncIterator[ProviderEvent]: ...

    async def list_models(self) -> list[str]: ...
