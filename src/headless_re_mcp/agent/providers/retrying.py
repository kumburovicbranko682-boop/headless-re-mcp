"""Survive a provider that is briefly unavailable.

Rate limits and 5xx are routine on hosted inference, and a mission that dies on
one wastes its whole budget on a fault that would have cleared in seconds. A run
is also the unit an operator sees fail, so retrying below it keeps a transient
provider blip from looking like an analysis failure.

The hard rule is that a retry may only happen before the stream has produced
anything. Once a token has been handed to the caller the request is no longer
idempotent from their point of view: replaying it would duplicate output and, if
the model had already emitted tool calls, could run a tool twice.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderPort
from headless_re_mcp.telemetry import record_alert

JsonObject = dict[str, Any]

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_TRANSIENT_MARKERS = ("timeout", "connect", "network", "remote protocol", "temporarily")

_MAX_ALERT_ERROR_CHARS = 300
_TRUNCATION_MARKER = "...[truncated]"


def _bounded_error(exc: BaseException) -> str:
    """The alert's error field, cut to its budget with the cut marked.

    The provider deliberately appends the HTTP error body to the exception it
    re-raises -- that body is where a host says which limit was hit and for how
    long -- so this text routinely exceeds the alert budget, and the operative
    detail sits past the cut. A bare slice read as the whole error; mark it,
    keeping the result within the same budget collectors already rely on.
    """
    text = f"{type(exc).__name__}: {exc}"
    if len(text) <= _MAX_ALERT_ERROR_CHARS:
        return text
    keep = max(0, _MAX_ALERT_ERROR_CHARS - len(_TRUNCATION_MARKER))
    return text[:keep] + _TRUNCATION_MARKER


def is_retryable(exc: BaseException) -> bool:
    """Decide whether the same request is worth sending again.

    Status codes are read off the exception when the client attached a response,
    which covers rate limiting and upstream faults. Everything else falls back to
    the exception's own name, because a transport error arrives as a type rather
    than a code and this must not import the HTTP client to recognise one.
    """
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int):
        return status in RETRYABLE_STATUS
    label = f"{type(exc).__name__} {exc}".casefold()
    return any(marker in label for marker in _TRANSIENT_MARKERS)


@dataclass(slots=True)
class RetryingProvider:
    """Wrap a provider so transient failures cost seconds, not a mission."""

    inner: ProviderPort
    max_attempts: int = 3
    backoff_start_s: float = 1.0
    backoff_cap_s: float = 20.0
    sleep: Callable[[float], Awaitable[None]] = field(default=asyncio.sleep)
    retryable: Callable[[BaseException], bool] = field(default=is_retryable)
    attempts_made: int = field(default=0, init=False)

    async def stream_chat(
        self,
        *,
        messages: Sequence[JsonObject],
        tools: Sequence[JsonObject],
        model: str,
        enable_thinking: bool = False,
        reasoning_effort: str | None = None,
    ) -> AsyncIterator[ProviderEvent]:
        backoff = self.backoff_start_s
        for attempt in range(1, self.max_attempts + 1):
            self.attempts_made = attempt
            emitted = False
            try:
                async for event in self.inner.stream_chat(
                    messages=messages,
                    tools=tools,
                    model=model,
                    enable_thinking=enable_thinking,
                    reasoning_effort=reasoning_effort,
                ):
                    emitted = True
                    yield event
                return
            except asyncio.CancelledError:
                raise
            except BaseException as exc:  # noqa: BLE001 - re-raised unless retryable
                # Past the first token this is no longer a safe replay: the
                # caller has already seen output, and a resent request could
                # duplicate it or re-issue tool calls.
                if emitted or attempt >= self.max_attempts or not self.retryable(exc):
                    raise
                record_alert(
                    "provider_retry",
                    severity="info",
                    fields={
                        "attempt": attempt,
                        "of": self.max_attempts,
                        "backoff_s": backoff,
                        "error": _bounded_error(exc),
                    },
                )
                await self.sleep(backoff)
                backoff = min(backoff * 2, self.backoff_cap_s)

    async def list_models(self) -> list[str]:
        return await self.inner.list_models()