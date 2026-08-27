from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.agent.providers.retrying import RetryingProvider, is_retryable

JsonObject = dict[str, Any]


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class HttpError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"http {status}")
        self.response = FakeResponse(status)


class ScriptedProvider:
    """Fails a scripted number of times, then streams normally."""

    def __init__(self, failures: list[BaseException], *, emit_before_failing: int = 0) -> None:
        self.failures = list(failures)
        self.emit_before_failing = emit_before_failing
        self.calls = 0

    def stream_chat(self, **kwargs: Any) -> AsyncIterator[ProviderEvent]:
        self.calls += 1
        failure = self.failures.pop(0) if self.failures else None
        return self._events(failure)

    async def _events(self, failure: BaseException | None) -> AsyncIterator[ProviderEvent]:
        for index in range(self.emit_before_failing):
            yield ProviderEvent("text_delta", text=f"chunk{index}")
        if failure is not None:
            raise failure
        yield ProviderEvent("text_delta", text="done")
        yield ProviderEvent("completed", tool_calls=(ProviderToolCall("c1", "t", {}),))

    async def list_models(self) -> list[str]:
        return ["fake"]


async def _drain(provider: RetryingProvider) -> list[ProviderEvent]:
    return [
        event
        async for event in provider.stream_chat(messages=[], tools=[], model="m")
    ]


async def _no_sleep(seconds: float) -> None:
    return None


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504, 408])
def test_transient_status_codes_are_retryable(status: int) -> None:
    assert is_retryable(HttpError(status)) is True


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
def test_client_errors_are_not_retryable(status: int) -> None:
    """Retrying a bad key or a bad request just spends the budget twice."""
    assert is_retryable(HttpError(status)) is False


def test_transport_faults_are_recognised_without_importing_the_http_client() -> None:
    class ConnectTimeout(Exception):
        pass

    class ReadTimeout(Exception):
        pass

    assert is_retryable(ConnectTimeout("connect timed out")) is True
    assert is_retryable(ReadTimeout("read timed out")) is True
    assert is_retryable(ValueError("model does not exist")) is False


@pytest.mark.asyncio
async def test_a_rate_limit_is_retried_and_then_succeeds() -> None:
    inner = ScriptedProvider([HttpError(429), HttpError(503)])
    provider = RetryingProvider(inner, sleep=_no_sleep)

    events = await _drain(provider)

    assert inner.calls == 3
    assert [event.type for event in events] == ["text_delta", "completed"]


@pytest.mark.asyncio
async def test_retries_stop_at_the_attempt_limit() -> None:
    inner = ScriptedProvider([HttpError(503)] * 10)
    provider = RetryingProvider(inner, max_attempts=3, sleep=_no_sleep)

    with pytest.raises(HttpError):
        await _drain(provider)
    assert inner.calls == 3


@pytest.mark.asyncio
async def test_a_permanent_error_is_not_retried_at_all() -> None:
    inner = ScriptedProvider([HttpError(401)])
    provider = RetryingProvider(inner, sleep=_no_sleep)

    with pytest.raises(HttpError):
        await _drain(provider)
    assert inner.calls == 1


@pytest.mark.asyncio
async def test_a_failure_after_the_first_token_is_never_retried() -> None:
    """Replaying a partly consumed stream would duplicate output.

    Worse, if the model had already emitted tool calls the retry could run a
    tool a second time, so the stream is only resumable before it has said
    anything.
    """
    inner = ScriptedProvider([HttpError(503)] * 5, emit_before_failing=2)
    provider = RetryingProvider(inner, sleep=_no_sleep)

    seen: list[str] = []
    with pytest.raises(HttpError):
        async for event in provider.stream_chat(messages=[], tools=[], model="m"):
            seen.append(event.text or "")

    assert inner.calls == 1, "a stream that already emitted must not be replayed"
    assert seen == ["chunk0", "chunk1"]


@pytest.mark.asyncio
async def test_backoff_grows_and_is_capped() -> None:
    waits: list[float] = []

    async def record(seconds: float) -> None:
        waits.append(seconds)

    inner = ScriptedProvider([HttpError(503)] * 10)
    provider = RetryingProvider(
        inner, max_attempts=6, backoff_start_s=1.0, backoff_cap_s=4.0, sleep=record
    )

    with pytest.raises(HttpError):
        await _drain(provider)

    assert waits == [1.0, 2.0, 4.0, 4.0, 4.0]


@pytest.mark.asyncio
async def test_cancellation_is_not_treated_as_a_retryable_fault() -> None:
    import asyncio

    inner = ScriptedProvider([asyncio.CancelledError()])
    provider = RetryingProvider(inner, sleep=_no_sleep)

    with pytest.raises(asyncio.CancelledError):
        await _drain(provider)
    assert inner.calls == 1


@pytest.mark.asyncio
async def test_a_long_retry_alert_error_is_marked_truncated_within_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cut alert error must say it was cut, not read as the whole error.

    The provider appends the HTTP error body to the exception it re-raises --
    that body is where a host says which limit was hit and for how long -- so
    the alert's error text routinely exceeds its 300-character budget and the
    operative detail sits past the cut. A bare slice read as complete.
    """
    from headless_re_mcp.agent.providers import retrying

    alerts: list[JsonObject] = []
    monkeypatch.setattr(
        retrying,
        "record_alert",
        lambda kind, severity, fields: alerts.append({"kind": kind, **fields}),
    )
    failure = HttpError(429)
    failure.args = ("http 429: " + "the body explains the limit " * 20,)
    inner = ScriptedProvider([failure])
    provider = RetryingProvider(inner, sleep=_no_sleep)

    await _drain(provider)

    assert alerts and alerts[0]["kind"] == "provider_retry"
    error = alerts[0]["error"]
    assert len(error) <= 300
    assert error.endswith("...[truncated]")
    assert error.startswith("HttpError: http 429")


@pytest.mark.asyncio
async def test_a_short_retry_alert_error_is_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Within budget the error is reported whole, with no marker."""
    from headless_re_mcp.agent.providers import retrying

    alerts: list[JsonObject] = []
    monkeypatch.setattr(
        retrying,
        "record_alert",
        lambda kind, severity, fields: alerts.append(dict(fields)),
    )
    inner = ScriptedProvider([HttpError(503)])
    provider = RetryingProvider(inner, sleep=_no_sleep)

    await _drain(provider)

    assert alerts[0]["error"] == "HttpError: http 503"


@pytest.mark.asyncio
async def test_list_models_passes_through() -> None:
    provider = RetryingProvider(ScriptedProvider([]), sleep=_no_sleep)
    assert await provider.list_models() == ["fake"]