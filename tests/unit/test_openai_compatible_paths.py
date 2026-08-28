"""Coverage for the OpenAI-compatible provider's helpers and edge arms.

The streaming happy path is exercised elsewhere; this focuses on the pure
delta/usage/tool-call parsers, the bounded SSE and error-body readers, the
client builder's proxy-environment fallback, and the ``list_models`` and
``stream_chat`` edge arms (rejections, malformed tool calls) via a mock
transport.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as oc
from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider

# ---------------------------------------------------------------------------
# _plain_text / _hidden_texts
# ---------------------------------------------------------------------------


def test_plain_text_reads_strings_lists_and_objects() -> None:
    assert oc._plain_text("hi") == "hi"
    assert oc._plain_text(["a", {"text": "b"}]) == "ab"
    assert oc._plain_text({"content": "c"}) == "c"
    assert oc._plain_text(42) == ""


def test_hidden_texts_collects_reasoning_object_and_google_thought() -> None:
    delta = {"reasoning": {"text": "thinking"}}
    assert oc._hidden_texts(delta) == ["thinking", "thinking"]

    google = {"extra_content": {"google": {"thought": "g-think"}}}
    assert oc._hidden_texts(google) == ["g-think"]

    fallback = {"extra": {"google": {"thoughts": "gg"}}}
    assert oc._hidden_texts(fallback) == ["gg"]


# ---------------------------------------------------------------------------
# _tool_argument_fragment / _usage_output_tokens / _normalize_chunk / _sse_payload
# ---------------------------------------------------------------------------


def test_tool_argument_fragment_serialises_or_drops() -> None:
    assert oc._tool_argument_fragment("raw") == "raw"
    assert oc._tool_argument_fragment({"a": 1}) == '{"a": 1}'
    assert oc._tool_argument_fragment(123) == ""


def test_usage_output_tokens_reads_ints_floats_and_details() -> None:
    assert oc._usage_output_tokens("not a dict") is None
    assert oc._usage_output_tokens({"completion_tokens": 7}) == 7
    assert oc._usage_output_tokens({"output_tokens": 3.0}) == 3
    assert (
        oc._usage_output_tokens(
            {"completion_tokens_details": {"reasoning_tokens": 4, "accepted_prediction_tokens": 2}}
        )
        == 6
    )
    assert oc._usage_output_tokens({"nothing": 1}) is None


def test_normalize_chunk_lifts_output_choices() -> None:
    assert oc._normalize_chunk("x") == {}
    chunk = {"output": {"choices": [{"delta": {}}], "usage": {"completion_tokens": 1}}}
    merged = oc._normalize_chunk(chunk)
    assert merged["choices"] == [{"delta": {}}]
    assert merged["usage"] == {"completion_tokens": 1}
    plain = {"choices": [1]}
    assert oc._normalize_chunk(plain) is plain


def test_sse_payload_extracts_data_and_json_lines() -> None:
    assert oc._sse_payload("data: hello") == "hello"
    assert oc._sse_payload("data:") is None
    assert oc._sse_payload('{"a":1}') == '{"a":1}'
    assert oc._sse_payload("event: ping") is None


# ---------------------------------------------------------------------------
# _ingest_tool_calls
# ---------------------------------------------------------------------------


def test_ingest_tool_calls_ignores_non_lists_and_non_dicts() -> None:
    assert oc._ingest_tool_calls("nope", {}, 0) == (0, [])
    fragments: dict[int, dict[str, str]] = {}
    total, pieces = oc._ingest_tool_calls(["skip", 1], fragments, 0)
    assert total == 0 and pieces == [] and fragments == {}


def test_ingest_tool_calls_accumulates_and_dedupes() -> None:
    fragments: dict[int, dict[str, str]] = {}
    call = {"index": 0, "id": "x", "function": {"name": "f", "arguments": '{"a":1}'}}
    _, first = oc._ingest_tool_calls([call], fragments, 0)
    assert first == ["f", '{"a":1}']

    # Same id and name again: neither is re-appended to the accumulator.
    _, second = oc._ingest_tool_calls(
        [{"index": 0, "id": "x", "function": {"name": "f", "arguments": "more"}}],
        fragments,
        0,
    )
    assert second == ["more"]
    assert fragments[0]["name"] == "f"
    assert fragments[0]["arguments"] == '{"a":1}more'


def test_ingest_tool_calls_enforces_the_call_count_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oc, "_MAX_TOOL_CALLS", 1)
    fragments: dict[int, dict[str, str]] = {}
    with pytest.raises(ValueError, match="tool-call count exceeded"):
        oc._ingest_tool_calls([{"index": 0, "id": "a"}, {"index": 1, "id": "b"}], fragments, 0)


def test_ingest_tool_calls_enforces_the_buffer_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oc, "_MAX_TOOL_CALL_BUFFER_BYTES", 4)
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls([{"index": 0, "id": "toolong"}], {}, 0)

    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls([{"index": 0, "function": {"name": "toolong"}}], {}, 0)

    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls([{"index": 0, "function": {"arguments": "toolong"}}], {}, 0)


# ---------------------------------------------------------------------------
# _aiter_bounded_sse_lines / _read_bounded_error_detail
# ---------------------------------------------------------------------------


class _ByteStream:
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = chunks

    async def aiter_bytes(self) -> Any:
        for chunk in self._chunks:
            yield chunk


async def _collect(aiter: Any) -> list[str]:
    return [line async for line in aiter]


@pytest.mark.asyncio
async def test_aiter_bounded_sse_lines_splits_and_strips_cr() -> None:
    stream = _ByteStream(b"data: a\n", b"data: b\r\n", b"tail")
    lines = await _collect(oc._aiter_bounded_sse_lines(stream))
    assert lines == ["data: a", "data: b", "tail"]


@pytest.mark.asyncio
async def test_aiter_bounded_sse_lines_flushes_a_trailing_cr_line() -> None:
    stream = _ByteStream(b"only\r")
    assert await _collect(oc._aiter_bounded_sse_lines(stream)) == ["only"]


@pytest.mark.asyncio
async def test_aiter_bounded_sse_lines_rejects_an_overlong_line() -> None:
    stream = _ByteStream(b"waytoolong\n")
    with pytest.raises(ValueError, match="SSE line exceeded"):
        await _collect(oc._aiter_bounded_sse_lines(stream, max_line_bytes=4))


@pytest.mark.asyncio
async def test_aiter_bounded_sse_lines_rejects_an_overlong_unterminated_chunk() -> None:
    stream = _ByteStream(b"waytoolong")
    with pytest.raises(ValueError, match="SSE line exceeded"):
        await _collect(oc._aiter_bounded_sse_lines(stream, max_line_bytes=4))


@pytest.mark.asyncio
async def test_read_bounded_error_detail_returns_short_bodies() -> None:
    detail = await oc._read_bounded_error_detail(_ByteStream(b"boom happened"))
    assert detail == "boom happened"


@pytest.mark.asyncio
async def test_read_bounded_error_detail_marks_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oc, "_MAX_ERROR_BODY_BYTES", 8)
    detail = await oc._read_bounded_error_detail(_ByteStream(b"x" * 200))
    assert detail.endswith("bytes]")
    assert "truncated" in detail


# ---------------------------------------------------------------------------
# shared_ssl_context / build_client / _headers
# ---------------------------------------------------------------------------


class _FakeInvalidURL(Exception):
    pass


class _FakeAsyncClient:
    def __init__(self, **options: Any) -> None:
        self.options = options


class _OkHttpx:
    InvalidURL = _FakeInvalidURL

    def __init__(self) -> None:
        self.ssl_builds = 0

    def create_ssl_context(self) -> str:
        self.ssl_builds += 1
        return "ssl-ctx"

    def AsyncClient(self, **options: Any) -> _FakeAsyncClient:
        return _FakeAsyncClient(**options)


def test_shared_ssl_context_is_built_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oc, "_ssl_context", None)
    fake = _OkHttpx()
    first = oc.shared_ssl_context(fake)
    second = oc.shared_ssl_context(fake)
    assert first == "ssl-ctx" and second == "ssl-ctx"
    assert fake.ssl_builds == 1


def test_build_client_sets_verify_from_the_shared_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oc, "_ssl_context", None)
    client = oc.build_client(_OkHttpx(), timeout=1.0)
    assert isinstance(client, _FakeAsyncClient)
    assert client.options["verify"] == "ssl-ctx"


def test_build_client_falls_back_when_the_proxy_env_is_unparseable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oc, "_ssl_context", None)
    monkeypatch.setattr(oc, "_reported_bad_proxy_env", False)
    alerts: list[str] = []
    monkeypatch.setattr(oc, "record_alert", lambda name, **kw: alerts.append(name))

    class _RaiseOnce(_OkHttpx):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def AsyncClient(self, **options: Any) -> _FakeAsyncClient:
            self.calls += 1
            if self.calls == 1:
                raise self.InvalidURL("Invalid port: ':1'")
            return _FakeAsyncClient(**options)

    fake = _RaiseOnce()
    client = oc.build_client(fake, timeout=1.0)
    assert isinstance(client, _FakeAsyncClient)
    assert client.options["trust_env"] is False
    assert alerts == ["proxy_env_unparseable"]


def test_build_client_fallback_stays_quiet_after_the_first_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oc, "_ssl_context", None)
    monkeypatch.setattr(oc, "_reported_bad_proxy_env", True)
    alerts: list[str] = []
    monkeypatch.setattr(oc, "record_alert", lambda name, **kw: alerts.append(name))

    class _RaiseOnce(_OkHttpx):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def AsyncClient(self, **options: Any) -> _FakeAsyncClient:
            self.calls += 1
            if self.calls == 1:
                raise self.InvalidURL("Invalid port: ':1'")
            return _FakeAsyncClient(**options)

    client = oc.build_client(_RaiseOnce(), timeout=1.0)
    assert isinstance(client, _FakeAsyncClient)
    assert alerts == []


def test_headers_include_authorization_only_with_a_key() -> None:
    with_key = OpenAICompatibleProvider(
        ProviderProfile("p", "https://api.example/v1", "m", api_key="secret")
    )
    assert with_key._headers()["Authorization"] == "Bearer secret"

    without_key = OpenAICompatibleProvider(ProviderProfile("p", "https://api.example/v1", "m"))
    assert "Authorization" not in without_key._headers()


# ---------------------------------------------------------------------------
# list_models
# ---------------------------------------------------------------------------


def _provider(handler: Any) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        ProviderProfile("p", "https://api.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_list_models_sorts_unique_ids() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": "beta"}, {"id": "alpha"}, {"id": "beta"}]})

    assert await _provider(respond).list_models() == ["alpha", "beta"]


@pytest.mark.asyncio
async def test_list_models_returns_empty_for_non_list_data() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": "nope"})

    assert await _provider(respond).list_models() == []


@pytest.mark.asyncio
async def test_list_models_wraps_a_rejection_with_its_body() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="quota exceeded, retry later")

    with pytest.raises(httpx.HTTPStatusError, match="quota exceeded"):
        await _provider(respond).list_models()


@pytest.mark.asyncio
async def test_list_models_reraises_a_bodyless_rejection() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="")

    with pytest.raises(httpx.HTTPStatusError):
        await _provider(respond).list_models()


@pytest.mark.asyncio
async def test_list_models_rejects_an_oversized_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oc, "_MAX_MODELS_BODY_BYTES", 8)

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": "x" * 100}]})

    with pytest.raises(ValueError, match="models response exceeded"):
        await _provider(respond).list_models()


# ---------------------------------------------------------------------------
# stream_chat edge arms
# ---------------------------------------------------------------------------


def _sse(*payloads: str) -> str:
    lines = [f"data: {payload}\n" for payload in payloads]
    lines.append("data: [DONE]\n")
    return "".join(lines)


async def _drain(provider: OpenAICompatibleProvider) -> list[Any]:
    return [event async for event in provider.stream_chat(messages=[], tools=[], model="m")]


@pytest.mark.asyncio
async def test_stream_chat_reraises_a_bodyless_rejection() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="")

    with pytest.raises(httpx.HTTPStatusError):
        await _drain(_provider(respond))


@pytest.mark.asyncio
async def test_stream_chat_rejects_invalid_tool_arguments() -> None:
    body = _sse(
        '{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":'
        '{"name":"f","arguments":"{not json"}}]}}]}'
    )

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    with pytest.raises(ValueError, match="invalid tool arguments"):
        await _drain(_provider(respond))


@pytest.mark.asyncio
async def test_stream_chat_rejects_an_incomplete_tool_call() -> None:
    # Valid JSON arguments but no function name: the call is incomplete.
    body = _sse(
        '{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":'
        '{"arguments":"{}"}}]}}]}'
    )

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    with pytest.raises(ValueError, match="incomplete tool call"):
        await _drain(_provider(respond))
