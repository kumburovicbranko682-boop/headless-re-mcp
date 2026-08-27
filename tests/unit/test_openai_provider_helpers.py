"""Pure helpers and error contracts of the OpenAI-compatible provider.

The streaming integration is pinned in test_agent_provider.py with a mock
transport. What is covered here is the layer beneath it -- the delta/usage/chunk
normalisers that absorb the shape drift between OpenAI, DeepSeek and Google, the
bounded SSE line reader, the tool-call accumulator's dedupe and skip branches --
plus the handful of request-level error contracts the transport tests do not
reach: a rejected request with an empty body, a tool call that never completed,
and the model listing's empty and success shapes.
"""

from __future__ import annotations

import sys
from typing import Any

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as oc
from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import (
    OpenAICompatibleProvider,
    _aiter_bounded_sse_lines,
    _hidden_texts,
    _ingest_tool_calls,
    _normalize_chunk,
    _plain_text,
    _sse_payload,
    _tool_argument_fragment,
    _usage_output_tokens,
)


# --------------------------------------------------------------------------
# _plain_text / _hidden_texts
# --------------------------------------------------------------------------
def test_plain_text_pulls_visible_text_from_each_shape() -> None:
    assert _plain_text("hi") == "hi"
    assert _plain_text([{"text": "a"}, {"content": "b"}]) == "ab"
    # An empty first key falls through to the next candidate key.
    assert _plain_text({"text": "", "content": "c"}) == "c"
    assert _plain_text({"summary": "s"}) == "s"
    assert _plain_text(42) == ""
    assert _plain_text({"other": "x"}) == ""


def test_hidden_texts_reads_reasoning_and_google_thoughts() -> None:
    """Thinking text arrives under several vendor spellings; all are surfaced."""
    # A dict under 'reasoning' is read by both the key loop and the reasoning
    # block, so a provider that streams it that way is surfaced (twice, by design).
    assert _hidden_texts({"reasoning": {"text": "step"}}) == ["step", "step"]
    # Google routes its thoughts through extra_content.google.thought.
    assert _hidden_texts({"extra_content": {"google": {"thought": "why"}}}) == ["why"]
    # extra is accepted as a fallback name for extra_content.
    assert _hidden_texts({"extra": {"google": {"thoughts": "because"}}}) == ["because"]
    # An empty first reasoning chunk contributes nothing.
    assert _hidden_texts({"reasoning_content": ""}) == []


def test_hidden_texts_combines_the_sources() -> None:
    texts = _hidden_texts(
        {"reasoning_content": "a", "extra_content": {"google": {"thought": "b"}}}
    )
    assert texts == ["a", "b"]


# --------------------------------------------------------------------------
# _tool_argument_fragment / _usage_output_tokens / _normalize_chunk
# --------------------------------------------------------------------------
def test_tool_argument_fragment_serialises_only_json_shapes() -> None:
    assert _tool_argument_fragment("raw") == "raw"
    assert _tool_argument_fragment({"a": 1}) == '{"a": 1}'
    assert _tool_argument_fragment([1, 2]) == "[1, 2]"
    assert _tool_argument_fragment(3) == ""


def test_usage_output_tokens_reads_ints_floats_and_detail_sums() -> None:
    assert _usage_output_tokens({"completion_tokens": 12}) == 12
    assert _usage_output_tokens({"output_tokens": 5.0}) == 5
    detail = {
        "completion_tokens_details": {
            "reasoning_tokens": 3,
            "accepted_prediction_tokens": 4,
            "text_tokens": 2,
        }
    }
    assert _usage_output_tokens(detail) == 9
    assert _usage_output_tokens({"completion_tokens_details": {}}) is None
    assert _usage_output_tokens("not a dict") is None
    assert _usage_output_tokens({}) is None


def test_normalize_chunk_lifts_a_nested_output_envelope() -> None:
    """A provider that wraps choices under 'output' is flattened to the top level."""
    chunk = {
        "output": {
            "choices": [{"delta": {"content": "x"}}],
            "usage": {"completion_tokens": 7},
        }
    }
    merged = _normalize_chunk(chunk)
    assert merged["choices"] == [{"delta": {"content": "x"}}]
    assert merged["usage"] == {"completion_tokens": 7}


def test_normalize_chunk_leaves_a_flat_chunk_and_rejects_a_non_dict() -> None:
    flat = {"choices": [{"delta": {}}]}
    assert _normalize_chunk(flat) is flat
    assert _normalize_chunk("not a dict") == {}
    # An 'output' without choices is not an envelope; pass through unchanged.
    passthrough = {"output": {"nothing": True}}
    assert _normalize_chunk(passthrough) is passthrough


# --------------------------------------------------------------------------
# _sse_payload
# --------------------------------------------------------------------------
def test_sse_payload_reads_data_lines_and_bare_json() -> None:
    assert _sse_payload("data: {\"a\":1}") == '{"a":1}'
    assert _sse_payload("data: ") is None
    assert _sse_payload('{"bare": true}') == '{"bare": true}'
    assert _sse_payload("event: ping") is None


# --------------------------------------------------------------------------
# _ingest_tool_calls
# --------------------------------------------------------------------------
def test_ingest_tool_calls_ignores_a_non_list() -> None:
    assert _ingest_tool_calls("nope", {}, 0) == (0, [])


def test_ingest_tool_calls_accumulates_dedupes_and_skips_noise() -> None:
    fragments: dict[int, dict[str, str]] = {}
    # A non-dict entry is skipped; the real call assembles id/name/arguments.
    first = [
        "junk",
        {"index": 0, "id": "call-a", "function": {"name": "get", "arguments": '{"x":'}},
    ]
    total, pieces = _ingest_tool_calls(first, fragments, 0)
    assert fragments[0] == {"id": "call-a", "name": "get", "arguments": '{"x":'}
    assert "get" in pieces
    # A repeat with the same id and name must not duplicate them, only extend args.
    second = [
        {"index": 0, "id": "call-a", "function": {"name": "get", "arguments": "1}"}},
    ]
    total, pieces = _ingest_tool_calls(second, fragments, total)
    assert fragments[0]["id"] == "call-a"
    assert fragments[0]["name"] == "get"
    assert fragments[0]["arguments"] == '{"x":1}'
    # An empty argument fragment adds nothing.
    third = [{"index": 0, "function": {"arguments": ""}}]
    _, pieces = _ingest_tool_calls(third, fragments, total)
    assert pieces == []


def test_ingest_tool_calls_bounds_the_id_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oc, "_MAX_TOOL_CALL_BUFFER_BYTES", 4)
    calls = [{"index": 0, "id": "toolongid", "function": {}}]
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        _ingest_tool_calls(calls, {}, 0)


def test_ingest_tool_calls_bounds_the_name_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oc, "_MAX_TOOL_CALL_BUFFER_BYTES", 4)
    calls = [{"index": 0, "id": "x", "function": {"name": "averylongname"}}]
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        _ingest_tool_calls(calls, {}, 0)


# --------------------------------------------------------------------------
# _aiter_bounded_sse_lines
# --------------------------------------------------------------------------
class _BytesResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def aiter_bytes(self):  # type: ignore[no-untyped-def]
        for chunk in self._chunks:
            yield chunk


@pytest.mark.asyncio
async def test_bounded_sse_lines_splits_strips_cr_and_keeps_the_tail() -> None:
    """A carriage return is trimmed, a split across chunks rejoins, the tail flushes."""
    response = _BytesResponse([b"x\r\n", b"parti", b"al\n", b"tail\r"])
    lines = [line async for line in _aiter_bounded_sse_lines(response)]
    assert lines == ["x", "partial", "tail"]


@pytest.mark.asyncio
async def test_bounded_sse_lines_flushes_a_plain_tail_without_a_cr() -> None:
    response = _BytesResponse([b"plain"])
    assert [line async for line in _aiter_bounded_sse_lines(response)] == ["plain"]


@pytest.mark.asyncio
async def test_bounded_sse_lines_refuses_an_endless_line() -> None:
    response = _BytesResponse([b"x" * 40])
    with pytest.raises(ValueError, match="SSE line exceeded"):
        _ = [line async for line in _aiter_bounded_sse_lines(response, max_line_bytes=16)]


@pytest.mark.asyncio
async def test_bounded_sse_lines_refuses_an_overflowing_completed_line() -> None:
    """A line that overshoots the limit before its newline is refused too."""
    response = _BytesResponse([b"x" * 40 + b"\n"])
    with pytest.raises(ValueError, match="SSE line exceeded"):
        _ = [line async for line in _aiter_bounded_sse_lines(response, max_line_bytes=16)]


@pytest.mark.asyncio
async def test_bounded_sse_lines_refuses_an_endless_tail() -> None:
    """A no-newline body that overflows only on flush is still refused."""
    response = _BytesResponse([b"x" * 10, b"y" * 10])
    with pytest.raises(ValueError, match="SSE line exceeded"):
        _ = [line async for line in _aiter_bounded_sse_lines(response, max_line_bytes=16)]


# --------------------------------------------------------------------------
# _headers
# --------------------------------------------------------------------------
def test_headers_carry_the_bearer_only_when_a_key_is_set() -> None:
    with_key = OpenAICompatibleProvider(
        ProviderProfile("default", "https://p.example/v1", "m", api_key="secret")
    )._headers()
    assert with_key["Authorization"] == "Bearer secret"
    without_key = OpenAICompatibleProvider(
        ProviderProfile("default", "https://p.example/v1", "m", api_key="")
    )._headers()
    assert "Authorization" not in without_key


# --------------------------------------------------------------------------
# stream_chat / list_models request-level contracts
# --------------------------------------------------------------------------
def _provider(handler: Any) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        ProviderProfile("default", "https://p.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_a_rejected_request_with_no_body_re_raises_the_status_error() -> None:
    def rejected(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="")

    with pytest.raises(httpx.HTTPStatusError):
        async for _ in _provider(rejected).stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_invalid_tool_arguments_are_blamed_on_the_provider() -> None:
    import json

    def bad_args(request: httpx.Request) -> httpx.Response:
        call = {"index": 0, "id": "c", "function": {"name": "t", "arguments": '{"x":'}}
        chunk = {"choices": [{"delta": {"tool_calls": [call]}}]}
        body = f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"
        return httpx.Response(200, text=body)

    with pytest.raises(ValueError, match="invalid tool arguments"):
        async for _ in _provider(bad_args).stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_a_tool_call_with_no_name_is_incomplete() -> None:
    import json

    def nameless(request: httpx.Request) -> httpx.Response:
        call = {"index": 0, "id": "c", "function": {"arguments": "{}"}}
        chunk = {"choices": [{"delta": {"tool_calls": [call]}}]}
        body = f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"
        return httpx.Response(200, text=body)

    with pytest.raises(ValueError, match="incomplete tool call"):
        async for _ in _provider(nameless).stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_list_models_returns_sorted_ids() -> None:
    def models(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": "gpt-b"}, {"id": "gpt-a"}, {"no": "id"}]})

    assert await _provider(models).list_models() == ["gpt-a", "gpt-b"]


@pytest.mark.asyncio
async def test_list_models_is_empty_when_data_is_not_a_list() -> None:
    def models(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": "not-a-list"})

    assert await _provider(models).list_models() == []


@pytest.mark.asyncio
async def test_list_models_re_raises_a_rejection_with_no_body() -> None:
    def rejected(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="")

    with pytest.raises(httpx.HTTPStatusError):
        await _provider(rejected).list_models()


@pytest.mark.asyncio
async def test_stream_chat_requires_the_web_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without httpx the streaming call fails with the actionable extra name."""
    monkeypatch.setitem(sys.modules, "httpx", None)
    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://p.example/v1", "m", api_key="k")
    )
    with pytest.raises(RuntimeError, match="web extra requires httpx"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_list_models_requires_the_web_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)
    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://p.example/v1", "m", api_key="k")
    )
    with pytest.raises(RuntimeError, match="web extra requires httpx"):
        await provider.list_models()
