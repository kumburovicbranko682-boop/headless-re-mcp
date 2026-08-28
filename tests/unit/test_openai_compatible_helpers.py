"""The OpenAI-compatible provider must parse messy streams and bound every read.

Providers disagree on delta shapes (string, parts, reasoning, vendor extras)
and on how tool calls are fragmented across chunks; the pure helpers here turn
that variety into visible/hidden text, output tokens and assembled tool calls,
ignoring anything unrecognised rather than stringifying it. The streaming
methods are driven through an ``httpx.MockTransport`` so the error-body,
oversize and malformed-tool-call paths are exercised without a network.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as oai
from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import (
    OpenAICompatibleProvider,
    _hidden_texts,
    _ingest_tool_calls,
    _normalize_chunk,
    _plain_text,
    _read_bounded_error_detail,
    _sse_payload,
    _tool_argument_fragment,
    _usage_output_tokens,
)

# --------------------------------------------------------------------------
# delta text extraction
# --------------------------------------------------------------------------


def test_plain_text_reads_the_first_present_object_key() -> None:
    assert _plain_text({"summary": "s"}) == "s"
    assert _plain_text({"other": "x"}) == ""
    assert _plain_text({"text": "", "content": "c"}) == "c"


def test_plain_text_joins_list_parts() -> None:
    assert _plain_text([{"text": "a"}, "b"]) == "ab"


def test_plain_text_ignores_unknown_shapes() -> None:
    assert _plain_text(42) == ""


def test_hidden_texts_reads_reasoning_object() -> None:
    texts = _hidden_texts({"reasoning": {"text": "why"}})
    assert "why" in texts


def test_hidden_texts_reads_google_extra_content() -> None:
    delta = {"extra_content": {"google": {"thought": "deep"}}}
    assert _hidden_texts(delta) == ["deep"]


def test_hidden_texts_reads_google_from_extra_fallback() -> None:
    delta = {"extra": {"google": {"thoughts": "alt"}}}
    assert _hidden_texts(delta) == ["alt"]


def test_hidden_texts_empty_when_nothing_hidden() -> None:
    assert _hidden_texts({"content": "visible"}) == []


# --------------------------------------------------------------------------
# tool-argument + usage helpers
# --------------------------------------------------------------------------


def test_tool_argument_fragment_shapes() -> None:
    assert _tool_argument_fragment("raw") == "raw"
    assert _tool_argument_fragment({"a": 1}) == '{"a": 1}'
    assert _tool_argument_fragment(123) == ""


def test_usage_output_tokens_reads_float() -> None:
    assert _usage_output_tokens({"completion_tokens": 12.0}) == 12


def test_usage_output_tokens_sums_completion_details() -> None:
    usage = {
        "completion_tokens_details": {
            "reasoning_tokens": 5,
            "accepted_prediction_tokens": 3,
            "text_tokens": 2,
        }
    }
    assert _usage_output_tokens(usage) == 10


def test_usage_output_tokens_none_for_non_dict() -> None:
    assert _usage_output_tokens("nope") is None


def test_usage_output_tokens_none_when_no_countable_field() -> None:
    assert _usage_output_tokens({"prompt_tokens": 9}) is None


# --------------------------------------------------------------------------
# chunk normalisation + SSE payload framing
# --------------------------------------------------------------------------


def test_normalize_chunk_ignores_non_dict() -> None:
    assert _normalize_chunk("x") == {}


def test_normalize_chunk_lifts_output_choices() -> None:
    chunk: dict[str, object] = {
        "output": {"choices": [{"delta": {}}], "usage": {"completion_tokens": 1}}
    }
    merged = _normalize_chunk(chunk)
    assert merged["choices"] == [{"delta": {}}]
    assert merged["usage"] == {"completion_tokens": 1}


def test_normalize_chunk_passes_plain_chunk_through() -> None:
    chunk: dict[str, object] = {"choices": [{"delta": {}}]}
    assert _normalize_chunk(chunk) is chunk


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("data: {\"a\":1}", '{"a":1}'),
        ("data:  ", None),
        ("{\"a\":1}", '{"a":1}'),
        ("event: ping", None),
    ],
)
def test_sse_payload_framing(line: str, expected: str | None) -> None:
    assert _sse_payload(line) == expected


# --------------------------------------------------------------------------
# tool-call ingestion
# --------------------------------------------------------------------------


def test_ingest_tool_calls_ignores_non_list() -> None:
    assert _ingest_tool_calls("nope", {}, 0) == (0, [])


def test_ingest_tool_calls_skips_non_dict_entries() -> None:
    fragments: dict[int, dict[str, str]] = {}
    calls = ["skip", {"index": 0, "function": {"name": "f"}}]
    _total, pieces = _ingest_tool_calls(calls, fragments, 0)
    assert pieces == ["f"]
    assert fragments[0]["name"] == "f"


def test_ingest_tool_calls_accumulates_id_name_and_arguments() -> None:
    fragments: dict[int, dict[str, str]] = {}
    calls = [{"index": 0, "id": "c1", "function": {"name": "run", "arguments": '{"x":'}}]
    total, pieces = _ingest_tool_calls(calls, fragments, 0)
    assert "run" in pieces and '{"x":' in pieces
    assert fragments[0] == {"id": "c1", "name": "run", "arguments": '{"x":'}
    assert total > 0


def test_ingest_tool_calls_refuses_oversize_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oai, "_MAX_TOOL_CALL_BUFFER_BYTES", 2)
    calls = [{"index": 0, "id": "toolongid", "function": {}}]
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        _ingest_tool_calls(calls, {}, 0)


def test_ingest_tool_calls_refuses_too_many_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oai, "_MAX_TOOL_CALLS", 1)
    fragments: dict[int, dict[str, str]] = {0: {"id": "", "name": "", "arguments": ""}}
    calls = [{"index": 5, "function": {"name": "f"}}]
    with pytest.raises(ValueError, match="tool-call count exceeded"):
        _ingest_tool_calls(calls, fragments, 0)


# --------------------------------------------------------------------------
# bounded readers
# --------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


@pytest.mark.asyncio
async def test_bounded_sse_lines_strip_cr_and_flush_trailing() -> None:
    response = _FakeResponse([b"data: a\r\n", b"tail\r"])
    lines = [line async for line in oai._aiter_bounded_sse_lines(response)]
    assert lines == ["data: a", "tail"]


@pytest.mark.asyncio
async def test_bounded_sse_lines_refuse_an_overlong_line() -> None:
    response = _FakeResponse([b"abcdefgh\n"])
    with pytest.raises(ValueError, match="SSE line exceeded"):
        [line async for line in oai._aiter_bounded_sse_lines(response, max_line_bytes=4)]


@pytest.mark.asyncio
async def test_read_bounded_error_detail_truncates_a_large_body() -> None:
    big = b"x" * (oai._MAX_ERROR_BODY_BYTES + 500)
    detail = await _read_bounded_error_detail(_FakeResponse([big]))
    assert detail.endswith("bytes]")


# --------------------------------------------------------------------------
# provider streaming error / tool-call paths
# --------------------------------------------------------------------------


def _provider(
    respond: Callable[[httpx.Request], httpx.Response], *, api_key: str = "k"
) -> OpenAICompatibleProvider:
    profile = ProviderProfile("default", "https://provider.example/v1", "m", api_key=api_key)
    return OpenAICompatibleProvider(profile, transport=httpx.MockTransport(respond))


def _sse(chunks: list[dict[str, object]]) -> str:
    body = "".join(
        f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks
    )
    return body + "data: [DONE]\n\n"


def test_headers_omit_authorization_without_a_key() -> None:
    provider = _provider(lambda request: httpx.Response(200, text=""), api_key="")
    assert "Authorization" not in provider._headers()


@pytest.mark.asyncio
async def test_stream_chat_reraises_when_error_body_is_empty() -> None:
    provider = _provider(lambda request: httpx.Response(429, text=""))
    with pytest.raises(httpx.HTTPStatusError):
        [event async for event in provider.stream_chat(messages=[], tools=[], model="m")]


@pytest.mark.asyncio
async def test_stream_chat_enriches_error_with_body() -> None:
    provider = _provider(
        lambda request: httpx.Response(429, text="quota exceeded, retry in 30s")
    )
    with pytest.raises(httpx.HTTPStatusError, match="quota exceeded"):
        [event async for event in provider.stream_chat(messages=[], tools=[], model="m")]


@pytest.mark.asyncio
async def test_stream_chat_rejects_unparseable_tool_arguments() -> None:
    chunks: list[dict[str, object]] = [
        {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "id": "c", "function": {"name": "f", "arguments": "{bad"}}
                        ]
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }
    ]
    provider = _provider(lambda request: httpx.Response(200, text=_sse(chunks)))
    with pytest.raises(ValueError, match="invalid tool arguments"):
        [event async for event in provider.stream_chat(messages=[], tools=[], model="m")]


@pytest.mark.asyncio
async def test_stream_chat_rejects_a_nameless_tool_call() -> None:
    chunks: list[dict[str, object]] = [
        {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "id": "c", "function": {"arguments": "{}"}}
                        ]
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }
    ]
    provider = _provider(lambda request: httpx.Response(200, text=_sse(chunks)))
    with pytest.raises(ValueError, match="incomplete tool call"):
        [event async for event in provider.stream_chat(messages=[], tools=[], model="m")]


# --------------------------------------------------------------------------
# list_models
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_models_returns_sorted_ids() -> None:
    payload = {"data": [{"id": "m2"}, {"id": "m1"}, {"noid": 1}, "string-entry"]}
    provider = _provider(lambda request: httpx.Response(200, json=payload))
    assert await provider.list_models() == ["m1", "m2"]


@pytest.mark.asyncio
async def test_list_models_empty_for_non_list_data() -> None:
    provider = _provider(lambda request: httpx.Response(200, json={"data": "nope"}))
    assert await provider.list_models() == []


@pytest.mark.asyncio
async def test_list_models_reraises_when_error_body_is_empty() -> None:
    provider = _provider(lambda request: httpx.Response(500, text=""))
    with pytest.raises(httpx.HTTPStatusError):
        await provider.list_models()


@pytest.mark.asyncio
async def test_list_models_refuses_an_oversize_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oai, "_MAX_MODELS_BODY_BYTES", 8)
    provider = _provider(
        lambda request: httpx.Response(200, json={"data": [{"id": "a-very-long-model-name"}]})
    )
    with pytest.raises(ValueError, match="models response exceeded"):
        await provider.list_models()
