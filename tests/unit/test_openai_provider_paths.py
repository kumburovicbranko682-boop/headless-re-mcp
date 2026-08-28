"""Branch coverage for the OpenAI-compatible provider helpers and arms.

The happy-path streaming and the byte-ceiling guards already have tests
(test_agent_provider.py). This file drives the remaining unreached branches:
the reasoning/thinking delta shapes, usage token variants, the ``output``
response envelope, tool-call ingest overflow/type guards, the bounded SSE line
reader's mid-line and trailing-buffer handling, and the async error/list arms
(empty error body, malformed tool calls, model listing, and the httpx import
guard). Async paths use httpx.MockTransport so nothing touches the network.
"""

from __future__ import annotations

import json
import sys
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as oc
from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider


def _provider(respond: Any) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(respond),
    )


def _sse(*chunks: dict[str, Any]) -> str:
    body = "".join(f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks)
    return body + "data: [DONE]\n\n"


# --------------------------------------------------------------------------- #
# _hidden_texts: reasoning-as-dict and provider "extra" thought channels
# --------------------------------------------------------------------------- #
def test_hidden_texts_reads_reasoning_dict() -> None:
    texts = oc._hidden_texts({"reasoning": {"text": "deep-thought"}})
    assert "deep-thought" in texts


def test_hidden_texts_reads_google_extra_content_thought() -> None:
    texts = oc._hidden_texts({"extra_content": {"google": {"thought": "gemini-plan"}}})
    assert texts == ["gemini-plan"]


def test_hidden_texts_reads_google_thoughts_via_extra_fallback() -> None:
    texts = oc._hidden_texts({"extra": {"google": {"thoughts": "fallback"}}})
    assert texts == ["fallback"]


# --------------------------------------------------------------------------- #
# _tool_argument_fragment
# --------------------------------------------------------------------------- #
def test_tool_argument_fragment_ignores_non_serializable_scalar() -> None:
    assert oc._tool_argument_fragment(123) == ""
    assert oc._tool_argument_fragment({"a": 1}) == '{"a": 1}'


# --------------------------------------------------------------------------- #
# _usage_output_tokens
# --------------------------------------------------------------------------- #
def test_usage_output_tokens_accepts_float() -> None:
    assert oc._usage_output_tokens({"completion_tokens": 42.0}) == 42


def test_usage_output_tokens_sums_completion_details() -> None:
    usage = {
        "completion_tokens_details": {
            "reasoning_tokens": 5,
            "accepted_prediction_tokens": 3,
            "text_tokens": 2,
        }
    }
    assert oc._usage_output_tokens(usage) == 10


def test_usage_output_tokens_details_without_numbers_is_none() -> None:
    assert oc._usage_output_tokens({"completion_tokens_details": {"x": "y"}}) is None


def test_usage_output_tokens_rejects_non_dict() -> None:
    assert oc._usage_output_tokens("nope") is None


# --------------------------------------------------------------------------- #
# _normalize_chunk
# --------------------------------------------------------------------------- #
def test_normalize_chunk_non_dict_becomes_empty() -> None:
    assert oc._normalize_chunk("not-a-dict") == {}


def test_normalize_chunk_lifts_output_envelope() -> None:
    chunk = {
        "output": {
            "choices": [{"delta": {"content": "hi"}}],
            "usage": {"completion_tokens": 7},
        }
    }
    merged = oc._normalize_chunk(chunk)
    assert merged["choices"] == [{"delta": {"content": "hi"}}]
    assert merged["usage"] == {"completion_tokens": 7}


def test_normalize_chunk_keeps_existing_usage_over_envelope() -> None:
    chunk = {
        "usage": {"completion_tokens": 1},
        "output": {"choices": [], "usage": {"completion_tokens": 9}},
    }
    merged = oc._normalize_chunk(chunk)
    assert merged["usage"] == {"completion_tokens": 1}


# --------------------------------------------------------------------------- #
# _ingest_tool_calls guards
# --------------------------------------------------------------------------- #
def test_ingest_tool_calls_non_list_is_noop() -> None:
    assert oc._ingest_tool_calls("nope", {}, 0) == (0, [])


def test_ingest_tool_calls_skips_non_dict_entries() -> None:
    frags: dict[int, dict[str, str]] = {}
    total, pieces = oc._ingest_tool_calls(
        [7, {"index": 0, "function": {"name": "doctor"}}], frags, 0
    )
    assert pieces == ["doctor"]
    assert frags[0]["name"] == "doctor"


def test_ingest_tool_calls_rejects_id_over_buffer_ceiling() -> None:
    frags: dict[int, dict[str, str]] = {}
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls([{"index": 0, "id": "x"}], frags, oc._MAX_TOOL_CALL_BUFFER_BYTES)


def test_ingest_tool_calls_rejects_name_over_buffer_ceiling() -> None:
    frags: dict[int, dict[str, str]] = {}
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls(
            [{"index": 0, "function": {"name": "y"}}],
            frags,
            oc._MAX_TOOL_CALL_BUFFER_BYTES,
        )


# --------------------------------------------------------------------------- #
# _aiter_bounded_sse_lines
# --------------------------------------------------------------------------- #
class _FakeByteResponse:
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = chunks

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


async def _collect_lines(response: Any, *, max_line_bytes: int | None = None) -> list[str]:
    return [
        line async for line in oc._aiter_bounded_sse_lines(response, max_line_bytes=max_line_bytes)
    ]


@pytest.mark.asyncio
async def test_sse_reader_strips_cr_and_flushes_trailing_buffer() -> None:
    lines = await _collect_lines(_FakeByteResponse(b"a\r\nb\r"))
    assert lines == ["a", "b"]


@pytest.mark.asyncio
async def test_sse_reader_refuses_oversized_completed_line() -> None:
    with pytest.raises(ValueError, match="SSE line exceeded 512 bytes"):
        await _collect_lines(_FakeByteResponse(b"x" * 600 + b"\n"), max_line_bytes=512)


# --------------------------------------------------------------------------- #
# stream_chat async arms
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_stream_reraises_when_error_body_is_empty() -> None:
    provider = _provider(lambda request: httpx.Response(503))
    with pytest.raises(httpx.HTTPStatusError) as caught:
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass
    assert "503" in str(caught.value)


@pytest.mark.asyncio
async def test_stream_rejects_invalid_tool_arguments_json() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        chunk = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "c1",
                                "function": {"name": "doctor", "arguments": "{bad"},
                            }
                        ]
                    }
                }
            ]
        }
        return httpx.Response(200, text=_sse(chunk))

    provider = _provider(respond)
    with pytest.raises(ValueError, match="invalid tool arguments"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_stream_rejects_tool_arguments_that_are_not_an_object() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        chunk = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "c1",
                                "function": {"name": "doctor", "arguments": "[1,2]"},
                            }
                        ]
                    }
                }
            ]
        }
        return httpx.Response(200, text=_sse(chunk))

    provider = _provider(respond)
    with pytest.raises(ValueError, match="incomplete tool call"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_stream_chat_requires_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)
    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k")
    )
    with pytest.raises(RuntimeError, match="web extra requires httpx"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


# --------------------------------------------------------------------------- #
# list_models async arms
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_list_models_returns_sorted_ids() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "gpt-z"},
                    {"id": "gpt-a"},
                    {"no": "id"},
                    "not-an-object",
                ]
            },
        )

    provider = _provider(respond)
    assert await provider.list_models() == ["gpt-a", "gpt-z"]


@pytest.mark.asyncio
async def test_list_models_without_data_list_is_empty() -> None:
    provider = _provider(lambda request: httpx.Response(200, json={"data": "nope"}))
    assert await provider.list_models() == []


@pytest.mark.asyncio
async def test_list_models_reraises_when_error_body_is_empty() -> None:
    provider = _provider(lambda request: httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        await provider.list_models()


@pytest.mark.asyncio
async def test_list_models_error_carries_provider_detail() -> None:
    def rate_limited(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"message": "quota exceeded, retry in 30s"}})

    provider = _provider(rate_limited)
    with pytest.raises(httpx.HTTPStatusError) as caught:
        await provider.list_models()
    assert "retry in 30s" in str(caught.value)


@pytest.mark.asyncio
async def test_list_models_requires_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)
    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k")
    )
    with pytest.raises(RuntimeError, match="web extra requires httpx"):
        await provider.list_models()
