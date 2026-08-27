"""Branch coverage for the OpenAI-compatible provider helpers and guards.

The happy paths live in test_agent_provider.py; this file drives the leftover
pure-function branches (delta/usage/chunk parsing, tool-call accumulation) and
the async guard branches (oversized/again-reported/import-missing/empty-error
paths), all without a network by using httpx.MockTransport and fake responses.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as oc
from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider

# --- pure helpers -----------------------------------------------------------


def test_plain_text_dict_forms_and_fallthrough() -> None:
    assert oc._plain_text({"text": "hi"}) == "hi"
    # First candidate key is non-string, so it is skipped and "" returned.
    assert oc._plain_text({"text": 5, "note": "x"}) == ""
    assert oc._plain_text(42) == ""


def test_hidden_texts_reasoning_dict_and_google_thought() -> None:
    texts = oc._hidden_texts({"reasoning": {"text": "because"}})
    assert "because" in texts

    google = oc._hidden_texts(
        {"extra_content": {"google": {"thought": "deep thought"}}}
    )
    assert google == ["deep thought"]

    # The ``extra`` spelling is honoured when ``extra_content`` is absent.
    alt = oc._hidden_texts({"extra": {"google": {"thoughts": "alt"}}})
    assert alt == ["alt"]


def test_tool_argument_fragment_ignores_unknown_types() -> None:
    assert oc._tool_argument_fragment("raw") == "raw"
    assert oc._tool_argument_fragment({"a": 1}) == '{"a": 1}'
    assert oc._tool_argument_fragment(None) == ""
    assert oc._tool_argument_fragment(7) == ""


def test_usage_output_tokens_variants() -> None:
    assert oc._usage_output_tokens("nope") is None
    assert oc._usage_output_tokens({"completion_tokens": 12}) == 12
    assert oc._usage_output_tokens({"output_tokens": 4.0}) == 4
    details = {
        "completion_tokens_details": {
            "reasoning_tokens": 5,
            "accepted_prediction_tokens": 3,
            "text_tokens": 2,
        }
    }
    assert oc._usage_output_tokens(details) == 10
    assert oc._usage_output_tokens({}) is None
    # Details present but with no usable integer fields -> still None.
    no_ints = {
        "completion_tokens_details": {
            "reasoning_tokens": "x",
            "accepted_prediction_tokens": None,
        }
    }
    assert oc._usage_output_tokens(no_ints) is None


def test_normalize_chunk_unwraps_output_and_ignores_non_dict() -> None:
    assert oc._normalize_chunk("x") == {}
    wrapped = {
        "output": {"choices": [{"delta": {"content": "hi"}}], "usage": {"completion_tokens": 3}},
        "usage": None,
    }
    merged = oc._normalize_chunk(wrapped)
    assert merged["choices"] == [{"delta": {"content": "hi"}}]
    assert merged["usage"] == {"completion_tokens": 3}

    # An already-present top-level usage must not be overwritten by output.usage.
    kept = oc._normalize_chunk(
        {
            "output": {"choices": [], "usage": {"completion_tokens": 99}},
            "usage": {"completion_tokens": 7},
        }
    )
    assert kept["usage"] == {"completion_tokens": 7}


def test_ingest_tool_calls_skips_and_dedupes() -> None:
    assert oc._ingest_tool_calls("not-a-list", {}, 0) == (0, [])

    frags: dict[int, dict[str, str]] = {}
    calls = [
        {"index": 0, "id": "a", "function": {"name": "f", "arguments": '{"x":1}'}},
        "junk-entry",
    ]
    buffered, pieces = oc._ingest_tool_calls(calls, frags, 0)
    assert "f" in pieces and '{"x":1}' in pieces
    assert frags[0] == {"id": "a", "name": "f", "arguments": '{"x":1}'}

    # A repeat of the same id/name with an empty fragment adds nothing.
    buffered2, pieces2 = oc._ingest_tool_calls(
        [{"index": 0, "id": "a", "function": {"name": "f", "arguments": ""}}],
        frags,
        buffered,
    )
    assert pieces2 == []
    assert frags[0]["id"] == "a" and frags[0]["name"] == "f"


def test_ingest_tool_calls_bounds_id_and_name_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oc, "_MAX_TOOL_CALL_BUFFER_BYTES", 4, raising=False)
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls([{"index": 0, "id": "aaaaa"}], {}, 0)

    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls(
            [{"index": 0, "id": "a", "function": {"name": "bbbb"}}], {}, 0
        )


# --- async line/error readers ----------------------------------------------


class _FakeResp:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def aiter_bytes(self) -> Any:
        for chunk in self._chunks:
            yield chunk


async def _collect(gen: Any) -> list[str]:
    return [line async for line in gen]


@pytest.mark.asyncio
async def test_bounded_sse_lines_strip_cr_and_flush_trailing() -> None:
    resp = _FakeResp([b"data: one\r\n", b"data: two"])  # second has no newline
    lines = await _collect(oc._aiter_bounded_sse_lines(resp))
    assert lines == ["data: one", "data: two"]


@pytest.mark.asyncio
async def test_bounded_sse_lines_reject_oversized_mid_chunk() -> None:
    resp = _FakeResp([b"aaaaaa\n"])
    with pytest.raises(ValueError, match="SSE line exceeded 2 bytes"):
        await _collect(oc._aiter_bounded_sse_lines(resp, max_line_bytes=2))


@pytest.mark.asyncio
async def test_bounded_sse_lines_reject_oversized_trailing_buffer() -> None:
    resp = _FakeResp([b"aaaaaa"])  # no newline at all
    with pytest.raises(ValueError, match="SSE line exceeded 2 bytes"):
        await _collect(oc._aiter_bounded_sse_lines(resp, max_line_bytes=2))


@pytest.mark.asyncio
async def test_bounded_sse_lines_flush_trailing_cr() -> None:
    resp = _FakeResp([b"tail\r"])
    assert await _collect(oc._aiter_bounded_sse_lines(resp)) == ["tail"]


@pytest.mark.asyncio
async def test_read_bounded_error_detail_returns_the_body() -> None:
    resp = _FakeResp([b"boom happened"])
    assert await oc._read_bounded_error_detail(resp) == "boom happened"


# --- build_client / headers -------------------------------------------------


@pytest.mark.asyncio
async def test_build_client_stays_quiet_after_first_bad_proxy_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken = "127.0.0.1,localhost,::1,127.0.0.0/8,::1/128"
    monkeypatch.setenv("NO_PROXY", broken)
    monkeypatch.setenv("no_proxy", broken)
    # Already reported once: this call must fall back silently, no new alert.
    monkeypatch.setattr(oc, "_reported_bad_proxy_env", True)
    alerts: list[str] = []
    monkeypatch.setattr(oc, "record_alert", lambda kind, **kw: alerts.append(kind))

    with pytest.raises(httpx.InvalidURL):
        httpx.AsyncClient(transport=None)

    client = oc.build_client(httpx, timeout=5.0, transport=None)
    assert client.trust_env is False
    assert alerts == []
    await client.aclose()


def test_headers_omit_authorization_without_a_key() -> None:
    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="")
    )
    headers = provider._headers()
    assert "Authorization" not in headers
    assert headers["Accept"] == "text/event-stream"


# --- stream_chat / list_models integration branches ------------------------


def _provider(handler: Any) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_stream_chat_requires_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k")
    )
    monkeypatch.setitem(sys.modules, "httpx", None)
    with pytest.raises(RuntimeError, match="web extra requires httpx"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_stream_chat_reraises_a_bare_status_without_body() -> None:
    def empty_429(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="")

    provider = _provider(empty_429)
    with pytest.raises(httpx.HTTPStatusError) as caught:
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass
    # No body detail was appended, so the message is the plain status line.
    assert "429" in str(caught.value)


@pytest.mark.asyncio
async def test_stream_chat_rejects_invalid_tool_arguments() -> None:
    def bad_args(request: httpx.Request) -> httpx.Response:
        chunk = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "id": "c", "function": {"name": "f", "arguments": "{bad"}}
                        ]
                    }
                }
            ]
        }
        body = f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"
        return httpx.Response(200, text=body)

    provider = _provider(bad_args)
    with pytest.raises(ValueError, match="invalid tool arguments"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_stream_chat_rejects_an_incomplete_tool_call() -> None:
    def no_name(request: httpx.Request) -> httpx.Response:
        chunk = {
            "choices": [
                {"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{}"}}]}}
            ]
        }
        body = f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"
        return httpx.Response(200, text=body)

    provider = _provider(no_name)
    with pytest.raises(ValueError, match="incomplete tool call"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_list_models_requires_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k")
    )
    monkeypatch.setitem(sys.modules, "httpx", None)
    with pytest.raises(RuntimeError, match="web extra requires httpx"):
        await provider.list_models()


@pytest.mark.asyncio
async def test_list_models_returns_sorted_unique_ids() -> None:
    def models(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "gamma"},
                    {"id": "alpha"},
                    {"id": "alpha"},
                    {"no": "id"},
                    "not-a-dict",
                ]
            },
        )

    provider = _provider(models)
    assert await provider.list_models() == ["alpha", "gamma"]


@pytest.mark.asyncio
async def test_list_models_reraises_a_bare_status_without_body() -> None:
    def empty_429(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="")

    provider = _provider(empty_429)
    with pytest.raises(httpx.HTTPStatusError) as caught:
        await provider.list_models()
    assert "429" in str(caught.value)


@pytest.mark.asyncio
async def test_list_models_returns_empty_when_data_is_not_a_list() -> None:
    def weird(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"not": "a list"}})

    provider = _provider(weird)
    assert await provider.list_models() == []
