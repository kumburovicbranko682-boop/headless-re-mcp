"""OpenAI-compatible provider: pure helpers and request-level error contracts.

test_agent_provider.py pins the streaming happy paths. What is covered here is
the translation layer underneath -- the delta/usage/tool-call readers that keep
a disagreeing provider from crashing a run -- and the guard rails: bounded SSE
lines, bounded error bodies, the tool-call assembly ceilings, and the
RuntimeError/ValueError/HTTPStatusError contracts a caller must be able to rely
on. No test talks to a network; requests end at a MockTransport.
"""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as oc
from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider


# --------------------------------------------------------------------------
# _plain_text / _hidden_texts
# --------------------------------------------------------------------------
def test_plain_text_reads_the_shapes_providers_send() -> None:
    assert oc._plain_text("abc") == "abc"
    assert oc._plain_text(["a", {"text": "b"}]) == "ab"
    assert oc._plain_text({"content": "c"}) == "c"
    assert oc._plain_text({"summary": "s"}) == "s"
    # An empty string is skipped in favour of the next key.
    assert oc._plain_text({"text": "", "content": "x"}) == "x"
    # A dict with none of the known keys, and non-text values, read as empty.
    assert oc._plain_text({"other": 1}) == ""
    assert oc._plain_text({"text": 5}) == ""
    assert oc._plain_text(42) == ""


def test_hidden_texts_reads_reasoning_and_google_thoughts() -> None:
    # A plain reasoning_content string.
    assert oc._hidden_texts({"reasoning_content": "why"}) == ["why"]
    # A reasoning dict is read by the generic key loop AND the dict branch.
    assert oc._hidden_texts({"reasoning": {"text": "step"}}) == ["step", "step"]
    # Google puts thinking under extra_content.google.thought(s).
    assert oc._hidden_texts({"extra_content": {"google": {"thought": "t1"}}}) == ["t1"]
    assert oc._hidden_texts({"extra": {"google": {"thoughts": "t2"}}}) == ["t2"]
    # Non-dict extras and empty pieces contribute nothing.
    assert oc._hidden_texts({"extra_content": "x", "extra": 5}) == []
    assert oc._hidden_texts({}) == []


# --------------------------------------------------------------------------
# _tool_argument_fragment / _usage_output_tokens / _normalize_chunk / _sse_payload
# --------------------------------------------------------------------------
def test_tool_argument_fragment_serializes_json_shapes_only() -> None:
    assert oc._tool_argument_fragment('{"a":1}') == '{"a":1}'
    assert oc._tool_argument_fragment({"a": 1}) == '{"a": 1}'
    assert oc._tool_argument_fragment([1, 2]) == "[1, 2]"
    assert oc._tool_argument_fragment(7) == ""
    assert oc._tool_argument_fragment(None) == ""


def test_usage_output_tokens_reads_ints_floats_and_detail_sums() -> None:
    assert oc._usage_output_tokens("nope") is None
    assert oc._usage_output_tokens({"completion_tokens": 5}) == 5
    assert oc._usage_output_tokens({"output_tokens": 3.0}) == 3
    assert (
        oc._usage_output_tokens(
            {
                "completion_tokens_details": {
                    "reasoning_tokens": 2,
                    "accepted_prediction_tokens": 3,
                    "text_tokens": 1,
                }
            }
        )
        == 6
    )
    # Details with no usable integers are honestly unknown, not zero.
    assert oc._usage_output_tokens({"completion_tokens_details": {"reasoning_tokens": "x"}}) is None
    assert oc._usage_output_tokens({}) is None


def test_normalize_chunk_lifts_a_nested_output_envelope() -> None:
    assert oc._normalize_chunk("junk") == {}
    nested = {
        "id": "r1",
        "usage": None,
        "output": {"choices": [{"delta": {"content": "x"}}], "usage": {"completion_tokens": 2}},
    }
    merged = oc._normalize_chunk(nested)
    assert merged["choices"] == [{"delta": {"content": "x"}}]
    assert merged["usage"] == {"completion_tokens": 2}
    # A flat chunk passes through untouched.
    flat = {"choices": [{"delta": {}}]}
    assert oc._normalize_chunk(flat) is flat


def test_sse_payload_reads_data_lines_and_bare_json() -> None:
    assert oc._sse_payload("data: {\"a\":1}") == '{"a":1}'
    assert oc._sse_payload("data:") is None
    assert oc._sse_payload('{"bare":true}') == '{"bare":true}'
    assert oc._sse_payload(": comment") is None


# --------------------------------------------------------------------------
# _ingest_tool_calls
# --------------------------------------------------------------------------
def test_ingest_tool_calls_ignores_non_lists_and_noise() -> None:
    fragments: dict[int, dict[str, str]] = {}
    used, pieces = oc._ingest_tool_calls("not-a-list", fragments, 0)
    assert (used, pieces, fragments) == (0, [], {})
    # A non-dict entry and a call with no fragment are skipped quietly.
    used, pieces = oc._ingest_tool_calls(["junk", {"index": 0, "id": "c1"}], fragments, 0)
    assert pieces == []
    assert fragments[0]["id"] == "c1"


def test_ingest_tool_calls_accumulates_and_dedupes_repeats() -> None:
    fragments: dict[int, dict[str, str]] = {}
    calls = [
        {"index": 0, "id": "c1", "function": {"name": "doctor", "arguments": '{"a"'}},
        {"index": 0, "id": "c1", "function": {"name": "doctor", "arguments": ":1}"}},
    ]
    _, pieces = oc._ingest_tool_calls(calls, fragments, 0)
    # The repeated id and name are folded in once; both fragments survive.
    assert fragments[0] == {"id": "c1", "name": "doctor", "arguments": '{"a":1}'}
    assert pieces == ["doctor", '{"a"', ":1}"]


def test_ingest_tool_calls_bounds_the_call_count_and_buffers() -> None:
    # One more distinct index than the ceiling is refused.
    full = {index: {"id": "", "name": "", "arguments": ""} for index in range(oc._MAX_TOOL_CALLS)}
    with pytest.raises(ValueError, match="tool-call count exceeded"):
        oc._ingest_tool_calls([{"index": oc._MAX_TOOL_CALLS}], full, 0)
    # An id that would push the shared buffer over the ceiling is refused.
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls(
            [{"index": 0, "id": "xx"}], {}, oc._MAX_TOOL_CALL_BUFFER_BYTES - 1
        )
    # So is a function name.
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls(
            [{"index": 0, "function": {"name": "nn"}}],
            {},
            oc._MAX_TOOL_CALL_BUFFER_BYTES - 1,
        )


# --------------------------------------------------------------------------
# _aiter_bounded_sse_lines / _read_bounded_error_detail
# --------------------------------------------------------------------------
class _ByteStream:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def aiter_bytes(self) -> Any:
        for chunk in self._chunks:
            yield chunk


async def _lines(chunks: list[bytes], **kwargs: Any) -> list[str]:
    return [
        line
        async for line in oc._aiter_bounded_sse_lines(_ByteStream(chunks), **kwargs)
    ]


@pytest.mark.asyncio
async def test_sse_lines_split_strip_cr_and_flush_the_tail() -> None:
    lines = await _lines([b"data: a\r\ndata: b\n", b"tail"])
    assert lines == ["data: a", "data: b", "tail"]
    # A trailing CR on the unterminated tail is stripped too.
    assert await _lines([b"tail\r"]) == ["tail"]


@pytest.mark.asyncio
async def test_sse_lines_refuse_overflow_before_buffering_it() -> None:
    # A line that overflows before any newline arrives.
    with pytest.raises(ValueError, match="SSE line exceeded"):
        await _lines([b"01234", b"56789"], max_line_bytes=8)
    # A line that overflows within one chunk, newline present.
    with pytest.raises(ValueError, match="SSE line exceeded"):
        await _lines([b"0123456789\n"], max_line_bytes=8)


@pytest.mark.asyncio
async def test_error_detail_is_bounded_and_says_so() -> None:
    small = await oc._read_bounded_error_detail(_ByteStream([b"  quota exceeded  "]))
    assert small == "quota exceeded"
    big = await oc._read_bounded_error_detail(
        _ByteStream([b"x" * (oc._MAX_ERROR_BODY_BYTES + 10)])
    )
    assert big.endswith(f"...[provider error body truncated at {oc._MAX_ERROR_BODY_BYTES} bytes]")
    assert len(big) <= oc._MAX_ERROR_DETAIL_CHARS


# --------------------------------------------------------------------------
# build_client proxy-environment fallback
# --------------------------------------------------------------------------
def test_build_client_falls_back_when_httpx_rejects_the_proxy_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _InvalidURL(Exception):
        pass

    attempts: list[dict[str, Any]] = []
    alerts: list[str] = []

    def _async_client(**options: Any) -> Any:
        attempts.append(options)
        if not options.get("trust_env", True):
            return SimpleNamespace(kind="fallback")
        raise _InvalidURL("Invalid port: ':1'")

    fake_httpx = SimpleNamespace(InvalidURL=_InvalidURL, AsyncClient=_async_client)
    monkeypatch.setattr(oc, "_reported_bad_proxy_env", False)
    monkeypatch.setattr(
        oc, "record_alert", lambda name, fields=None: alerts.append(name)
    )

    # First failure: the alert names the problem once, the fallback client wins.
    client = oc.build_client(fake_httpx, verify=False)
    assert client.kind == "fallback"
    assert alerts == ["proxy_env_unparseable"]
    assert attempts[-1]["trust_env"] is False

    # Second failure: same fallback, but the alert is not repeated.
    client = oc.build_client(fake_httpx, verify=False)
    assert client.kind == "fallback"
    assert alerts == ["proxy_env_unparseable"]


# --------------------------------------------------------------------------
# request-level contracts through a MockTransport
# --------------------------------------------------------------------------
def _provider(respond: Any) -> OpenAICompatibleProvider:
    profile = ProviderProfile("default", "https://provider.example/v1", "fake", api_key="k")
    return OpenAICompatibleProvider(profile, transport=httpx.MockTransport(respond))


def _sse_body(chunks: list[dict[str, Any]]) -> str:
    return (
        "".join(f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks)
        + "data: [DONE]\n\n"
    )


def test_headers_carry_the_bearer_token_only_when_configured() -> None:
    keyed = OpenAICompatibleProvider(
        ProviderProfile("p", "https://provider.example/v1", "m", api_key="secret")
    )
    assert keyed._headers()["Authorization"] == "Bearer secret"
    anonymous = OpenAICompatibleProvider(
        ProviderProfile("p", "https://provider.example/v1", "m")
    )
    assert "Authorization" not in anonymous._headers()


@pytest.mark.asyncio
async def test_stream_chat_reraises_a_rejected_request_with_no_body_as_is() -> None:
    provider = _provider(lambda request: httpx.Response(503, text=""))
    with pytest.raises(httpx.HTTPStatusError):
        async for _ in provider.stream_chat(messages=[], tools=[], model="fake"):
            pass


@pytest.mark.asyncio
async def test_stream_chat_refuses_invalid_tool_arguments() -> None:
    body = _sse_body(
        [
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "c",
                                    "function": {"name": "doctor", "arguments": "not-json"},
                                }
                            ]
                        }
                    }
                ]
            }
        ]
    )
    provider = _provider(lambda request: httpx.Response(200, text=body))
    with pytest.raises(ValueError, match="invalid tool arguments"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="fake"):
            pass


@pytest.mark.asyncio
async def test_stream_chat_refuses_an_incomplete_tool_call() -> None:
    body = _sse_body(
        [
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {"index": 0, "id": "c", "function": {"arguments": "{}"}}
                            ]
                        }
                    }
                ]
            }
        ]
    )
    provider = _provider(lambda request: httpx.Response(200, text=body))
    with pytest.raises(ValueError, match="incomplete tool call"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="fake"):
            pass


@pytest.mark.asyncio
async def test_stream_chat_and_list_models_require_httpx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = OpenAICompatibleProvider(
        ProviderProfile("p", "https://provider.example/v1", "m", api_key="k")
    )
    # None in sys.modules is Python's known-absent sentinel: import raises.
    monkeypatch.setitem(sys.modules, "httpx", None)
    with pytest.raises(RuntimeError, match="requires httpx"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="fake"):
            pass
    with pytest.raises(RuntimeError, match="requires httpx"):
        await provider.list_models()


@pytest.mark.asyncio
async def test_list_models_returns_sorted_unique_ids() -> None:
    payload = {"data": [{"id": "m-b"}, {"id": "m-a"}, {"id": "m-a"}, "junk", {"noid": 1}]}
    provider = _provider(lambda request: httpx.Response(200, json=payload))
    assert await provider.list_models() == ["m-a", "m-b"]


@pytest.mark.asyncio
async def test_list_models_reads_non_list_data_as_empty() -> None:
    provider = _provider(lambda request: httpx.Response(200, json={"data": "x"}))
    assert await provider.list_models() == []
    provider = _provider(lambda request: httpx.Response(200, json=[1, 2]))
    assert await provider.list_models() == []


@pytest.mark.asyncio
async def test_list_models_keeps_the_rejection_body_in_the_error() -> None:
    provider = _provider(
        lambda request: httpx.Response(429, text="quota exceeded retry after 30s")
    )
    with pytest.raises(httpx.HTTPStatusError, match="quota exceeded"):
        await provider.list_models()
    # An empty body re-raises the bare status error rather than ": ".
    provider = _provider(lambda request: httpx.Response(429, text=""))
    with pytest.raises(httpx.HTTPStatusError):
        await provider.list_models()
