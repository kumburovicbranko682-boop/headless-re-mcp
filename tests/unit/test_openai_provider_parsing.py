"""Parsing and assembly contract for the OpenAI-compatible provider.

Every value here comes off the wire from a third-party model endpoint, so the
delta/usage/tool-call helpers must accept the shapes real providers actually
send and quietly ignore the ones they must not stringify. The existing
``test_agent_provider.py`` drives these through httpx; this file exercises the
pure helpers directly (and a few final-assembly / models branches) so the
odd-shaped inputs are pinned without a transport in the way.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as oc
from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import (
    OpenAICompatibleProvider,
    _hidden_texts,
    _ingest_tool_calls,
    _normalize_chunk,
    _plain_text,
    _sse_payload,
    _tool_argument_fragment,
    _usage_output_tokens,
)


def _profile(api_key: str = "k") -> ProviderProfile:
    return ProviderProfile("default", "https://provider.example/v1", "m", api_key=api_key)


def _sse(*chunks: Mapping[str, object]) -> str:
    body = "".join(f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks)
    return body + "data: [DONE]\n\n"


# ---------------------------------------------------------------------------
# _plain_text: providers disagree on how a delta field is shaped
# ---------------------------------------------------------------------------


def test_plain_text_reads_the_shapes_and_ignores_the_rest() -> None:
    assert _plain_text("hi") == "hi"
    assert _plain_text([{"text": "a"}, "b", 7]) == "ab"
    # The first string-valued key wins; a non-string value is skipped.
    assert _plain_text({"text": 123, "content": "ok"}) == "ok"
    # A dict with no recognised key yields nothing rather than its repr.
    assert _plain_text({"nope": "x"}) == ""
    assert _plain_text(42) == ""


# ---------------------------------------------------------------------------
# _hidden_texts: reasoning / thinking arrives under many vendor keys
# ---------------------------------------------------------------------------


def test_hidden_texts_pulls_reasoning_object_and_google_thoughts() -> None:
    # An object-shaped reasoning field is read exactly once (the key loop's
    # _plain_text already handles the object), so it is not double-emitted.
    assert _hidden_texts({"reasoning": {"text": "r"}}) == ["r"]
    # The string form is unchanged, and both spell out to a single piece.
    assert _hidden_texts({"reasoning": "r"}) == ["r"]
    assert _hidden_texts({"reasoning_content": "r"}) == ["r"]
    # Google-style thoughts ride under extra_content.google.thought ...
    assert _hidden_texts({"extra_content": {"google": {"thought": "g"}}}) == ["g"]
    # ... and fall back to a bare `extra` container using the plural key.
    assert _hidden_texts({"extra": {"google": {"thoughts": "g2"}}}) == ["g2"]
    # Nothing hidden means an empty list, not a spurious blank chunk.
    assert _hidden_texts({"content": "visible"}) == []
    # Object-shaped fields that carry no usable text add nothing: a reasoning
    # object with no recognised key, a non-object google container, and an
    # empty thought string are each dropped rather than emitted blank.
    assert _hidden_texts({"reasoning": {"nope": "x"}}) == []
    assert _hidden_texts({"extra_content": {"google": "not-an-object"}}) == []
    assert _hidden_texts({"extra_content": {"google": {"thought": ""}}}) == []


def test_tool_argument_fragment_serialises_only_known_shapes() -> None:
    assert _tool_argument_fragment("literal") == "literal"
    assert _tool_argument_fragment({"a": 1}) == '{"a": 1}'
    assert _tool_argument_fragment([1, 2]) == "[1, 2]"
    assert _tool_argument_fragment(5) == ""


# ---------------------------------------------------------------------------
# _usage_output_tokens: OpenAI/DeepSeek report tokens several ways
# ---------------------------------------------------------------------------


def test_usage_output_tokens_across_provider_spellings() -> None:
    assert _usage_output_tokens({"completion_tokens": 42}) == 42
    # A float count is floored to an int.
    assert _usage_output_tokens({"output_tokens": 7.9}) == 7
    # Absent a top-level count, the detail breakdown is summed.
    assert (
        _usage_output_tokens(
            {
                "completion_tokens_details": {
                    "reasoning_tokens": 3,
                    "accepted_prediction_tokens": 2,
                    "text_tokens": 1,
                }
            }
        )
        == 6
    )
    assert _usage_output_tokens({"unrelated": 1}) is None
    assert _usage_output_tokens("not-a-dict") is None
    # A details block whose numbers are all non-integers yields nothing summed.
    assert _usage_output_tokens({"completion_tokens_details": {"reasoning_tokens": "x"}}) is None


# ---------------------------------------------------------------------------
# _normalize_chunk: the Responses-style {"output": {...}} envelope
# ---------------------------------------------------------------------------


def test_normalize_chunk_lifts_the_output_envelope() -> None:
    assert _normalize_chunk("not-a-dict") == {}
    merged = _normalize_chunk(
        {"output": {"choices": [{"delta": {"content": "hi"}}], "usage": {"completion_tokens": 4}}}
    )
    assert merged["choices"] == [{"delta": {"content": "hi"}}]
    # The nested usage is only borrowed when the top level has none.
    assert merged["usage"] == {"completion_tokens": 4}
    kept = _normalize_chunk(
        {
            "usage": {"completion_tokens": 9},
            "output": {"choices": [], "usage": {"completion_tokens": 4}},
        }
    )
    assert kept["usage"] == {"completion_tokens": 9}


def test_sse_payload_recognises_data_lines_and_bare_json() -> None:
    assert _sse_payload('data: {"a":1}') == '{"a":1}'
    assert _sse_payload('{"bare":true}') == '{"bare":true}'
    # A keep-alive `data:` with nothing after it is not a payload.
    assert _sse_payload("data:") is None
    assert _sse_payload("event: ping") is None


# ---------------------------------------------------------------------------
# _ingest_tool_calls: streamed fragments must dedupe and stay bounded
# ---------------------------------------------------------------------------


def test_ingest_tool_calls_dedupes_ids_and_names_and_skips_junk() -> None:
    fragments: dict[int, dict[str, str]] = {}
    _, first = _ingest_tool_calls("not-a-list", fragments, 0)
    assert first == []
    _, _pieces = _ingest_tool_calls(
        [
            "junk",
            {"index": 0, "id": "abc", "function": {"name": "t", "arguments": "{}"}},
            {"index": 0, "id": "abc", "function": {"name": "t", "arguments": ""}},
        ],
        fragments,
        0,
    )
    # The repeated id/name are not concatenated onto themselves, and the empty
    # arguments fragment adds nothing.
    assert fragments[0] == {"id": "abc", "name": "t", "arguments": "{}"}


def test_ingest_tool_calls_bounds_id_and_name_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oc, "_MAX_TOOL_CALL_BUFFER_BYTES", 4)
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        _ingest_tool_calls([{"index": 0, "id": "abcdef", "function": {}}], {}, 0)
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        _ingest_tool_calls([{"index": 0, "id": "a", "function": {"name": "abcdef"}}], {}, 0)


# ---------------------------------------------------------------------------
# _aiter_bounded_sse_lines: line splitting edges
# ---------------------------------------------------------------------------


class _FakeByteStream:
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = chunks

    async def aiter_bytes(self):  # type: ignore[no-untyped-def]
        for chunk in self._chunks:
            yield chunk


async def _collect_lines(*chunks: bytes, **kwargs: object) -> list[str]:
    return [
        line
        async for line in oc._aiter_bounded_sse_lines(_FakeByteStream(*chunks), **kwargs)  # type: ignore[arg-type]
    ]


@pytest.mark.asyncio
async def test_sse_splitter_strips_carriage_returns_and_flushes_a_trailing_line() -> None:
    # A mid-stream CRLF line is trimmed, and a final line with no newline is
    # still yielded (with its CR removed) instead of being dropped.
    assert await _collect_lines(b"a\r\nb\n") == ["a", "b"]
    assert await _collect_lines(b'data: {"x":1}\r') == ['data: {"x":1}']
    # A trailing line with neither newline nor CR is flushed verbatim.
    assert await _collect_lines(b"tail-no-eol") == ["tail-no-eol"]


@pytest.mark.asyncio
async def test_sse_splitter_refuses_an_oversized_completed_line() -> None:
    # A line that terminates with a newline but blew the ceiling before it is
    # rejected, not buffered.
    with pytest.raises(ValueError, match="SSE line exceeded 10 bytes"):
        await _collect_lines(b"x" * 50 + b"\n", max_line_bytes=10)


# ---------------------------------------------------------------------------
# stream_chat: header shaping and final tool-call assembly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_omits_authorization_when_no_key_is_configured() -> None:
    observed: dict[str, object] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        observed["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, text=_sse({"choices": [{"delta": {"content": "hi"}}]}))

    provider = OpenAICompatibleProvider(
        _profile(api_key=""), transport=httpx.MockTransport(respond)
    )
    events = [e async for e in provider.stream_chat(messages=[], tools=[], model="m")]
    assert observed["authorization"] is None
    assert events[-1].type == "completed"


@pytest.mark.asyncio
async def test_object_shaped_reasoning_is_streamed_once_not_twice() -> None:
    # Regression: a provider that sends delta.reasoning as an object used to
    # produce two reasoning_delta events for one chunk, so the orchestrator
    # stored the thinking text doubled.
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=_sse(
                {"choices": [{"delta": {"reasoning": {"text": "let me think"}}}]},
                {"choices": [{"delta": {}, "finish_reason": "stop"}]},
            ),
        )

    provider = OpenAICompatibleProvider(_profile(), transport=httpx.MockTransport(respond))
    events = [e async for e in provider.stream_chat(messages=[], tools=[], model="m")]
    assert [e.text for e in events if e.type == "reasoning_delta"] == ["let me think"]


@pytest.mark.asyncio
async def test_stream_reraises_a_bare_status_when_the_error_body_is_empty() -> None:
    def rejected(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"")

    provider = OpenAICompatibleProvider(_profile(), transport=httpx.MockTransport(rejected))
    with pytest.raises(httpx.HTTPStatusError) as caught:
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass
    # No body means the message stays the plain status, with no ": detail" tail.
    assert "500" in str(caught.value)


@pytest.mark.asyncio
async def test_stream_rejects_tool_arguments_that_never_became_valid_json() -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        chunk = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "id": "c", "function": {"name": "t", "arguments": "{oops"}}
                        ]
                    }
                }
            ]
        }
        return httpx.Response(200, text=_sse(chunk))

    provider = OpenAICompatibleProvider(_profile(), transport=httpx.MockTransport(broken))
    with pytest.raises(ValueError, match="invalid tool arguments at index 0"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_stream_rejects_a_tool_call_that_never_named_a_function() -> None:
    def nameless(request: httpx.Request) -> httpx.Response:
        chunk = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [{"index": 0, "id": "c", "function": {"arguments": "{}"}}]
                    }
                }
            ]
        }
        return httpx.Response(200, text=_sse(chunk))

    provider = OpenAICompatibleProvider(_profile(), transport=httpx.MockTransport(nameless))
    with pytest.raises(ValueError, match="incomplete tool call at index 0"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_stream_rejects_tool_arguments_that_are_not_an_object() -> None:
    def array_args(request: httpx.Request) -> httpx.Response:
        chunk = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "id": "c", "function": {"name": "t", "arguments": "[1,2]"}}
                        ]
                    }
                }
            ]
        }
        return httpx.Response(200, text=_sse(chunk))

    provider = OpenAICompatibleProvider(_profile(), transport=httpx.MockTransport(array_args))
    with pytest.raises(ValueError, match="incomplete tool call at index 0"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


# ---------------------------------------------------------------------------
# list_models: success shape and empty-error path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_models_returns_sorted_ids_and_ignores_malformed_entries() -> None:
    def models(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": [{"id": "beta"}, {"id": "alpha"}, {"no_id": 1}, "junk"]},
        )

    provider = OpenAICompatibleProvider(_profile(), transport=httpx.MockTransport(models))
    assert await provider.list_models() == ["alpha", "beta"]


@pytest.mark.asyncio
async def test_list_models_returns_empty_when_data_is_not_a_list() -> None:
    def odd(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": "not-a-list"})

    provider = OpenAICompatibleProvider(_profile(), transport=httpx.MockTransport(odd))
    assert await provider.list_models() == []


@pytest.mark.asyncio
async def test_list_models_reraises_a_bare_status_when_the_error_body_is_empty() -> None:
    def rejected(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, content=b"")

    provider = OpenAICompatibleProvider(_profile(), transport=httpx.MockTransport(rejected))
    with pytest.raises(httpx.HTTPStatusError) as caught:
        await provider.list_models()
    assert "503" in str(caught.value)


# ---------------------------------------------------------------------------
# httpx is an optional extra: both entrypoints must say so, not NameError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_chat_reports_the_missing_web_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)
    provider = OpenAICompatibleProvider(_profile())
    with pytest.raises(RuntimeError, match="web extra requires httpx"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_list_models_reports_the_missing_web_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)
    provider = OpenAICompatibleProvider(_profile())
    with pytest.raises(RuntimeError, match="web extra requires httpx"):
        await provider.list_models()


# ---------------------------------------------------------------------------
# build_client: the proxy-env alert fires once, not per client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_build_client_does_not_realert_after_the_first_bad_proxy_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken = "127.0.0.1,::1/128"
    monkeypatch.setenv("NO_PROXY", broken)
    monkeypatch.setenv("no_proxy", broken)
    # Pretend the alert already fired: a second unusable build must stay quiet.
    monkeypatch.setattr(oc, "_reported_bad_proxy_env", True)
    alerts: list[str] = []
    monkeypatch.setattr(oc, "record_alert", lambda kind, **kwargs: alerts.append(kind))

    with pytest.raises(httpx.InvalidURL):
        httpx.AsyncClient(transport=None)

    client = oc.build_client(httpx, timeout=5.0, transport=None)
    assert client.trust_env is False
    assert alerts == []
    await client.aclose()
