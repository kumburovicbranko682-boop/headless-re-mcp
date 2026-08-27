"""Degradation and parser-fallback branches of the OpenAI-compatible provider.

The happy path -- streamed text, fragmented tool calls, usage, SSE and
tool-call byte ceilings -- is pinned in ``test_agent_provider.py``. This file
covers the honesty and defensive branches the agent leans on when a provider
answers in a shape that is legal JSON but not the shape the parser hoped for:
the delta/usage field readers' fallbacks, the tool-call assembler's dedup and
error paths, the SSE reader's CRLF and trailing-buffer handling, empty error
bodies, the missing-``httpx`` guard, and the ``list_models`` success return.
Each is a place a hostile or merely idiosyncratic provider could otherwise
turn into a wrong answer or a silent hang.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as oc
from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider


def _profile(*, api_key: str | None = "k") -> ProviderProfile:
    return ProviderProfile("default", "https://provider.example/v1", "m", api_key=api_key)


# --------------------------------------------------------------------------
# _plain_text / _hidden_texts / _tool_argument_fragment
# --------------------------------------------------------------------------


def test_plain_text_skips_a_non_string_part_and_takes_the_next_key() -> None:
    """A delta object whose first candidate key is non-text falls through.

    Providers put visible text under text/content/summary; if one of those is
    present but not a string (a number, a nested object), it must be ignored
    and the next candidate tried, not stringified into the transcript.
    """
    assert oc._plain_text({"text": 123, "content": "ok"}) == "ok"
    assert oc._plain_text({"unrelated": "x"}) == ""
    assert oc._plain_text(42) == ""


def test_hidden_texts_reads_reasoning_object_and_google_thoughts() -> None:
    """Reasoning arrives three ways; each idiosyncratic shape must surface once.

    A bare ``reasoning`` object, a Gemini-style ``extra_content.google.thought``,
    and the ``extra`` spelling of the same are all hidden-thought carriers the
    agent shows as reasoning. A provider using one of them must not have its
    thinking silently dropped.
    """
    from_reasoning_object = oc._hidden_texts({"reasoning": {"text": "why"}})
    assert from_reasoning_object.count("why") == 2  # keyed pass + object pass

    assert oc._hidden_texts({"extra_content": {"google": {"thought": "g1"}}}) == ["g1"]
    assert oc._hidden_texts({"extra": {"google": {"thoughts": "g2"}}}) == ["g2"]
    assert oc._hidden_texts({}) == []


def test_hidden_texts_stays_empty_when_the_carriers_hold_nothing_usable() -> None:
    """Each reasoning carrier can be present but empty; none should emit a blank.

    An empty ``reasoning`` object, a ``google`` block that is not a dict, and a
    ``thought`` that is an empty string are all the "provider set the field but
    put no thinking in it" case. Emitting an empty reasoning delta for any of
    them would show the operator a blank thought.
    """
    assert oc._hidden_texts({"reasoning": {}}) == []
    assert oc._hidden_texts({"extra_content": {"google": "not a dict"}}) == []
    assert oc._hidden_texts({"extra_content": {"google": {"thought": ""}}}) == []


def test_tool_argument_fragment_ignores_a_type_it_cannot_serialize() -> None:
    assert oc._tool_argument_fragment("raw") == "raw"
    assert oc._tool_argument_fragment({"a": 1}) == '{"a": 1}'
    assert oc._tool_argument_fragment(3.14) == ""


# --------------------------------------------------------------------------
# _usage_output_tokens
# --------------------------------------------------------------------------


def test_usage_reads_a_float_count_and_falls_back_to_detail_sums() -> None:
    """Output-token accounting must survive floats and the details-only shape.

    Some providers report ``completion_tokens`` as a float; others omit it and
    only break the count out under ``completion_tokens_details``. Both are the
    number the run's budget is measured against, so both are read, and a usage
    object carrying neither returns None rather than a misleading zero.
    """
    assert oc._usage_output_tokens({"completion_tokens": 42.0}) == 42
    assert (
        oc._usage_output_tokens(
            {
                "completion_tokens_details": {
                    "reasoning_tokens": 3,
                    "accepted_prediction_tokens": 4,
                    "text_tokens": 5,
                }
            }
        )
        == 12
    )
    assert oc._usage_output_tokens({"completion_tokens_details": {"reasoning_tokens": "x"}}) is None
    assert oc._usage_output_tokens({"prompt_tokens": 10}) is None
    assert oc._usage_output_tokens(None) is None


# --------------------------------------------------------------------------
# _normalize_chunk
# --------------------------------------------------------------------------


def test_normalize_chunk_lifts_nested_output_choices_and_usage() -> None:
    """A responses-style ``output.choices`` envelope is flattened to top level.

    Some gateways wrap the OpenAI shape one level deeper; the parser only reads
    top-level ``choices``/``usage``, so the nested form is lifted. An existing
    top-level usage must win over the nested one, and a non-dict chunk degrades
    to an empty dict rather than raising mid-stream.
    """
    assert oc._normalize_chunk("not a dict") == {}

    lifted = oc._normalize_chunk(
        {"output": {"choices": [{"x": 1}], "usage": {"completion_tokens": 5}}}
    )
    assert lifted["choices"] == [{"x": 1}]
    assert lifted["usage"] == {"completion_tokens": 5}

    kept = oc._normalize_chunk(
        {
            "usage": {"completion_tokens": 9},
            "output": {"choices": [{"x": 1}], "usage": {"completion_tokens": 5}},
        }
    )
    assert kept["usage"] == {"completion_tokens": 9}


# --------------------------------------------------------------------------
# _ingest_tool_calls
# --------------------------------------------------------------------------


def test_ingest_tool_calls_ignores_non_list_and_non_dict_entries() -> None:
    assert oc._ingest_tool_calls("not a list", {}, 0) == (0, [])
    fragments: dict[int, dict[str, str]] = {}
    used, pieces = oc._ingest_tool_calls([123, None], fragments, 0)
    assert (used, pieces, fragments) == (0, [], {})


def test_ingest_tool_calls_deduplicates_repeated_id_and_name() -> None:
    """Snapshot-style streams resend the same id/name each chunk; keep it once.

    A provider that re-emits the whole tool call every delta would otherwise
    concatenate ``call-acall-a`` and ``getget``. The id and name are appended
    only when not already present, so a resent snapshot is idempotent, while a
    fresh arguments fragment still accumulates.
    """
    fragments: dict[int, dict[str, str]] = {}
    call = [{"index": 0, "id": "call-a", "function": {"name": "get", "arguments": ""}}]
    oc._ingest_tool_calls(call, fragments, 0)
    oc._ingest_tool_calls(call, fragments, 0)

    assert fragments[0]["id"] == "call-a"
    assert fragments[0]["name"] == "get"


def test_ingest_tool_calls_skips_an_empty_argument_fragment() -> None:
    """A tool-call delta that carries no arguments text emits no output piece."""
    fragments: dict[int, dict[str, str]] = {}
    _, pieces = oc._ingest_tool_calls(
        [{"index": 0, "function": {"name": "doctor"}}], fragments, 0
    )
    assert pieces == ["doctor"]
    assert fragments[0]["arguments"] == ""


def test_ingest_tool_calls_bounds_the_id_bytes() -> None:
    """The id is peer-controlled and accumulates; it needs the same byte ceiling."""
    fragments: dict[int, dict[str, str]] = {}
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls(
            [{"index": 0, "id": "x" * 32, "function": {}}],
            fragments,
            oc._MAX_TOOL_CALL_BUFFER_BYTES,
        )


def test_ingest_tool_calls_bounds_the_name_bytes() -> None:
    fragments: dict[int, dict[str, str]] = {}
    with pytest.raises(ValueError, match="tool-call buffer exceeded"):
        oc._ingest_tool_calls(
            [{"index": 0, "function": {"name": "n" * 32}}],
            fragments,
            oc._MAX_TOOL_CALL_BUFFER_BYTES,
        )


# --------------------------------------------------------------------------
# _aiter_bounded_sse_lines / _read_bounded_error_detail
# --------------------------------------------------------------------------


class _BytesResponse:
    """Minimal response exposing aiter_bytes over a fixed chunk list."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


async def _collect(response: _BytesResponse, **kwargs: Any) -> list[str]:
    return [line async for line in oc._aiter_bounded_sse_lines(response, **kwargs)]


@pytest.mark.asyncio
async def test_sse_reader_strips_crlf_on_split_and_trailing_lines() -> None:
    """SSE uses CRLF; the \\r must be trimmed whether the line ends a chunk or the body.

    A newline-terminated CRLF line exercises the in-loop trim; a body that ends
    without a final newline exercises the trailing-buffer flush, which also
    trims. Either \\r left in place would corrupt the JSON payload that follows.
    """
    lines = await _collect(_BytesResponse([b"data: a\r\n", b"data: b\r"]))
    assert lines == ["data: a", "data: b"]


@pytest.mark.asyncio
async def test_sse_reader_yields_a_trailing_line_that_has_no_carriage_return() -> None:
    """A body ending mid-line without CRLF is still yielded, un-trimmed."""
    lines = await _collect(_BytesResponse([b"data: x"]))
    assert lines == ["data: x"]


@pytest.mark.asyncio
async def test_sse_reader_refuses_an_oversized_line_at_the_newline() -> None:
    """The ceiling applies to a completed line, not only to an endless one."""
    with pytest.raises(ValueError, match="SSE line exceeded 4 bytes"):
        await _collect(_BytesResponse([b"aaaaaa\n"]), max_line_bytes=4)


@pytest.mark.asyncio
async def test_sse_reader_refuses_an_oversized_trailing_line() -> None:
    """A body that never sends its final newline is still bounded on flush."""
    with pytest.raises(ValueError, match="SSE line exceeded 4 bytes"):
        await _collect(_BytesResponse([b"aa", b"aaaa"]), max_line_bytes=4)


# --------------------------------------------------------------------------
# provider-level branches: headers, missing httpx, empty error bodies
# --------------------------------------------------------------------------


def test_headers_omit_authorization_without_an_api_key() -> None:
    """A keyless local endpoint must not get an empty Bearer header."""
    provider = OpenAICompatibleProvider(_profile(api_key=None))
    headers = provider._headers()
    assert "Authorization" not in headers
    assert headers["Accept"] == "text/event-stream"


@pytest.mark.asyncio
async def test_stream_chat_reports_a_missing_web_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without httpx the failure must name the extra, not raise ImportError raw."""
    monkeypatch.setitem(sys.modules, "httpx", None)
    provider = OpenAICompatibleProvider(_profile())
    with pytest.raises(RuntimeError, match="web extra requires httpx"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_list_models_reports_a_missing_web_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)
    provider = OpenAICompatibleProvider(_profile())
    with pytest.raises(RuntimeError, match="web extra requires httpx"):
        await provider.list_models()


@pytest.mark.asyncio
async def test_stream_chat_reraises_a_bare_status_when_the_error_body_is_empty() -> None:
    """With nothing to enrich, the original status error is re-raised untouched."""

    def empty_429(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content=b"")

    provider = OpenAICompatibleProvider(
        _profile(), transport=httpx.MockTransport(empty_429)
    )
    with pytest.raises(httpx.HTTPStatusError) as caught:
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass
    assert "429" in str(caught.value)


@pytest.mark.asyncio
async def test_list_models_reraises_a_bare_status_when_the_error_body_is_empty() -> None:
    def empty_429(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content=b"")

    provider = OpenAICompatibleProvider(
        _profile(), transport=httpx.MockTransport(empty_429)
    )
    with pytest.raises(httpx.HTTPStatusError):
        await provider.list_models()


@pytest.mark.asyncio
async def test_list_models_returns_sorted_unique_string_ids() -> None:
    """The success path dedupes, sorts, and keeps only string ids.

    A models list can repeat an id, carry a non-object row, or an object whose
    id is not a string; none of those should crash the listing or smuggle a
    non-string into the result the console renders.
    """

    def models(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": [{"id": "m2"}, {"id": "m1"}, {"id": "m1"}, {"no": "id"}, "x"]},
        )

    provider = OpenAICompatibleProvider(
        _profile(), transport=httpx.MockTransport(models)
    )
    assert await provider.list_models() == ["m1", "m2"]


@pytest.mark.asyncio
async def test_list_models_tolerates_a_response_without_a_data_list() -> None:
    def models(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"object": "list"})

    provider = OpenAICompatibleProvider(
        _profile(), transport=httpx.MockTransport(models)
    )
    assert await provider.list_models() == []


# --------------------------------------------------------------------------
# final tool-call assembly errors
# --------------------------------------------------------------------------


def _stream_response(body: str):  # type: ignore[no-untyped-def]
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    return httpx.MockTransport(respond)


@pytest.mark.asyncio
async def test_assembly_rejects_tool_arguments_that_are_not_json() -> None:
    """A truncated or malformed arguments buffer is the provider's fault, named so."""
    body = (
        'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c",'
        '"function":{"name":"get","arguments":"{oops"}}]}}]}\n\n'
        "data: [DONE]\n\n"
    )
    provider = OpenAICompatibleProvider(_profile(), transport=_stream_response(body))
    with pytest.raises(ValueError, match="invalid tool arguments at index 0"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_assembly_rejects_a_tool_call_that_never_got_a_name() -> None:
    """Valid-JSON arguments with no function name is an incomplete call, not runnable."""
    body = (
        'data: {"choices":[{"delta":{"tool_calls":[{"index":0,'
        '"function":{"arguments":"{}"}}]}}]}\n\n'
        "data: [DONE]\n\n"
    )
    provider = OpenAICompatibleProvider(_profile(), transport=_stream_response(body))
    with pytest.raises(ValueError, match="incomplete tool call at index 0"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_assembly_rejects_tool_arguments_that_are_a_list_not_an_object() -> None:
    """Arguments must be a JSON object; a bare array cannot map to keyword args."""
    body = (
        'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c",'
        '"function":{"name":"get","arguments":"[1,2]"}}]}}]}\n\n'
        "data: [DONE]\n\n"
    )
    provider = OpenAICompatibleProvider(_profile(), transport=_stream_response(body))
    with pytest.raises(ValueError, match="incomplete tool call at index 0"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_build_client_alerts_only_once_about_an_unparseable_proxy_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The proxy-env warning is a one-shot; a second bad build must stay quiet.

    Every LLM round builds a client, so alerting on each would bury the log
    under the same message. Once reported, subsequent builds still fall back to
    trust_env=False silently.
    """
    broken = "127.0.0.1,::1/128"
    monkeypatch.setenv("NO_PROXY", broken)
    monkeypatch.setenv("no_proxy", broken)
    monkeypatch.setattr(oc, "_reported_bad_proxy_env", True)
    alerts: list[str] = []
    monkeypatch.setattr(oc, "record_alert", lambda kind, **kwargs: alerts.append(kind))

    client = oc.build_client(httpx, timeout=5.0, transport=None)

    assert client.trust_env is False
    assert alerts == []
    await client.aclose()
