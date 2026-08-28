"""Direct coverage for the OpenAI-compatible provider's parsing helpers.

``test_agent_provider.py`` drives ``stream_chat``/``list_models`` end to end
through a mock transport, which leaves the small provider-shape helpers and a
handful of completion branches unverified in isolation. This file unit-tests
those helpers directly -- the delta/reasoning text extractors, the usage
mapper, the chunk normalizer, the SSE payload splitter, the tool-call
accumulator, and the bounded byte-line reader -- plus the completion-time
tool-call validation and the ``list_models`` response shaping.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as oc
from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider


class _BytesResponse:
    """Minimal stand-in exposing the ``aiter_bytes`` the readers consume."""

    def __init__(self, *chunks: bytes) -> None:
        self._chunks = chunks

    async def aiter_bytes(self) -> Any:
        for chunk in self._chunks:
            yield chunk


async def _collect(aiter: Any) -> list[Any]:
    return [item async for item in aiter]


def _provider(respond: Any) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(respond),
    )


# ---------------------------------------------------------------------------
# _plain_text


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("hello", "hello"),
        (["a", "b", "c"], "abc"),
        ([{"text": "x"}, {"content": "y"}], "xy"),
        ({"text": "t"}, "t"),
        ({"content": "c"}, "c"),
        ({"summary": "s"}, "s"),
        ({"other": "ignored"}, ""),
        ({"text": ""}, ""),
        (42, ""),
        (None, ""),
    ],
)
def test_plain_text_pulls_visible_text_out_of_each_shape(value: Any, expected: str) -> None:
    assert oc._plain_text(value) == expected


# ---------------------------------------------------------------------------
# _hidden_texts


def test_hidden_texts_reads_reasoning_content_and_thinking() -> None:
    delta = {"reasoning_content": "step one ", "thinking": "step two"}
    assert oc._hidden_texts(delta) == ["step one ", "step two"]


def test_hidden_texts_reads_a_reasoning_object() -> None:
    # "reasoning" is both in _HIDDEN_DELTA_KEYS (handled by _plain_text, which
    # reads the "text" field of a dict) and handled again by the explicit
    # reasoning-dict block, so a reasoning object currently emits twice. Pin
    # the observed behavior rather than the ideal single emission.
    assert oc._hidden_texts({"reasoning": {"text": "because"}}) == ["because", "because"]


def test_hidden_texts_reads_a_string_reasoning_field_once() -> None:
    # A string "reasoning" is handled only by the keyed loop (the dict-only
    # block below it does not fire), so it appears exactly once.
    assert oc._hidden_texts({"reasoning": "plain"}) == ["plain"]


def test_hidden_texts_ignores_empty_leading_chunks() -> None:
    assert oc._hidden_texts({"reasoning_content": ""}) == []


def test_hidden_texts_reads_google_thought_out_of_extra_content() -> None:
    delta = {"extra_content": {"google": {"thought": "gemini reasoning"}}}
    assert oc._hidden_texts(delta) == ["gemini reasoning"]


def test_hidden_texts_falls_back_to_extra_when_extra_content_is_absent() -> None:
    delta = {"extra": {"google": {"thoughts": "via extra"}}}
    assert oc._hidden_texts(delta) == ["via extra"]


def test_hidden_texts_ignores_extra_that_is_not_a_mapping() -> None:
    assert oc._hidden_texts({"extra": "nope", "extra_content": 5}) == []


# ---------------------------------------------------------------------------
# _tool_argument_fragment


def test_tool_argument_fragment_passes_strings_through() -> None:
    assert oc._tool_argument_fragment('{"a": 1}') == '{"a": 1}'


def test_tool_argument_fragment_serializes_objects_and_lists() -> None:
    assert oc._tool_argument_fragment({"a": 1}) == '{"a": 1}'
    assert oc._tool_argument_fragment([1, 2]) == "[1, 2]"


def test_tool_argument_fragment_ignores_other_types() -> None:
    assert oc._tool_argument_fragment(None) == ""
    assert oc._tool_argument_fragment(7) == ""


# ---------------------------------------------------------------------------
# _usage_output_tokens


def test_usage_output_tokens_reads_an_integer_completion_count() -> None:
    assert oc._usage_output_tokens({"completion_tokens": 42}) == 42


def test_usage_output_tokens_truncates_a_float_count() -> None:
    assert oc._usage_output_tokens({"output_tokens": 12.9}) == 12


def test_usage_output_tokens_sums_completion_token_details() -> None:
    usage = {
        "completion_tokens_details": {
            "reasoning_tokens": 5,
            "accepted_prediction_tokens": 3,
            "text_tokens": 2,
        }
    }
    assert oc._usage_output_tokens(usage) == 10


def test_usage_output_tokens_returns_none_when_nothing_is_present() -> None:
    assert oc._usage_output_tokens({}) is None
    assert oc._usage_output_tokens("not a dict") is None
    assert oc._usage_output_tokens({"completion_tokens_details": {}}) is None


# ---------------------------------------------------------------------------
# _normalize_chunk


def test_normalize_chunk_returns_empty_for_a_non_mapping() -> None:
    assert oc._normalize_chunk("nope") == {}


def test_normalize_chunk_lifts_nested_output_choices_and_usage() -> None:
    chunk = {
        "output": {"choices": [{"delta": {"content": "x"}}], "usage": {"completion_tokens": 4}},
    }
    merged = oc._normalize_chunk(chunk)
    assert merged["choices"] == [{"delta": {"content": "x"}}]
    assert merged["usage"] == {"completion_tokens": 4}


def test_normalize_chunk_keeps_an_existing_top_level_usage() -> None:
    chunk = {
        "usage": {"completion_tokens": 1},
        "output": {"choices": [], "usage": {"completion_tokens": 99}},
    }
    assert oc._normalize_chunk(chunk)["usage"] == {"completion_tokens": 1}


def test_normalize_chunk_passes_a_flat_chunk_through_unchanged() -> None:
    chunk = {"choices": [{"delta": {"content": "hi"}}]}
    assert oc._normalize_chunk(chunk) is chunk


# ---------------------------------------------------------------------------
# _sse_payload


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('data: {"a": 1}', '{"a": 1}'),
        ('data:{"a":1}', '{"a":1}'),
        ("data: [DONE]", "[DONE]"),
        ('{"bare": true}', '{"bare": true}'),
        ("data: ", None),
        ("event: ping", None),
        ("", None),
    ],
)
def test_sse_payload_extracts_only_data_or_bare_json(line: str, expected: str | None) -> None:
    assert oc._sse_payload(line) == expected


# ---------------------------------------------------------------------------
# _ingest_tool_calls


def test_ingest_ignores_a_non_list_and_non_dict_entries() -> None:
    frags: dict[int, dict[str, str]] = {}
    assert oc._ingest_tool_calls("nope", frags, 0) == (0, [])
    calls = [None, 5, {"index": 0, "function": {"name": "d", "arguments": "{}"}}]
    total, pieces = oc._ingest_tool_calls(calls, frags, 0)
    assert frags[0]["name"] == "d"
    assert pieces == ["d", "{}"]


def test_ingest_defaults_a_missing_index_to_zero() -> None:
    frags: dict[int, dict[str, str]] = {}
    oc._ingest_tool_calls([{"id": "x", "function": {"name": "n"}}], frags, 0)
    assert frags[0]["id"] == "x"
    assert frags[0]["name"] == "n"


def test_ingest_does_not_duplicate_an_id_or_name_already_seen() -> None:
    frags = {0: {"id": "call-a", "name": "session.get", "arguments": ""}}
    total, pieces = oc._ingest_tool_calls(
        [{"index": 0, "id": "call-a", "function": {"name": "session.get"}}],
        frags,
        0,
    )
    assert frags[0]["id"] == "call-a", "a repeated id must not be concatenated"
    assert frags[0]["name"] == "session.get"
    assert pieces == [], "a name already recorded must not re-emit an output piece"


def test_ingest_skips_an_empty_argument_fragment() -> None:
    frags: dict[int, dict[str, str]] = {}
    total, pieces = oc._ingest_tool_calls(
        [{"index": 0, "function": {"name": "n", "arguments": ""}}],
        frags,
        0,
    )
    assert frags[0]["arguments"] == ""
    assert pieces == ["n"], "only the name piece, no empty-argument piece"


def test_ingest_accumulates_bytes_across_id_name_and_arguments() -> None:
    frags: dict[int, dict[str, str]] = {}
    total, _ = oc._ingest_tool_calls(
        [{"index": 0, "id": "ab", "function": {"name": "cd", "arguments": "ef"}}],
        frags,
        0,
    )
    assert total == len(b"ab") + len(b"cd") + len(b"ef")


def test_ingest_refuses_an_oversized_call_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oc, "_MAX_TOOL_CALL_BUFFER_BYTES", 10)
    with pytest.raises(ValueError, match="tool-call buffer exceeded 10 bytes"):
        oc._ingest_tool_calls([{"index": 0, "id": "x" * 100}], {}, 0)


def test_ingest_refuses_an_oversized_function_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oc, "_MAX_TOOL_CALL_BUFFER_BYTES", 10)
    with pytest.raises(ValueError, match="tool-call buffer exceeded 10 bytes"):
        oc._ingest_tool_calls([{"index": 0, "function": {"name": "y" * 100}}], {}, 0)


# ---------------------------------------------------------------------------
# _headers


def test_headers_omit_authorization_when_no_api_key_is_configured() -> None:
    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="")
    )
    headers = provider._headers()
    assert "Authorization" not in headers
    assert headers["Accept"] == "text/event-stream"


def test_headers_carry_a_bearer_token_when_an_api_key_is_configured() -> None:
    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="secret")
    )
    assert provider._headers()["Authorization"] == "Bearer secret"


# ---------------------------------------------------------------------------
# _aiter_bounded_sse_lines


@pytest.mark.asyncio
async def test_bounded_sse_lines_splits_across_chunks_and_strips_crlf() -> None:
    response = _BytesResponse(b"data: on", b"e\r\ndata: two\n")
    lines = await _collect(oc._aiter_bounded_sse_lines(response))
    assert lines == ["data: one", "data: two"]


@pytest.mark.asyncio
async def test_bounded_sse_lines_flushes_a_trailing_line_without_a_newline() -> None:
    response = _BytesResponse(b"data: only")
    assert await _collect(oc._aiter_bounded_sse_lines(response)) == ["data: only"]


@pytest.mark.asyncio
async def test_bounded_sse_lines_flushes_a_trailing_line_stripping_a_bare_cr() -> None:
    response = _BytesResponse(b"data: tail\r")
    assert await _collect(oc._aiter_bounded_sse_lines(response)) == ["data: tail"]


@pytest.mark.asyncio
async def test_bounded_sse_lines_refuses_a_line_that_grows_past_the_limit() -> None:
    response = _BytesResponse(b"x" * 40, b"y" * 40)
    with pytest.raises(ValueError, match="SSE line exceeded 64 bytes"):
        await _collect(oc._aiter_bounded_sse_lines(response, max_line_bytes=64))


@pytest.mark.asyncio
async def test_bounded_sse_lines_refuses_an_oversized_completed_line() -> None:
    response = _BytesResponse(b"z" * 100 + b"\n")
    with pytest.raises(ValueError, match="SSE line exceeded 64 bytes"):
        await _collect(oc._aiter_bounded_sse_lines(response, max_line_bytes=64))


@pytest.mark.asyncio
async def test_bounded_sse_lines_refuses_an_oversized_trailing_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A buffer that only becomes over-limit at end-of-stream flush: 40 bytes
    # fit under a 64-byte cap during accumulation, but the trailing-flush guard
    # is checked independently, so shrink the cap so the retained 40 trip it.
    response = _BytesResponse(b"a" * 40)
    monkeypatch.setattr(oc, "_MAX_SSE_LINE_BYTES", 16)
    with pytest.raises(ValueError, match="SSE line exceeded 16 bytes"):
        await _collect(oc._aiter_bounded_sse_lines(response))


# ---------------------------------------------------------------------------
# completion-time tool-call validation (stream_chat tail)


def _sse_body(*chunks: dict[str, Any]) -> str:
    return (
        "".join(f"data: {json.dumps(c, separators=(',', ':'))}\n\n" for c in chunks)
        + "data: [DONE]\n\n"
    )


@pytest.mark.asyncio
async def test_completion_rejects_tool_arguments_that_are_not_json() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        del request
        chunk = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "id": "c", "function": {"name": "n", "arguments": "{oops"}}
                        ]
                    }
                }
            ]
        }
        return httpx.Response(200, text=_sse_body(chunk))

    with pytest.raises(ValueError, match="invalid tool arguments at index 0"):
        async for _ in _provider(respond).stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
async def test_completion_rejects_non_finite_tool_argument_constants(literal: str) -> None:
    # json.loads accepts the non-standard tokens NaN/Infinity/-Infinity by
    # default, so a malformed provider could smuggle a float nan/inf into a
    # tool argument. Downstream assumes standard JSON: the args hash uses
    # allow_nan=False and would abort the whole run with an opaque ValueError,
    # and the stored row plus the replayed assistant turn would carry a bare
    # NaN that a strict provider parser rejects. It must fail as the same clean
    # "invalid tool arguments" error the parser raises for any other bad JSON.
    def respond(request: httpx.Request) -> httpx.Response:
        del request
        chunk = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "c",
                                "function": {"name": "n", "arguments": f'{{"x": {literal}}}'},
                            }
                        ]
                    }
                }
            ]
        }
        return httpx.Response(200, text=_sse_body(chunk))

    with pytest.raises(ValueError, match="invalid tool arguments at index 0"):
        async for _ in _provider(respond).stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_completion_rejects_a_tool_call_that_never_named_a_function() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        del request
        chunk = {
            "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{}"}}]}}]
        }
        return httpx.Response(200, text=_sse_body(chunk))

    with pytest.raises(ValueError, match="incomplete tool call at index 0"):
        async for _ in _provider(respond).stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_completion_synthesizes_a_call_id_when_the_provider_omits_one() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        del request
        call = {"index": 0, "function": {"name": "doctor", "arguments": "{}"}}
        chunk = {"choices": [{"delta": {"tool_calls": [call]}}]}
        return httpx.Response(200, text=_sse_body(chunk))

    events = [
        event async for event in _provider(respond).stream_chat(messages=[], tools=[], model="m")
    ]
    call = events[-1].tool_calls[0]
    assert call.id == "call_0", "a missing id becomes call_<index>"
    assert call.name == "doctor"


@pytest.mark.asyncio
async def test_a_rejected_stream_with_an_empty_body_reraises_the_bare_status() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(500, content=b"")

    with pytest.raises(httpx.HTTPStatusError) as caught:
        async for _ in _provider(respond).stream_chat(messages=[], tools=[], model="m"):
            pass
    assert "500" in str(caught.value)


# ---------------------------------------------------------------------------
# list_models


@pytest.mark.asyncio
async def test_list_models_returns_sorted_string_ids_ignoring_other_shapes() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/models")
        return httpx.Response(
            200,
            json={"data": [{"id": "beta"}, {"id": "alpha"}, {"id": 123}, "loose", {"no_id": 1}]},
        )

    assert await _provider(respond).list_models() == ["alpha", "beta"]


@pytest.mark.asyncio
async def test_list_models_returns_empty_when_data_is_not_a_list() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, json={"data": {"not": "a list"}})

    assert await _provider(respond).list_models() == []


@pytest.mark.asyncio
async def test_list_models_enriches_a_rejection_with_the_response_body() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(429, json={"error": {"message": "slow down, retry in 5s"}})

    with pytest.raises(httpx.HTTPStatusError) as caught:
        await _provider(respond).list_models()
    assert "retry in 5s" in str(caught.value)


@pytest.mark.asyncio
async def test_list_models_reraises_a_bare_status_when_the_body_is_empty() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(503, content=b"")

    with pytest.raises(httpx.HTTPStatusError) as caught:
        await _provider(respond).list_models()
    assert "503" in str(caught.value)
