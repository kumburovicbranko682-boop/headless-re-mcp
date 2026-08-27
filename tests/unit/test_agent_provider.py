from __future__ import annotations

import json
import ssl
from pathlib import Path

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as openai_compatible
from headless_re_mcp.agent.config import ProviderProfile, normalize_base_url
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider
from headless_re_mcp.agent.providers.retrying import is_retryable


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://api.example.com", "https://api.example.com/v1"),
        ("https://api.example.com/", "https://api.example.com/v1"),
        ("https://api.example.com/v1", "https://api.example.com/v1"),
        ("https://api.example.com/v1/", "https://api.example.com/v1"),
        ("https://api.example.com/openai", "https://api.example.com/openai/v1"),
        ("  https://api.example.com/v1  ", "https://api.example.com/v1"),
        ("HTTPS://api.example.com/v1", "https://api.example.com/v1"),
        ("http://127.0.0.1:11434", "http://127.0.0.1:11434/v1"),
    ],
)
def test_normalize_base_url_canonicalizes_the_endpoint(raw: str, expected: str) -> None:
    """The endpoint the api key is sent to must be one canonical shape."""
    assert normalize_base_url(raw) == expected


def test_normalize_base_url_drops_query_and_fragment() -> None:
    """A base url is a prefix, not a request: a stray ?token=... must not ride along.

    urlsplit keeps query and fragment; if they survived into the stored profile
    every request would carry them, and a credential pasted into the query would
    be logged with every call. The rebuilt url must be scheme://netloc/path only.
    """
    assert normalize_base_url("https://api.example.com/v1?token=leak#frag") == (
        "https://api.example.com/v1"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "ftp://api.example.com",
        "file:///etc/passwd",
        "api.example.com/v1",  # no scheme
        "https://",  # scheme but no host
        "://api.example.com",
    ],
)
def test_normalize_base_url_refuses_a_non_absolute_http_endpoint(bad: str) -> None:
    """Anything that is not absolute http(s) is refused rather than guessed at."""
    with pytest.raises(ValueError, match="base URL"):
        normalize_base_url(bad)


def test_provider_profile_normalizes_its_base_url_on_construction() -> None:
    """ProviderProfile stores the canonical form, so callers cannot bypass it."""
    profile = ProviderProfile("default", "https://api.example.com", "m", api_key="k")
    assert profile.base_url == "https://api.example.com/v1"
    with pytest.raises(ValueError, match="base URL"):
        ProviderProfile("default", "ftp://api.example.com", "m", api_key="k")


@pytest.mark.asyncio
async def test_openai_compatible_streams_text_and_fragmented_multiple_calls(
    tmp_path: Path,
) -> None:
    del tmp_path
    observed: dict[str, object] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        observed["url"] = str(request.url)
        observed["authorization"] = request.headers.get("authorization")
        payload = json.loads(request.content)
        observed["payload"] = payload
        chunks = [
            {"choices": [{"delta": {"content": "hello "}}]},
            {"choices": [{"delta": {"content": "world"}}]},
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call-a",
                                    "function": {
                                        "name": "session.get",
                                        "arguments": '{"session_',
                                    },
                                },
                                {
                                    "index": 1,
                                    "id": "call-b",
                                    "function": {
                                        "name": "doctor",
                                        "arguments": "{}",
                                    },
                                },
                            ]
                        }
                    }
                ]
            },
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {"arguments": 'id":"s"}'},
                                }
                            ]
                        },
                        "finish_reason": "tool_calls",
                    }
                ]
            },
        ]
        body = "".join(
            f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n"
            for chunk in chunks
        ) + "data: [DONE]\n\n"
        return httpx.Response(200, text=body)

    profile = ProviderProfile(
        "default",
        "https://provider.example/v1",
        "fake-model",
        api_key="provider-secret",
        enable_thinking=True,
        reasoning_effort="high",
    )
    provider = OpenAICompatibleProvider(
        profile,
        transport=httpx.MockTransport(respond),
    )
    events = [
        event
        async for event in provider.stream_chat(
            messages=[{"role": "user", "content": "inspect"}],
            tools=[],
            model="fake-model",
            enable_thinking=True,
            reasoning_effort="high",
        )
    ]

    assert [event.text for event in events if event.type == "text_delta"] == [
        "hello ",
        "world",
    ]
    completed = events[-1]
    assert completed.finish_reason == "tool_calls"
    assert [(call.id, call.name, call.arguments) for call in completed.tool_calls] == [
        ("call-a", "session.get", {"session_id": "s"}),
        ("call-b", "doctor", {}),
    ]
    assert observed["url"] == "https://provider.example/v1/chat/completions"
    assert observed["authorization"] == "Bearer provider-secret"
    sent = observed["payload"]
    assert isinstance(sent, dict)
    assert sent["thinking"] == {"type": "enabled"}
    assert sent["enable_thinking"] is True
    assert sent["stream_options"] == {"include_usage": True}
    assert sent["reasoning_effort"] == "high"
    hidden = [event.text for event in events if event.type == "output_delta"]
    assert '{"session_' in "".join(str(part) for part in hidden)
    assert "session.get" in hidden


@pytest.mark.asyncio
async def test_reasoning_and_content_parts_count_as_generation(
    tmp_path: Path,
) -> None:
    del tmp_path

    def respond(request: httpx.Request) -> httpx.Response:
        del request
        chunks = [
            {"choices": [{"delta": {"reasoning_content": "think "}}]},
            {"choices": [{"delta": {"content": [{"type": "text", "text": "hi"}]}}]},
            {"choices": [{"delta": {}, "finish_reason": "stop"}]},
        ]
        body = "".join(
            f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks
        ) + "data: [DONE]\n\n"
        return httpx.Response(200, text=body)

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(respond),
    )
    events = [
        event
        async for event in provider.stream_chat(messages=[], tools=[], model="m")
    ]
    assert [event.type for event in events if event.type != "completed"] == [
        "reasoning_delta",
        "text_delta",
    ]
    assert [event.text for event in events if event.type == "reasoning_delta"] == ["think "]
    assert [event.text for event in events if event.type == "text_delta"] == ["hi"]


@pytest.mark.asyncio
async def test_stream_counts_reasoning_usage_and_message_snapshots(
    tmp_path: Path,
) -> None:
    del tmp_path

    def respond(request: httpx.Request) -> httpx.Response:
        del request
        chunks = [
            {"choices": [{"delta": {"reasoning_content": ""}}]},
            {"choices": [{"delta": {"reasoning_content": "plan "}}]},
            {"choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 42}},
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "c1",
                                    "function": {
                                        "name": "static.open",
                                        "arguments": {"session_id": "s"},
                                    },
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ]
            },
        ]
        body = "".join(
            f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks
        ) + "data: [DONE]\n\n"
        return httpx.Response(200, text=body)

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(respond),
    )
    events = [
        event async for event in provider.stream_chat(messages=[], tools=[], model="m")
    ]
    assert [event.text for event in events if event.type == "reasoning_delta"][0] == "plan "
    usage = next(event for event in events if event.type == "usage")
    assert usage.output_tokens == 42
    completed = events[-1]
    assert completed.output_tokens == 42
    assert completed.tool_calls[0].name == "static.open"
    assert completed.tool_calls[0].arguments == {"session_id": "s"}


@pytest.mark.asyncio
async def test_message_snapshot_with_multiple_indexless_tool_calls(
    tmp_path: Path,
) -> None:
    """A non-incremental snapshot carries tool calls with no ``index``.

    The /chat/completions non-streaming shape (which a provider that answers in
    one chunk despite stream:True re-uses) lists tool calls without an ``index``
    on any of them. Defaulting a missing index to 0 collapsed both onto one
    slot: their arguments were concatenated into ``{"a":1}{"b":2}`` -- invalid
    JSON -- and the whole response was rejected as "invalid tool arguments at
    index 0". Each call must land in its own slot, in order.
    """
    del tmp_path

    def respond(request: httpx.Request) -> httpx.Response:
        del request
        chunk = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call-a",
                                "type": "function",
                                "function": {
                                    "name": "session.get",
                                    "arguments": '{"session_id":"s"}',
                                },
                            },
                            {
                                "id": "call-b",
                                "type": "function",
                                "function": {"name": "doctor", "arguments": "{}"},
                            },
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }
        body = f"data: {json.dumps(chunk, separators=(',', ':'))}\n\ndata: [DONE]\n\n"
        return httpx.Response(200, text=body)

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(respond),
    )
    events = [
        event async for event in provider.stream_chat(messages=[], tools=[], model="m")
    ]
    completed = events[-1]
    assert [(call.id, call.name, call.arguments) for call in completed.tool_calls] == [
        ("call-a", "session.get", {"session_id": "s"}),
        ("call-b", "doctor", {}),
    ]


@pytest.mark.asyncio
async def test_json_lines_without_sse_prefix_still_stream(tmp_path: Path) -> None:
    del tmp_path

    def respond(request: httpx.Request) -> httpx.Response:
        del request
        body = (
            json.dumps({"choices": [{"delta": {"content": "hi"}}]})
            + "\n"
            + json.dumps({"choices": [{"delta": {}, "finish_reason": "stop"}]})
            + "\n"
        )
        return httpx.Response(200, text=body)

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(respond),
    )
    events = [
        event async for event in provider.stream_chat(messages=[], tools=[], model="m")
    ]
    assert [event.text for event in events if event.type == "text_delta"] == ["hi"]
    assert events[-1].type == "completed"


@pytest.mark.asyncio
async def test_a_rejected_request_carries_what_the_provider_said(tmp_path: Path) -> None:
    """A 429 without its body is not a diagnosis.

    The body is where a provider says which limit was hit and for how long.
    Streaming leaves it unread, so the failure recorded against the run said
    only "429" -- and nobody is watching an unattended deployment at the moment
    the quota runs out, so that record is the whole account of it.
    """

    def rate_limited(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            json={"error": {"message": "Rate limit reached: 30000 tokens per min, retry in 12s"}},
        )

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(rate_limited),
    )

    with pytest.raises(httpx.HTTPStatusError) as caught:
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass

    message = str(caught.value)
    assert "429" in message
    assert "retry in 12s" in message, "the provider's own explanation must survive"
    assert is_retryable(caught.value), "enriching the message must not break retry classification"


@pytest.mark.asyncio
async def test_a_rejected_request_stops_reading_its_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sliced error message previously came from an unlimited body read.

    Eight 256-byte chunks were all consumed even though only 500 characters
    reached the exception. A 512-byte test limit should need only the third
    chunk to prove truncation, leaving the remaining five unread.
    """
    monkeypatch.setattr(openai_compatible, "_MAX_ERROR_BODY_BYTES", 512, raising=False)

    class CountingStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.chunks_read = 0

        async def __aiter__(self):  # type: ignore[no-untyped-def]
            for _ in range(8):
                self.chunks_read += 1
                yield b"x" * 256

    stream = CountingStream()

    def rejected(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, stream=stream)

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(rejected),
    )

    with pytest.raises(httpx.HTTPStatusError) as caught:
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass

    assert stream.chunks_read == 3
    assert "truncated at 512 bytes" in str(caught.value)


@pytest.mark.asyncio
async def test_a_proxy_setting_httpx_cannot_parse_does_not_end_every_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """no_proxy is read while the client is built, before any request is made.

    An entry of ::1/128 is ordinary -- it is in the default no_proxy on this
    machine and plenty of others -- and httpx 0.28 raises InvalidURL: Invalid
    port: ':1' on it. Every agent run then died before reaching the network,
    with a message naming neither the variable nor a proxy, so an unattended
    deployment spent its whole mission budget on it.

    Built with transport=None, which is what every real call does and what no
    other test here does: httpx skips environment proxies when one is supplied,
    so a MockTransport hides this entirely.
    """
    # Set under both spellings: one key on Windows, two on POSIX.
    broken = "127.0.0.1,localhost,::1,127.0.0.0/8,::1/128"
    monkeypatch.setenv("NO_PROXY", broken)
    monkeypatch.setenv("no_proxy", broken)
    monkeypatch.setattr(openai_compatible, "_reported_bad_proxy_env", False)
    alerts: list[str] = []
    monkeypatch.setattr(
        openai_compatible, "record_alert", lambda kind, **kwargs: alerts.append(kind)
    )

    with pytest.raises(httpx.InvalidURL):
        httpx.AsyncClient(transport=None)  # the environment really is unparseable

    client = openai_compatible.build_client(httpx, timeout=5.0, transport=None)

    assert client.trust_env is False, "the unusable environment must be left out"
    assert alerts == ["proxy_env_unparseable"], "and the operator must be told which"
    await client.aclose()


@pytest.mark.asyncio
async def test_every_client_shares_one_ssl_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """Building the context per client cost 352ms, on the shared event loop.

    A client is built for every LLM round, so a run with a dozen tool rounds
    froze the console and the health endpoint for four seconds spread across
    it. Reusing the context measured 20ms and leaves verification alone.
    """
    monkeypatch.setattr(openai_compatible, "_ssl_context", None)
    seen: list[object] = []
    real = httpx.AsyncClient

    class Spy:
        InvalidURL = httpx.InvalidURL

        @staticmethod
        def AsyncClient(**options: object) -> httpx.AsyncClient:
            seen.append(options.get("verify"))
            return real(**options)  # type: ignore[arg-type]

        @staticmethod
        def create_ssl_context() -> object:
            return httpx.create_ssl_context()

    first = openai_compatible.build_client(Spy, timeout=5.0, transport=None)
    second = openai_compatible.build_client(Spy, timeout=5.0, transport=None)

    assert seen[0] is not None, "a client must still verify certificates"
    assert seen[0] is seen[1], "the context is built once and reused"
    assert seen[0].verify_mode == ssl.CERT_REQUIRED  # type: ignore[union-attr]
    assert seen[0].check_hostname is True  # type: ignore[union-attr]
    await first.aclose()
    await second.aclose()


@pytest.mark.asyncio
async def test_a_usable_proxy_environment_is_still_honoured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fallback is for an environment httpx rejects, not for all of them."""
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")

    client = openai_compatible.build_client(httpx, timeout=5.0, transport=None)

    assert client.trust_env is True, "a proxy the operator configured must still apply"
    await client.aclose()


@pytest.mark.asyncio
async def test_model_listing_stops_reading_an_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 1,000-model output cap did not bound bytes downloaded before parsing.

    A valid 2,068-byte payload arrived in nine 256-byte chunks and was retained
    whole. With a 512-byte test ceiling, the third chunk is enough to reject it.
    """
    monkeypatch.setattr(openai_compatible, "_MAX_MODELS_BODY_BYTES", 512, raising=False)
    payload = json.dumps(
        {"data": [{"id": "m" * 2_048}]},
        separators=(",", ":"),
    ).encode()
    chunks = [payload[offset : offset + 256] for offset in range(0, len(payload), 256)]

    class CountingStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.chunks_read = 0

        async def __aiter__(self):  # type: ignore[no-untyped-def]
            for chunk in chunks:
                self.chunks_read += 1
                yield chunk

    stream = CountingStream()

    def models(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(models),
    )

    with pytest.raises(ValueError, match="models response exceeded 512 bytes"):
        await provider.list_models()

    assert stream.chunks_read == 3


@pytest.mark.asyncio
async def test_a_chunk_that_is_not_json_is_blamed_on_the_provider(tmp_path: Path) -> None:
    """Every field in a chunk is type-checked; the chunk being JSON was assumed."""

    def malformed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="data: {not json at all\n\ndata: [DONE]\n\n")

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(malformed),
    )

    with pytest.raises(ValueError, match="not JSON"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_stream_stops_reading_an_oversized_sse_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """aiter_lines() has no byte ceiling, so a line without a newline is the body.

    Eight 256-byte chunks with no newline were all consumed (2,048 bytes) and
    the stream answered completed -- the junk line did not start with data: so
    it was skipped. A 64 KiB no-newline body was likewise retained in full
    (16/16 chunks, 65,536 bytes) with no error. A 512-byte test limit should
    refuse on the third chunk and leave the rest unread.
    """
    monkeypatch.setattr(openai_compatible, "_MAX_SSE_LINE_BYTES", 512, raising=False)

    class CountingStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.chunks_read = 0

        async def __aiter__(self):  # type: ignore[no-untyped-def]
            for _ in range(8):
                self.chunks_read += 1
                yield b"x" * 256

    stream = CountingStream()

    def endless_line(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(endless_line),
    )

    with pytest.raises(ValueError, match="SSE line exceeded 512 bytes"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass

    assert stream.chunks_read == 3


@pytest.mark.asyncio
async def test_tool_call_stream_is_rejected_before_unbounded_buffering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider-controlled argument stream needs a byte ceiling while assembling.

    With a 1 KiB test ceiling, the previous implementation accepted a 2,059-byte
    arguments value and only handed it to the later orchestrator size check after
    retaining the whole value. The production path therefore retained any amount
    the peer sent during its 600-second response window.
    """
    monkeypatch.setattr(
        openai_compatible,
        "_MAX_TOOL_CALL_BUFFER_BYTES",
        1_024,
        raising=False,
    )
    arguments = json.dumps({"blob": "x" * 2_048}, separators=(",", ":"))

    def oversized_call(request: httpx.Request) -> httpx.Response:
        chunk = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call-a",
                                "function": {
                                    "name": "session.get",
                                    "arguments": arguments,
                                },
                            }
                        ]
                    }
                }
            ]
        }
        body = f"data: {json.dumps(chunk, separators=(',', ':'))}\n\ndata: [DONE]\n\n"
        return httpx.Response(200, text=body)

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(oversized_call),
    )

    with pytest.raises(ValueError, match="tool-call buffer exceeded 1024 bytes"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


@pytest.mark.asyncio
async def test_tool_call_stream_caps_distinct_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Small calls still grew the per-response fragment map without a count bound."""
    monkeypatch.setattr(openai_compatible, "_MAX_TOOL_CALLS", 2, raising=False)

    def too_many_calls(request: httpx.Request) -> httpx.Response:
        calls = [
            {
                "index": index,
                "id": f"call-{index}",
                "function": {"name": "doctor", "arguments": "{}"},
            }
            for index in range(3)
        ]
        chunk = {"choices": [{"delta": {"tool_calls": calls}}]}
        body = f"data: {json.dumps(chunk, separators=(',', ':'))}\n\ndata: [DONE]\n\n"
        return httpx.Response(200, text=body)

    provider = OpenAICompatibleProvider(
        ProviderProfile("default", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(too_many_calls),
    )

    with pytest.raises(ValueError, match="tool-call count exceeded 2"):
        async for _ in provider.stream_chat(messages=[], tools=[], model="m"):
            pass


def test_protecting_provider_config_does_not_hang_when_icacls_is_a_launcher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """subprocess.run timed out then drained with no deadline; the except missed it.

    Measured: TimeoutExpired is not a TimeoutError (its MRO stops at
    SubprocessError), so a 10s icacls deadline raised out of a function named
    best-effort. A launcher that held the pipes did not return at all. Provider
    saves run this on every write.
    """
    import os
    import sys
    import time

    from headless_re_mcp.agent.config import ProviderConfigStore

    if os.name != "nt":
        pytest.skip("icacls protect is Windows-only (skip != pass)")

    stub = tmp_path / "icacls_stub.py"
    stub.write_text(
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        "print(child.pid, flush=True)\n"
        "while True: time.sleep(0.2)\n",
        encoding="utf-8",
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "icacls.cmd").write_text(
        f'@echo off\r\n"{sys.executable}" "{stub}"\r\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))

    target = tmp_path / "providers.json"
    target.write_text("{}", encoding="utf-8")
    started = time.monotonic()
    ProviderConfigStore._best_effort_protect(target, timeout=0.8)
    elapsed = time.monotonic() - started
    assert elapsed < 10.0, f"deadline 0.8s, caller waited {elapsed:.1f}s"


def test_windows_config_acl_uses_username_when_getlogin_has_no_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows services commonly have no login session for os.getlogin()."""
    from headless_re_mcp.agent import config

    calls: list[list[str]] = []

    def no_login() -> str:
        raise OSError("no controlling terminal")

    def capture(command: list[str], **_: object) -> None:
        calls.append(command)

    monkeypatch.setattr(config.os, "name", "nt")
    monkeypatch.setattr(config.os, "getlogin", no_login)
    monkeypatch.setenv("USERNAME", "service-account")
    monkeypatch.setattr(config, "run_bounded", capture)

    config.ProviderConfigStore._best_effort_protect(tmp_path / "providers.json")

    assert calls == [
        ["icacls", str(tmp_path / "providers.json"), "/inheritance:r", "/grant:r", "service-account:F"]
    ]
