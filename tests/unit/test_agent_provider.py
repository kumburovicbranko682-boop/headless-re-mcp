from __future__ import annotations

import json
import ssl
from pathlib import Path

import httpx
import pytest

import headless_re_mcp.agent.providers.openai_compatible as openai_compatible
from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider
from headless_re_mcp.agent.providers.retrying import is_retryable


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
    assert sent["reasoning_effort"] == "high"


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
