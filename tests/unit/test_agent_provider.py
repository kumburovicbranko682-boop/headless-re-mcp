from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider


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
