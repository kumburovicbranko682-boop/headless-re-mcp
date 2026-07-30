"""OpenAI-compatible streaming chat-completions provider."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from typing import Any

from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall

JsonObject = dict[str, Any]


class OpenAICompatibleProvider:
    def __init__(
        self,
        profile: ProviderProfile,
        *,
        timeout: float = 120.0,
        transport: Any | None = None,
    ) -> None:
        self.profile = profile
        self.timeout = max(1.0, min(timeout, 600.0))
        self.transport = transport

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        if self.profile.api_key:
            headers["Authorization"] = f"Bearer {self.profile.api_key}"
        return headers

    async def stream_chat(
        self,
        *,
        messages: Sequence[JsonObject],
        tools: Sequence[JsonObject],
        model: str,
        enable_thinking: bool = False,
        reasoning_effort: str | None = None,
    ) -> AsyncIterator[ProviderEvent]:
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError("web extra requires httpx") from exc
        payload: JsonObject = {
            "model": model,
            "messages": list(messages),
            "tools": list(tools),
            "stream": True,
            "stream_options": {"include_usage": False},
        }
        if enable_thinking:
            payload["thinking"] = {"type": "enabled"}
        if reasoning_effort:
            payload["reasoning_effort"] = reasoning_effort
        url = f"{self.profile.base_url}/chat/completions"
        tool_fragments: dict[int, dict[str, str]] = {}
        finish_reason: str | None = None
        timeout = httpx.Timeout(self.timeout, connect=min(self.timeout, 30.0))
        async with (
            httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                transport=self.transport,
            ) as client,
            client.stream("POST", url, headers=self._headers(), json=payload) as response,
        ):
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                if not data:
                    continue
                chunk = json.loads(data)
                choices = chunk.get("choices") if isinstance(chunk, dict) else None
                if not isinstance(choices, list) or not choices:
                    continue
                choice_value = choices[0]
                choice: dict[str, Any] = choice_value if isinstance(choice_value, dict) else {}
                finish = choice.get("finish_reason")
                if isinstance(finish, str):
                    finish_reason = finish
                delta_value = choice.get("delta")
                delta: dict[str, Any] = delta_value if isinstance(delta_value, dict) else {}
                content = delta.get("content")
                if isinstance(content, str) and content:
                    yield ProviderEvent("text_delta", text=content)
                calls = delta.get("tool_calls")
                if isinstance(calls, list):
                    for raw_call in calls:
                        if not isinstance(raw_call, dict):
                            continue
                        index = int(raw_call.get("index", 0))
                        item = tool_fragments.setdefault(index, {"id": "", "name": "", "arguments": ""})
                        call_id = raw_call.get("id")
                        if isinstance(call_id, str):
                            item["id"] += call_id
                        function_value = raw_call.get("function")
                        function: dict[str, Any] = (
                            function_value if isinstance(function_value, dict) else {}
                        )
                        function_name = function.get("name")
                        if isinstance(function_name, str):
                            item["name"] += function_name
                        function_arguments = function.get("arguments")
                        if isinstance(function_arguments, str):
                            item["arguments"] += function_arguments
        calls_out: list[ProviderToolCall] = []
        for index, item in sorted(tool_fragments.items()):
            try:
                arguments = json.loads(item["arguments"] or "{}")
            except json.JSONDecodeError as exc:
                raise ValueError(f"provider emitted invalid tool arguments at index {index}") from exc
            if not isinstance(arguments, dict) or not item["name"]:
                raise ValueError(f"provider emitted incomplete tool call at index {index}")
            calls_out.append(ProviderToolCall(item["id"] or f"call_{index}", item["name"], arguments))
        yield ProviderEvent("completed", tool_calls=tuple(calls_out), finish_reason=finish_reason)

    async def list_models(self) -> list[str]:
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError("web extra requires httpx") from exc
        async with httpx.AsyncClient(
            timeout=min(self.timeout, 30.0),
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            response = await client.get(f"{self.profile.base_url}/models", headers=self._headers())
            response.raise_for_status()
            payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            return []
        return sorted({str(item["id"]) for item in data if isinstance(item, dict) and isinstance(item.get("id"), str)})[:1000]
