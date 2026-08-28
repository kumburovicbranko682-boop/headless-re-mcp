"""OpenAI-compatible streaming chat-completions provider."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from threading import Lock
from typing import Any

from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.telemetry import record_alert

JsonObject = dict[str, Any]

_MAX_ERROR_BODY_BYTES = 64 * 1024
_MAX_ERROR_DETAIL_CHARS = 500
_MAX_MODELS_BODY_BYTES = 1024 * 1024
_MAX_TOOL_CALL_BUFFER_BYTES = 4 * 1024 * 1024
# A little above the tool-call buffer so a single legal arguments payload
# still fits inside one SSE line after the JSON envelope.
_MAX_SSE_LINE_BYTES = _MAX_TOOL_CALL_BUFFER_BYTES + 64 * 1024
_MAX_TOOL_CALLS = 128
_reported_bad_proxy_env = False
_ssl_context: Any = None
_ssl_lock = Lock()
_HIDDEN_DELTA_KEYS = ("reasoning_content", "reasoning", "thinking")


def _plain_text(value: Any) -> str:
    """Pull visible text out of a chat-completions delta field.

    Providers disagree: a string, a list of parts, or a small object with
    ``text`` / ``content``. Anything else is ignored rather than stringified.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(_plain_text(item) for item in value)
    if isinstance(value, dict):
        for key in ("text", "content", "summary"):
            piece = value.get(key)
            if isinstance(piece, str) and piece:
                return piece
    return ""


def _hidden_texts(delta: dict[str, Any]) -> list[str]:
    """Thinking / reasoning text. Empty first chunks are ignored, like Harness."""
    texts: list[str] = []
    for key in _HIDDEN_DELTA_KEYS:
        piece = _plain_text(delta.get(key))
        if piece:
            texts.append(piece)
    reasoning = delta.get("reasoning")
    if isinstance(reasoning, dict):
        piece = _plain_text(reasoning)
        if piece:
            texts.append(piece)
    extra = delta.get("extra_content")
    if not isinstance(extra, dict):
        extra = delta.get("extra") if isinstance(delta.get("extra"), dict) else None
    if isinstance(extra, dict):
        google = extra.get("google")
        if isinstance(google, dict):
            piece = _plain_text(google.get("thought") or google.get("thoughts"))
            if piece:
                texts.append(piece)
    return texts


def _tool_argument_fragment(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return ""


def _usage_output_tokens(usage: Any) -> int | None:
    """Map OpenAI/DeepSeek usage to output tokens (Harness ``outputTokens``)."""
    if not isinstance(usage, dict):
        return None
    for key in ("completion_tokens", "output_tokens", "completionTokens", "outputTokens"):
        value = usage.get(key)
        if isinstance(value, int) and value >= 0:
            return value
        if isinstance(value, float) and value >= 0:
            return int(value)
    details = usage.get("completion_tokens_details")
    if isinstance(details, dict):
        reasoning = details.get("reasoning_tokens")
        accepted = details.get("accepted_prediction_tokens")
        total = 0
        found = False
        for item in (reasoning, accepted, details.get("text_tokens")):
            if isinstance(item, int) and item >= 0:
                total += item
                found = True
        if found:
            return total
    return None


def _normalize_chunk(chunk: Any) -> dict[str, Any]:
    if not isinstance(chunk, dict):
        return {}
    output = chunk.get("output")
    if isinstance(output, dict) and isinstance(output.get("choices"), list):
        merged = dict(chunk)
        merged["choices"] = output["choices"]
        if merged.get("usage") is None and output.get("usage") is not None:
            merged["usage"] = output["usage"]
        return merged
    return chunk


def _sse_payload(line: str) -> str | None:
    stripped = line.strip()
    if stripped.startswith("data:"):
        data = stripped[5:].strip()
        return data or None
    if stripped.startswith("{"):
        return stripped
    return None


def _ingest_tool_calls(
    calls: Any,
    tool_fragments: dict[int, dict[str, str]],
    tool_buffer_bytes: int,
) -> tuple[int, list[str]]:
    """Accumulate streamed or snapshot tool calls. Returns (bytes, output pieces)."""
    if not isinstance(calls, list):
        return tool_buffer_bytes, []
    pieces: list[str] = []
    for raw_call in calls:
        if not isinstance(raw_call, dict):
            continue
        index = int(raw_call.get("index", 0))
        if index not in tool_fragments and len(tool_fragments) >= _MAX_TOOL_CALLS:
            raise ValueError(
                "provider tool-call count exceeded "
                f"{_MAX_TOOL_CALLS} while assembling index {index}"
            )
        item = tool_fragments.setdefault(index, {"id": "", "name": "", "arguments": ""})
        call_id = raw_call.get("id")
        if isinstance(call_id, str) and call_id:
            tool_buffer_bytes += len(call_id.encode("utf-8"))
            if tool_buffer_bytes > _MAX_TOOL_CALL_BUFFER_BYTES:
                raise ValueError(
                    "provider tool-call buffer exceeded "
                    f"{_MAX_TOOL_CALL_BUFFER_BYTES} bytes while assembling index {index}"
                )
            if call_id not in item["id"]:
                item["id"] += call_id
        function_value = raw_call.get("function")
        function: dict[str, Any] = function_value if isinstance(function_value, dict) else {}
        function_name = function.get("name")
        if isinstance(function_name, str) and function_name:
            tool_buffer_bytes += len(function_name.encode("utf-8"))
            if tool_buffer_bytes > _MAX_TOOL_CALL_BUFFER_BYTES:
                raise ValueError(
                    "provider tool-call buffer exceeded "
                    f"{_MAX_TOOL_CALL_BUFFER_BYTES} bytes while assembling index {index}"
                )
            if function_name not in item["name"]:
                item["name"] += function_name
                pieces.append(function_name)
        fragment = _tool_argument_fragment(function.get("arguments"))
        if fragment:
            tool_buffer_bytes += len(fragment.encode("utf-8"))
            if tool_buffer_bytes > _MAX_TOOL_CALL_BUFFER_BYTES:
                raise ValueError(
                    "provider tool-call buffer exceeded "
                    f"{_MAX_TOOL_CALL_BUFFER_BYTES} bytes while assembling index {index}"
                )
            item["arguments"] += fragment
            pieces.append(fragment)
    return tool_buffer_bytes, pieces


async def _aiter_bounded_sse_lines(
    response: Any, *, max_line_bytes: int | None = None
) -> AsyncIterator[str]:
    """Yield SSE lines, refusing one that grows past ``max_line_bytes``.

    ``aiter_lines()`` has no ceiling. A provider that never sends a newline --
    or sends one enormous ``data:`` frame -- is then the whole body, held for
    the rest of the 600-second response window. Measured here: eight 256-byte
    chunks with no newline were all consumed (2,048 bytes) and the stream
    answered completed, because the junk line did not start with ``data:`` and
    was skipped. A 64 KiB no-newline body was likewise retained in full.
    """
    limit = _MAX_SSE_LINE_BYTES if max_line_bytes is None else max_line_bytes
    buf = bytearray()
    async for chunk in response.aiter_bytes():
        start = 0
        while start < len(chunk):
            newline = chunk.find(b"\n", start)
            if newline < 0:
                piece = chunk[start:]
                if len(buf) + len(piece) > limit:
                    raise ValueError(f"provider SSE line exceeded {limit} bytes")
                buf.extend(piece)
                break
            piece = chunk[start:newline]
            if len(buf) + len(piece) > limit:
                raise ValueError(f"provider SSE line exceeded {limit} bytes")
            line = bytes(buf) + piece
            buf.clear()
            if line.endswith(b"\r"):
                line = line[:-1]
            yield line.decode("utf-8", "replace")
            start = newline + 1
    if buf:
        if len(buf) > limit:
            raise ValueError(f"provider SSE line exceeded {limit} bytes")
        line = bytes(buf)
        if line.endswith(b"\r"):
            line = line[:-1]
        yield line.decode("utf-8", "replace")


async def _read_bounded_error_detail(response: Any) -> str:
    """Read enough of a rejected response to diagnose it, never the whole body."""
    body = bytearray()
    truncated = False
    async for chunk in response.aiter_bytes():
        allowance = _MAX_ERROR_BODY_BYTES + 1 - len(body)
        if allowance <= 0:
            truncated = True
            break
        body.extend(chunk[:allowance])
        if len(chunk) > allowance or len(body) > _MAX_ERROR_BODY_BYTES:
            truncated = True
            break

    detail = bytes(body[:_MAX_ERROR_BODY_BYTES]).decode("utf-8", "replace").strip()
    if not truncated:
        return detail[:_MAX_ERROR_DETAIL_CHARS]
    marker = f"...[provider error body truncated at {_MAX_ERROR_BODY_BYTES} bytes]"
    kept = max(0, _MAX_ERROR_DETAIL_CHARS - len(marker))
    return f"{detail[:kept]}{marker}"


def shared_ssl_context(httpx: Any) -> Any:
    """One verifying SSL context for every provider client.

    httpx builds its own per client and loads the CA bundle each time, which
    measured 352ms here against 20ms when the context is reused. That cost is
    paid synchronously, on the event loop the web server shares, once for every
    LLM round -- so a run with a dozen tool rounds froze the console and the
    health endpoint for four seconds spread over it.

    Built the way httpx builds its own, so verification is unchanged: the first
    caller still pays for it once, and nobody pays again.
    """
    global _ssl_context
    with _ssl_lock:
        if _ssl_context is None:
            _ssl_context = httpx.create_ssl_context()
        return _ssl_context


def build_client(httpx: Any, **options: Any) -> Any:
    """Build a client, tolerating a proxy environment httpx cannot parse.

    httpx reads no_proxy while the client is constructed, and an entry of
    ``::1/128`` -- ordinary, and part of the default no_proxy on many machines
    -- raises ``InvalidURL: Invalid port: ':1'``. Every run then failed before
    it reached the network, with a message naming neither the variable nor a
    proxy, so an unattended deployment spent its whole mission budget on it.

    Only when no transport is supplied, which is every real call and no test:
    httpx skips environment proxies entirely when one is passed.

    Ignoring the environment is the lesser loss. A proxy that really was
    required then fails as a connection error, which at least points at the
    network, and the alert says which variable to look at.
    """
    global _reported_bad_proxy_env
    if options.get("transport") is None and "verify" not in options:
        options["verify"] = shared_ssl_context(httpx)
    try:
        return httpx.AsyncClient(**options)
    except httpx.InvalidURL as exc:
        if not _reported_bad_proxy_env:
            _reported_bad_proxy_env = True
            record_alert(
                "proxy_env_unparseable",
                fields={
                    "error": f"{type(exc).__name__}: {exc}",
                    "detail": "ignoring http_proxy/https_proxy/no_proxy for provider calls",
                },
            )
        return httpx.AsyncClient(trust_env=False, **options)


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
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        # Only advertise tools when there are some. The wrap-up round runs with
        # none on purpose, and OpenAI's own API rejects "tools": [] with a 400
        # ("Invalid 'tools': empty array") -- so sending the empty array turned
        # the final summarizing round of any run that spent its tool budget into
        # a failed run instead of the summary it exists to produce. Omitting the
        # key is the compatible way to say the model may not call a tool.
        tool_list = list(tools)
        if tool_list:
            payload["tools"] = tool_list
        if enable_thinking:
            payload["thinking"] = {"type": "enabled"}
            payload["enable_thinking"] = True
        if reasoning_effort:
            payload["reasoning_effort"] = reasoning_effort
        url = f"{self.profile.base_url}/chat/completions"
        tool_fragments: dict[int, dict[str, str]] = {}
        tool_buffer_bytes = 0
        finish_reason: str | None = None
        output_tokens: int | None = None
        saw_incremental = False
        timeout = httpx.Timeout(self.timeout, connect=min(self.timeout, 30.0))
        async with (
            build_client(
                httpx,
                timeout=timeout,
                follow_redirects=False,
                transport=self.transport,
            ) as client,
            client.stream("POST", url, headers=self._headers(), json=payload) as response,
        ):
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                # The body is where a provider says which limit was hit and for
                # how long. Streaming means it is unread, so the exception says
                # only "429" -- and in an unattended deployment that record is
                # all anyone gets. Re-raised as the same type so the retry
                # classifier still reads the status code off it.
                detail = await _read_bounded_error_detail(response)
                if not detail:
                    raise
                raise httpx.HTTPStatusError(
                    f"{exc}: {detail}",
                    request=exc.request,
                    response=exc.response,
                ) from exc
            async for line in _aiter_bounded_sse_lines(response):
                data = _sse_payload(line)
                if data is None:
                    continue
                if data == "[DONE]":
                    break
                try:
                    chunk = _normalize_chunk(json.loads(data))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"provider emitted a stream chunk that is not JSON: {data[:200]}"
                    ) from exc
                usage_tokens = _usage_output_tokens(chunk.get("usage"))
                if usage_tokens is not None:
                    output_tokens = usage_tokens
                    yield ProviderEvent("usage", output_tokens=usage_tokens)
                choices = chunk.get("choices")
                if not isinstance(choices, list) or not choices:
                    continue
                choice_value = choices[0]
                choice: dict[str, Any] = choice_value if isinstance(choice_value, dict) else {}
                finish = choice.get("finish_reason")
                if isinstance(finish, str):
                    finish_reason = finish
                delta_value = choice.get("delta")
                delta: dict[str, Any] = delta_value if isinstance(delta_value, dict) else {}
                message_value = choice.get("message")
                message: dict[str, Any] = (
                    message_value if isinstance(message_value, dict) else {}
                )
                content = _plain_text(delta.get("content"))
                hidden = _hidden_texts(delta)
                calls = delta.get("tool_calls")
                has_delta = bool(content or hidden or calls)
                if not has_delta and not saw_incremental:
                    content = _plain_text(message.get("content"))
                    hidden = _hidden_texts(message)
                    calls = message.get("tool_calls")
                elif not calls and not tool_fragments:
                    message_calls = message.get("tool_calls")
                    if isinstance(message_calls, list) and message_calls:
                        calls = message_calls
                if content:
                    saw_incremental = True
                    yield ProviderEvent("text_delta", text=content)
                for piece in hidden:
                    saw_incremental = True
                    yield ProviderEvent("reasoning_delta", text=piece)
                if calls:
                    saw_incremental = True
                    tool_buffer_bytes, pieces = _ingest_tool_calls(
                        calls, tool_fragments, tool_buffer_bytes
                    )
                    for piece in pieces:
                        yield ProviderEvent("output_delta", text=piece)
        calls_out: list[ProviderToolCall] = []
        for index, item in sorted(tool_fragments.items()):
            try:
                arguments = json.loads(item["arguments"] or "{}")
            except json.JSONDecodeError as exc:
                raise ValueError(f"provider emitted invalid tool arguments at index {index}") from exc
            if not isinstance(arguments, dict) or not item["name"]:
                raise ValueError(f"provider emitted incomplete tool call at index {index}")
            calls_out.append(ProviderToolCall(item["id"] or f"call_{index}", item["name"], arguments))
        yield ProviderEvent(
            "completed",
            tool_calls=tuple(calls_out),
            finish_reason=finish_reason,
            output_tokens=output_tokens,
        )

    async def list_models(self) -> list[str]:
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError("web extra requires httpx") from exc
        async with (
            build_client(
                httpx,
                timeout=min(self.timeout, 30.0),
                follow_redirects=False,
                transport=self.transport,
            ) as client,
            client.stream(
                "GET",
                f"{self.profile.base_url}/models",
                headers=self._headers(),
            ) as response,
        ):
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                # Streaming leaves the body unread, so raise_for_status says
                # only "429 Too Many Requests". probe_models then kept just
                # HTTPStatusError. Measured: a 429 whose body said
                # "quota exceeded retry after 30s" produced an exception
                # without those words.
                detail = await _read_bounded_error_detail(response)
                if not detail:
                    raise
                raise httpx.HTTPStatusError(
                    f"{exc}: {detail}",
                    request=exc.request,
                    response=exc.response,
                ) from exc
            body = bytearray()
            async for chunk in response.aiter_bytes():
                allowance = _MAX_MODELS_BODY_BYTES + 1 - len(body)
                body.extend(chunk[:allowance])
                if len(chunk) > allowance or len(body) > _MAX_MODELS_BODY_BYTES:
                    raise ValueError(
                        f"provider models response exceeded {_MAX_MODELS_BODY_BYTES} bytes"
                    )
            payload = json.loads(body)
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            return []
        return sorted({str(item["id"]) for item in data if isinstance(item, dict) and isinstance(item.get("id"), str)})[:1000]
