"""Turn stdio lines the SDK cannot parse into JSON-RPC errors the caller can read."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

import anyio
from mcp.types import (
    INVALID_REQUEST,
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
)

# pydantic's JSON parser gives up around 200 levels, well before json.loads.
# The SDK then puts the ValidationError on the read stream; the server logs
# "Internal Server Error" and never replies with the request id. Measured:
# a tools/call nested 200 deep produced no JSON-RPC response at all.
_RECURSION_MARKERS = ("recursion limit exceeded", "recursion")
_MAX_STDIO_MESSAGE_BYTES = 8 * 1024 * 1024


async def _read_bounded_line(
    stream: Any,
    *,
    limit: int = _MAX_STDIO_MESSAGE_BYTES,
) -> tuple[bytes, bool]:
    """Read one binary NDJSON record and drain any oversized remainder."""
    cap = max(1, int(limit))
    line = await anyio.to_thread.run_sync(stream.readline, cap + 1)
    if not line:
        return b"", False
    if len(line) <= cap:
        return line, False

    prefix = line
    while line and not line.endswith(b"\n"):
        line = await anyio.to_thread.run_sync(stream.readline, cap + 1)
    return prefix, True


def error_message_for_unreadable_line(line: str) -> JSONRPCMessage | None:
    """A JSON-RPC error named after the request, or None if there is no id to answer.

    Without an id the caller cannot correlate a reply, so we stay silent the
    way a parse of complete garbage already did. A tools/call that merely
    nested too far still has an id, and that is the unattended case.
    """
    try:
        JSONRPCMessage.model_validate_json(line)
    except Exception as exc:
        return _error_for_parse_failure(line, exc)
    return None


def _request_id(line: str) -> str | int | None:
    try:
        parsed: Any = json.loads(line)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return None
    if not isinstance(parsed, dict) or "id" not in parsed:
        return None
    value = parsed["id"]
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    return value


@asynccontextmanager
async def stdio_server_with_parse_replies() -> Any:
    """SDK stdio, except an unreadable request with an id gets an error reply.

    The SDK reader forwards the parse exception inward; the server logs
    Internal Server Error and never writes a JSON-RPC response. Answering on
    the write stream is what lets an unattended caller see the refusal.
    """
    import sys
    from io import TextIOWrapper

    import anyio.lowlevel
    from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
    from mcp.shared.message import SessionMessage
    from mcp.types import JSONRPCMessage as RpcMessage

    stdin = sys.stdin.buffer
    stdout = anyio.wrap_file(TextIOWrapper(sys.stdout.buffer, encoding="utf-8"))
    read_stream_writer: MemoryObjectSendStream[SessionMessage]
    read_stream: MemoryObjectReceiveStream[SessionMessage]
    write_stream: MemoryObjectSendStream[SessionMessage]
    write_stream_reader: MemoryObjectReceiveStream[SessionMessage]
    read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_stream_reader = anyio.create_memory_object_stream(0)
    error_writer = write_stream.clone()

    async def stdin_reader() -> None:
        try:
            async with read_stream_writer, error_writer:
                while True:
                    encoded, oversized = await _read_bounded_line(stdin)
                    if not encoded:
                        break
                    line = encoded.decode("utf-8", errors="replace")
                    if oversized:
                        exc = ValueError(
                            f"request exceeds {_MAX_STDIO_MESSAGE_BYTES} bytes"
                        )
                        reply = _error_for_parse_failure(line, exc)
                        if reply is not None:
                            await error_writer.send(SessionMessage(reply))
                        continue
                    try:
                        message = RpcMessage.model_validate_json(line)
                    except Exception as exc:
                        reply = _error_for_parse_failure(line, exc)
                        if reply is not None:
                            await error_writer.send(SessionMessage(reply))
                        continue
                    await read_stream_writer.send(SessionMessage(message))
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()

    async def stdout_writer() -> None:
        try:
            async with write_stream_reader:
                async for session_message in write_stream_reader:
                    payload = session_message.message.model_dump_json(
                        by_alias=True, exclude_none=True
                    )
                    await stdout.write(payload + "\n")
                    await stdout.flush()
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()

    async with anyio.create_task_group() as tg:
        tg.start_soon(stdin_reader)
        tg.start_soon(stdout_writer)
        yield read_stream, write_stream


def _error_for_parse_failure(line: str, exc: BaseException) -> JSONRPCMessage | None:
    request_id = _request_id(line)
    if request_id is None:
        return None
    text = str(exc)
    if any(marker in text.casefold() for marker in _RECURSION_MARKERS):
        text = "request is nested too deeply to parse"
    else:
        text = text.splitlines()[0][:2048]
    return JSONRPCMessage(
        JSONRPCError(
            jsonrpc="2.0",
            id=request_id,
            error=ErrorData(code=INVALID_REQUEST, message=text),
        )
    )