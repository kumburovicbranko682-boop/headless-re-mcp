"""Pure helpers for length-prefixed JSON RPC frames (fuzz target)."""

from __future__ import annotations

import json
from typing import Any

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.backends.x64dbg.limits import MAX_FRAME_BYTES

_MAX_FRAME_BYTES = MAX_FRAME_BYTES
_PROTOCOL = "headless-re-xdbg"
_PROTOCOL_VERSION = 1


def encode_rpc_frame(payload: dict[str, Any]) -> bytes:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not encoded or len(encoded) > _MAX_FRAME_BYTES:
        raise XdbgRpcError("request_too_large", "RPC request exceeds the frame limit")
    return len(encoded).to_bytes(4, "little") + encoded


def parse_rpc_frame(data: bytes) -> dict[str, Any]:
    """Parse ``u32le length || utf-8 JSON object`` and enforce size bounds."""
    if len(data) < 4:
        raise XdbgRpcError("rpc_protocol_error", "RPC frame too short for length prefix")
    size = int.from_bytes(data[:4], "little")
    if size <= 0 or size > _MAX_FRAME_BYTES:
        raise XdbgRpcError("rpc_protocol_error", "RPC response frame length is invalid")
    if len(data) < 4 + size:
        raise XdbgRpcError("rpc_protocol_error", "RPC frame truncated")
    if len(data) > 4 + size:
        raise XdbgRpcError("rpc_protocol_error", "RPC frame has trailing bytes")
    raw = data[4 : 4 + size]
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise XdbgRpcError(
            "rpc_protocol_error", "RPC response is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(response, dict):
        raise XdbgRpcError("rpc_protocol_error", "RPC response must be an object")
    return response


def validate_rpc_envelope(response: dict[str, Any], *, request_id: str | None = None) -> None:
    if response.get("protocol") != _PROTOCOL:
        raise XdbgRpcError("rpc_protocol_error", "RPC protocol mismatch")
    if response.get("version") != _PROTOCOL_VERSION:
        raise XdbgRpcError("rpc_protocol_error", "RPC version mismatch")
    if request_id is not None and response.get("id") != request_id:
        raise XdbgRpcError("rpc_protocol_error", "RPC id mismatch")
    if not isinstance(response.get("ok"), bool):
        raise XdbgRpcError("rpc_protocol_error", "RPC ok must be boolean")
