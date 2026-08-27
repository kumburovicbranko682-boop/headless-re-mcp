from __future__ import annotations

import json

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.backends.x64dbg.limits import MAX_FRAME_BYTES
from headless_re_mcp.backends.x64dbg.rpc_frame import (
    encode_rpc_frame,
    parse_rpc_frame,
    validate_rpc_envelope,
)


def test_roundtrip_frame() -> None:
    payload = {
        "protocol": "headless-re-xdbg",
        "version": 1,
        "id": "1",
        "ok": True,
        "result": {"x": 1},
    }
    frame = encode_rpc_frame(payload)
    parsed = parse_rpc_frame(frame)
    validate_rpc_envelope(parsed, request_id="1")
    assert parsed["result"]["x"] == 1


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"\x00\x00\x00",
        b"\xff\xff\xff\xff" + b"{}",
        b"\x01\x00\x00\x00",
        b"\x02\x00\x00\x00" + b"[]",
        b"\x05\x00\x00\x00" + b'"abc"',
        (10).to_bytes(4, "little") + b"{not-json",
        (2).to_bytes(4, "little") + b"{}" + b"xx",
        # Valid length prefix, valid UTF-8, nested past the recursion limit:
        # json.loads raises RecursionError (a RuntimeError, not a ValueError)
        # while descending, before it can notice the string is unterminated,
        # so this escaped the JSONDecodeError catch as a raw interpreter error.
        pytest.param(
            (20_000).to_bytes(4, "little") + b"[" * 20_000, id="deep-nesting"
        ),
    ],
)
def test_frame_parser_rejects_garbage(blob: bytes) -> None:
    with pytest.raises(XdbgRpcError):
        parse_rpc_frame(blob)


def test_frame_fuzz_random_lengths() -> None:
    # Deterministic pseudo-fuzz: many length prefixes and bodies.
    for size in list(range(0, 40)) + [1024, MAX_FRAME_BYTES, MAX_FRAME_BYTES + 1]:
        prefix = size.to_bytes(4, "little")
        body = b"x" * min(size, 64)
        try:
            parse_rpc_frame(prefix + body)
        except XdbgRpcError:
            pass
        except Exception as exc:  # noqa: BLE001 — fuzz must not raise unexpected types
            raise AssertionError(f"unexpected {type(exc)} for size={size}") from exc


def test_encode_rejects_oversized() -> None:
    huge = {"protocol": "headless-re-xdbg", "data": "y" * (MAX_FRAME_BYTES + 1)}
    with pytest.raises(XdbgRpcError):
        encode_rpc_frame(huge)


def test_json_roundtrip_via_stdlib() -> None:
    raw = json.dumps({"ok": True, "protocol": "headless-re-xdbg", "version": 1, "id": "9"})
    frame = len(raw.encode()).to_bytes(4, "little") + raw.encode()
    parsed = parse_rpc_frame(frame)
    validate_rpc_envelope(parsed, request_id="9")
