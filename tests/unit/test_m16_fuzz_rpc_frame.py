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


def test_frame_parser_rejects_deeply_nested_json_as_protocol_error() -> None:
    """A valid-JSON frame nested past the decoder's C recursion limit.

    The size cap is 8 MiB, so ~100k open brackets (200 KB) sail under it while
    the C json decoder -- which tops out around ten times the interpreter's
    recursion limit -- raises RecursionError, not JSONDecodeError. The old
    ``except (UnicodeDecodeError, json.JSONDecodeError)`` let that escape, so a
    documented fuzz target broke its one contract (raise only XdbgRpcError) and
    a hostile frame became an internal incident instead of a clean protocol
    error. The debuggee is live malware on the same host, and a session-scoped
    named pipe is reachable, so the frame is genuinely untrusted.
    """
    depth = 100_000
    body = (b"[" * depth) + (b"]" * depth)
    frame = len(body).to_bytes(4, "little") + body
    assert len(frame) <= MAX_FRAME_BYTES
    with pytest.raises(XdbgRpcError) as excinfo:
        parse_rpc_frame(frame)
    assert excinfo.value.code == "rpc_protocol_error"


def test_encode_rejects_oversized() -> None:
    huge = {"protocol": "headless-re-xdbg", "data": "y" * (MAX_FRAME_BYTES + 1)}
    with pytest.raises(XdbgRpcError):
        encode_rpc_frame(huge)


def test_json_roundtrip_via_stdlib() -> None:
    raw = json.dumps({"ok": True, "protocol": "headless-re-xdbg", "version": 1, "id": "9"})
    frame = len(raw.encode()).to_bytes(4, "little") + raw.encode()
    parsed = parse_rpc_frame(frame)
    validate_rpc_envelope(parsed, request_id="9")
