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


def test_encode_rejects_oversized() -> None:
    huge = {"protocol": "headless-re-xdbg", "data": "y" * (MAX_FRAME_BYTES + 1)}
    with pytest.raises(XdbgRpcError):
        encode_rpc_frame(huge)


def test_json_roundtrip_via_stdlib() -> None:
    raw = json.dumps({"ok": True, "protocol": "headless-re-xdbg", "version": 1, "id": "9"})
    frame = len(raw.encode()).to_bytes(4, "little") + raw.encode()
    parsed = parse_rpc_frame(frame)
    validate_rpc_envelope(parsed, request_id="9")


# Each entry is a single-field mutation of an otherwise valid envelope, so a
# helper that stopped rejecting one of them would fail its own row rather than
# hide behind the others.
_MALFORMED_ENVELOPES: list[tuple[str, dict[str, object], str]] = [
    (
        "protocol mismatch",
        {"protocol": "not-ours", "version": 1, "id": "1", "ok": True},
        "RPC protocol mismatch",
    ),
    (
        "version mismatch",
        {"protocol": "headless-re-xdbg", "version": 2, "id": "1", "ok": True},
        "RPC version mismatch",
    ),
    (
        "id mismatch",
        {"protocol": "headless-re-xdbg", "version": 1, "id": "2", "ok": True},
        "RPC id mismatch",
    ),
    (
        "non-boolean ok",
        {"protocol": "headless-re-xdbg", "version": 1, "id": "1", "ok": "yes"},
        "RPC ok must be boolean",
    ),
]


@pytest.mark.parametrize(
    ("label", "envelope", "message"),
    _MALFORMED_ENVELOPES,
    ids=[label for label, _, _ in _MALFORMED_ENVELOPES],
)
def test_validate_rpc_envelope_rejects_each_malformed_field(
    label: str,
    envelope: dict[str, object],
    message: str,
) -> None:
    # A hostile or buggy worker can answer with any one field wrong; the
    # envelope guard must name which field, not collapse them into one message.
    with pytest.raises(XdbgRpcError, match=message) as exc_info:
        validate_rpc_envelope(envelope, request_id="1")
    assert exc_info.value.code == "rpc_protocol_error"


def test_validate_rpc_envelope_skips_the_id_check_without_a_request_id() -> None:
    # A caller that does not track ids passes request_id=None; the id field must
    # then be ignored while the rest of the envelope is still enforced.
    envelope = {"protocol": "headless-re-xdbg", "version": 1, "id": "whatever", "ok": False}
    validate_rpc_envelope(envelope)


def test_validate_rpc_envelope_accepts_a_false_ok() -> None:
    # ok=False is a well-formed envelope carrying an error; only a non-boolean ok
    # is a protocol violation, so this must pass the guard.
    envelope = {"protocol": "headless-re-xdbg", "version": 1, "id": "1", "ok": False}
    validate_rpc_envelope(envelope, request_id="1")
