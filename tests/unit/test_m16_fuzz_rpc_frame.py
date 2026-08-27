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


def test_frame_parser_refuses_deeply_nested_json() -> None:
    # A body of ``[[[...]]]`` stays far under MAX_FRAME_BYTES yet exhausts
    # CPython's recursion limit inside json.loads. The parser must surface the
    # same structured rpc_protocol_error it gives any other malformed frame,
    # not leak a raw RecursionError.
    depth = 100_000
    body = (("[" * depth) + ("]" * depth)).encode("utf-8")
    assert len(body) < MAX_FRAME_BYTES
    frame = len(body).to_bytes(4, "little") + body
    with pytest.raises(XdbgRpcError) as caught:
        parse_rpc_frame(frame)
    assert caught.value.code == "rpc_protocol_error"


def test_json_roundtrip_via_stdlib() -> None:
    raw = json.dumps({"ok": True, "protocol": "headless-re-xdbg", "version": 1, "id": "9"})
    frame = len(raw.encode()).to_bytes(4, "little") + raw.encode()
    parsed = parse_rpc_frame(frame)
    validate_rpc_envelope(parsed, request_id="9")


_VALID_ENVELOPE: dict[str, object] = {
    "protocol": "headless-re-xdbg",
    "version": 1,
    "id": "1",
    "ok": True,
}


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"protocol": "someone-elses-tool"}, "RPC protocol mismatch"),
        ({"protocol": None}, "RPC protocol mismatch"),
        ({"version": 2}, "RPC version mismatch"),
        ({"version": None}, "RPC version mismatch"),
        ({"id": "a-stale-id"}, "RPC id mismatch"),
        ({"ok": None}, "RPC ok must be boolean"),
        ({"ok": 1}, "RPC ok must be boolean"),
        ({"ok": "true"}, "RPC ok must be boolean"),
    ],
)
def test_validate_rpc_envelope_rejects_a_mismatched_field(
    mutation: dict[str, object],
    message: str,
) -> None:
    """Each envelope field the peer controls has its own guard.

    parse_rpc_frame proves the bytes are a JSON object; this validator is the
    next line -- it confirms the object came from our x64dbg plugin, at the
    version we speak, answering the request we sent. A field the peer got wrong
    (a foreign protocol tag, an unspoken version, a stale id, or an ``ok`` that
    is not a real boolean) must raise rpc_protocol_error rather than pass as a
    valid reply. ``ok: 1`` is rejected on purpose: bool is an int subclass, and
    a truthy int is not the boolean the contract requires.
    """
    response = {**_VALID_ENVELOPE, **mutation}
    with pytest.raises(XdbgRpcError) as caught:
        validate_rpc_envelope(response, request_id="1")
    assert caught.value.code == "rpc_protocol_error"
    assert str(caught.value) == message


def test_validate_rpc_envelope_only_checks_id_when_one_was_requested() -> None:
    """The id guard is conditional: no request id, no id comparison.

    A caller that sent no id must not have a reply rejected just because the
    peer echoed one; the id check fires only when request_id is provided, so a
    differing id is tolerated here while every other field still validates.
    """
    response = {**_VALID_ENVELOPE, "id": "a-different-id"}
    validate_rpc_envelope(response, request_id=None)
