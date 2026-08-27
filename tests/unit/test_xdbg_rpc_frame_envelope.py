"""Envelope validation for the x64dbg length-prefixed RPC frames.

test_m16_fuzz_rpc_frame.py fuzzes encode/parse; the four ``validate_rpc_envelope``
rejections (protocol, version, id and ``ok`` type) had no direct assertion.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.backends.x64dbg.rpc_frame import validate_rpc_envelope


def _envelope(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "protocol": "headless-re-xdbg",
        "version": 1,
        "id": "req-1",
        "ok": True,
    }
    base.update(overrides)
    return base


def test_a_matching_envelope_is_accepted() -> None:
    validate_rpc_envelope(_envelope(), request_id="req-1")


def test_a_wrong_protocol_is_rejected() -> None:
    with pytest.raises(XdbgRpcError) as caught:
        validate_rpc_envelope(_envelope(protocol="other"))
    assert caught.value.code == "rpc_protocol_error"
    assert "protocol mismatch" in str(caught.value)


def test_a_wrong_version_is_rejected() -> None:
    with pytest.raises(XdbgRpcError) as caught:
        validate_rpc_envelope(_envelope(version=2))
    assert "version mismatch" in str(caught.value)


def test_a_mismatched_id_is_rejected() -> None:
    with pytest.raises(XdbgRpcError) as caught:
        validate_rpc_envelope(_envelope(id="other"), request_id="req-1")
    assert "id mismatch" in str(caught.value)


def test_a_missing_id_check_is_skipped_when_no_request_id_is_given() -> None:
    validate_rpc_envelope(_envelope(id="whatever"))  # request_id=None -> no id check


def test_a_non_boolean_ok_is_rejected() -> None:
    with pytest.raises(XdbgRpcError) as caught:
        validate_rpc_envelope(_envelope(ok="yes"))
    assert "ok must be boolean" in str(caught.value)
