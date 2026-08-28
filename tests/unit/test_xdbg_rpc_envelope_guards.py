"""Pin the fail-closed arms of the x64dbg RPC envelope validator.

``test_m16_fuzz_rpc_frame.py`` fuzzes the frame parser and exercises the
accepting path of ``validate_rpc_envelope``, but none of its four rejection
arms: a frame from the wrong protocol, the wrong protocol version, a reply
whose id does not match the request, and an ``ok`` field that is truthy but
not a boolean. Each is the last check between bytes off a pipe and code that
trusts the reply, so each must refuse with a structured
``rpc_protocol_error`` rather than let a mismatched or forged envelope
through. Also pins the gate result serializer, which the Windows-only gate
tests leave unexercised on Linux.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.backends.x64dbg.gate import XdbgHeadlessGateResult
from headless_re_mcp.backends.x64dbg.rpc_frame import validate_rpc_envelope
from headless_re_mcp.core.models import Architecture


def _envelope(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "protocol": "headless-re-xdbg",
        "version": 1,
        "id": "req-1",
        "ok": True,
    }
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    ("overrides", "complaint"),
    [
        ({"protocol": "someone-elses-protocol"}, "protocol mismatch"),
        ({"protocol": None}, "protocol mismatch"),
        ({"version": 2}, "version mismatch"),
        ({"version": "1"}, "version mismatch"),
        ({"id": "req-2"}, "id mismatch"),
        ({"ok": 1}, "ok must be boolean"),
        ({"ok": "true"}, "ok must be boolean"),
        ({"ok": None}, "ok must be boolean"),
    ],
)
def test_envelope_validator_refuses_a_mismatched_reply(
    overrides: dict[str, Any], complaint: str
) -> None:
    with pytest.raises(XdbgRpcError, match=complaint) as excinfo:
        validate_rpc_envelope(_envelope(**overrides), request_id="req-1")
    assert excinfo.value.code == "rpc_protocol_error"


def test_id_check_is_skipped_when_no_request_id_is_supplied() -> None:
    # Callers that fire-and-match elsewhere pass request_id=None; the envelope
    # is still held to protocol, version, and ok shape.
    validate_rpc_envelope(_envelope(id="anything"))


def test_gate_result_serializes_every_field() -> None:
    result = XdbgHeadlessGateResult(
        ok=False,
        architecture=Architecture.X64,
        executable="C:/x64dbg/headless.exe",
        exit_code=3,
        stdout="[headless] entering command loop\n",
        stderr="warning: stub\n",
        analyzer_windows=("Analyzer - main", "Analyzer - popup"),
        command_loop_seen=True,
    )

    assert result.to_dict() == {
        "ok": False,
        "architecture": "x64",
        "executable": "C:/x64dbg/headless.exe",
        "exit_code": 3,
        "stdout": "[headless] entering command loop\n",
        "stderr": "warning: stub\n",
        "analyzer_windows": ["Analyzer - main", "Analyzer - popup"],
        "command_loop_seen": True,
    }
