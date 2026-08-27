"""Deviceless frida gate: authorization and argument checks fire before attach.

The live frida gate (test_m11_frida_live_gate.py) attaches to a real local
process and skips without one, so frida's security-critical contract -- that it
refuses a pid outside the session's authorized set, and validates arguments,
*before* it ever attaches to anything -- was never exercised on a machine
without a target. That contract needs no ptrace and no debuggee: the checks run
ahead of any process access. This gate pins them, plus device enumeration
(frida always exposes a local device). Needs only the frida pip module; skips
honestly (skip != pass) when it is absent.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.core.service import AnalysisService

# A pid the session is not authorized to touch, and one that is authorized only
# so the *argument* checks (which run after the auth check) can be reached.
_UNAUTHORIZED_PID = 99998
_AUTHORIZED_PID = 99999


def _frida_available() -> bool:
    return FridaClient().available


@pytest.mark.integration
def test_frida_refuses_an_unauthorized_pid_before_attaching() -> None:
    """frida must never touch a pid outside the session's allow-set.

    This is the whole reason the surface takes an allowed-pid rather than a raw
    pid: a compromised or confused caller must not be able to point frida at an
    arbitrary process. The check runs before any attach, so it holds with no
    debuggee present -- and permission_denied, never a silent attach.
    """
    if not _frida_available():
        pytest.skip("frida not installed — frida deviceless Gate not run (skip != pass)")
    client = FridaClient()

    def denied(call) -> None:  # noqa: ANN001 - a thunk per operation
        with pytest.raises(FridaError) as info:
            call()
        assert info.value.code == "permission_denied", info.value.code

    denied(lambda: client.attach(_UNAUTHORIZED_PID, allowed_pid=1))
    denied(lambda: client.memory_read(_UNAUTHORIZED_PID, 0x1000, 16, allowed_pid=1))
    denied(lambda: client.modules(_UNAUTHORIZED_PID, allowed_pid=1))
    denied(lambda: client.exports(_UNAUTHORIZED_PID, "libc.so", allowed_pid=1))
    denied(lambda: client.java_enumerate(None, _UNAUTHORIZED_PID, allowed_pids={1}, mode="classes"))
    denied(lambda: client.hook_template_device(None, _UNAUTHORIZED_PID, "noop", allowed_pids={1}))


@pytest.mark.integration
def test_frida_validates_arguments_before_attaching() -> None:
    if not _frida_available():
        pytest.skip("frida not installed — frida deviceless Gate not run (skip != pass)")
    client = FridaClient()

    def invalid(call) -> None:  # noqa: ANN001
        with pytest.raises(FridaError) as info:
            call()
        assert info.value.code == "invalid_params", info.value.code

    # A non-positive pid is rejected before the authorization comparison.
    invalid(lambda: client.attach(0, allowed_pid=0))
    # size and template are checked after the (passing) auth check but before
    # the attach, so an authorized pid still fails here without touching it.
    invalid(lambda: client.memory_read(_AUTHORIZED_PID, 0x1000, 0, allowed_pid=_AUTHORIZED_PID))
    invalid(lambda: client.hook_template(_AUTHORIZED_PID, "nope", allowed_pid=_AUTHORIZED_PID))
    # spawn resolves the local device, then refuses a value that is not an
    # Android package id before spawning anything.
    invalid(lambda: client.spawn(None, "not a package"))


@pytest.mark.integration
def test_frida_enumerates_the_local_device() -> None:
    if not _frida_available():
        pytest.skip("frida not installed — frida deviceless Gate not run (skip != pass)")
    client = FridaClient()
    enumerated = client.enumerate_devices()
    assert enumerated["count"] >= 1
    kinds = {(d["id"], d["type"]) for d in enumerated["devices"]}
    # frida always exposes a local device; without it the whole surface is dead.
    assert ("local", "local") in kinds, enumerated["devices"]

    # The same through the service surface: an envelope, ok, with the local
    # device present and no error-boundary incident.
    service = AnalysisService()
    try:
        result = service.frida_devices()
        assert result.ok, result.error
        served = {(d["id"], d["type"]) for d in result.data["devices"]}
        assert ("local", "local") in served, result.data["devices"]
    finally:
        service.close_all()
