"""The local frida probes share attach()'s boundary checks via _require.

modules / exports / memory_read / hook_template all gate on _require. That gate
used to check authorization before capability and never validated the pid, so a
malformed pid surfaced as permission_denied (or, once it reached frida.attach, as
an opaque backend_error) instead of the invalid_params that attach() raises for
the same input, and an unavailable runtime was reported as permission_denied when
the pid also mismatched. The frida native runtime cannot run in CI, so these
drive the gate directly with a stub frida object; every case raises before any
attach would happen.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _client(*, available: bool) -> FridaClient:
    client = FridaClient()
    client._available = available
    # A non-None stub so the capability gate passes when available; _require
    # never touches it, and every case below raises before an attach.
    client._frida = object() if available else None
    return client


# The four public methods gated by _require, each called with pid first.
def _gated_calls(client: FridaClient, pid: Any, allowed: int) -> dict[str, Callable[[], Any]]:
    return {
        "modules": lambda: client.modules(pid, allowed_pid=allowed),
        "exports": lambda: client.exports(pid, "libc.so", allowed_pid=allowed),
        "memory_read": lambda: client.memory_read(pid, 0x1000, 16, allowed_pid=allowed),
        "hook_template": lambda: client.hook_template(pid, "noop", allowed_pid=allowed),
    }


@pytest.mark.parametrize("name", ["modules", "exports", "memory_read", "hook_template"])
@pytest.mark.parametrize("bad_pid", [0, -1, "1", 1.0])
def test_gate_rejects_a_malformed_pid_as_invalid_params(name: str, bad_pid: Any) -> None:
    """A non-positive or non-int pid is invalid_params, like attach()."""
    client = _client(available=True)
    call = _gated_calls(client, bad_pid, allowed=1)[name]
    with pytest.raises(FridaError) as caught:
        call()
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("name", ["modules", "exports", "memory_read", "hook_template"])
def test_gate_checks_capability_before_authorization(name: str) -> None:
    """frida missing is capability_unavailable even when the pid also mismatches."""
    client = _client(available=False)
    call = _gated_calls(client, 4321, allowed=1234)[name]
    with pytest.raises(FridaError) as caught:
        call()
    assert caught.value.code == "capability_unavailable"


@pytest.mark.parametrize("name", ["modules", "exports", "memory_read", "hook_template"])
def test_gate_still_denies_an_unauthorized_pid(name: str) -> None:
    """A well-formed pid outside the session's allowed pid is permission_denied."""
    client = _client(available=True)
    call = _gated_calls(client, 4321, allowed=1234)[name]
    with pytest.raises(FridaError) as caught:
        call()
    assert caught.value.code == "permission_denied"
    assert caught.value.details.get("allowed_pid") == 1234
