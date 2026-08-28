"""No frida method touches a process outside the session's authorized pids.

Frida is the most powerful non-PE capability: it attaches to a live process and
runs instrumentation inside it. The whole safety model rests on one invariant --
every entry point that touches a process first checks the caller-supplied pid
against what the session is allowed to touch (``_require`` for the local single
pid, ``_authorize`` for the device pid set) and refuses with
``permission_denied`` otherwise. A method that attaches before that check, or a
new method added without it, is a privilege escalation: an agent could read the
memory of, or inject a hook into, a process that is not its debuggee.

Each method enforces this itself, but nothing pinned that they all do, or that a
newly added process-touching method joins the contract -- the same family-level
blind spot the timeout-clamp audit found in Ghidra, except here the stake is
security, not a wedged worker. This test is self-auditing: it discovers every
public method that declares an ``allowed_pid``/``allowed_pids`` parameter and
fails if the tested set does not cover it exactly, so a new gated method cannot
be added without landing here too. Then it drives each one with a pid outside
the authorized set and asserts it refuses with ``permission_denied`` before any
attach.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError

# name -> a call that supplies a pid (1) the session is NOT allowed to touch,
# with allowed_pid(s) naming a different pid (2). Every process-touching method
# must refuse before it reaches _attach_local / device.attach.
_DENIED_CALLS: dict[str, Callable[[FridaClient], Any]] = {
    "attach": lambda c: c.attach(1, allowed_pid=2),
    "modules": lambda c: c.modules(1, allowed_pid=2),
    "exports": lambda c: c.exports(1, "libc.so", allowed_pid=2),
    "memory_read": lambda c: c.memory_read(1, 0x1000, 16, allowed_pid=2),
    "hook_template": lambda c: c.hook_template(1, "open", allowed_pid=2),
    "java_enumerate": lambda c: c.java_enumerate("local", 1, allowed_pids=[2], mode="classes"),
    "hook_template_device": lambda c: c.hook_template_device(
        "local", 1, "open", allowed_pids=[2]
    ),
}


def _gated_methods() -> set[str]:
    """Every public method that declares an allowed_pid(s) parameter."""
    gated: set[str] = set()
    for name, member in inspect.getmembers(FridaClient, predicate=inspect.isfunction):
        if name.startswith("_"):
            continue
        params = inspect.signature(member).parameters
        if "allowed_pid" in params or "allowed_pids" in params:
            gated.add(name)
    return gated


def _armed_client() -> FridaClient:
    """A client that reports frida present but whose module is an inert stub.

    ``_available`` True and a non-None ``_frida`` make the guards fall through to
    the pid check rather than short-circuiting on capability_unavailable; the
    stub has no ``attach``, so any method that skipped the gate would blow up on
    it -- surfacing as a non-permission_denied failure the test catches.
    """
    client = FridaClient()
    client._available = True
    client._frida = object()
    return client


def test_the_contract_covers_every_method_that_declares_an_allowed_pid_param() -> None:
    """A new gated method must be added to _DENIED_CALLS, or this fails."""
    assert _gated_methods() == set(_DENIED_CALLS)


@pytest.mark.parametrize("name", sorted(_DENIED_CALLS))
def test_a_pid_outside_the_authorized_set_is_refused_before_attach(name: str) -> None:
    client = _armed_client()
    with pytest.raises(FridaError) as caught:
        _DENIED_CALLS[name](client)
    assert caught.value.code == "permission_denied"
