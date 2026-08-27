"""The frida pid gate must refuse before it resolves a device or attaches.

frida is the one non-PE backend that reaches into a live process, so its only
safety boundary is the per-session pid allow-set: ``attach`` / ``modules`` /
``exports`` / ``memory_read`` / ``hook_template`` take a single ``allowed_pid``,
and the device-aware ``java_enumerate`` / ``hook_template_device`` take an
``allowed_pids`` set. Every entry point checks that gate first -- ``_require`` /
the inline ``attach`` check / ``_authorize`` -- and only then resolves a device
or attaches. That ordering is the whole control: an unauthorized pid must be
turned away *before* any side effect, or a caller could make the backend open a
USB/remote device (or attach to a process it was never granted) simply by naming
a pid it does not own and reading the error.

The existing authorization tests in ``test_android_backends.py`` use a real
``FridaClient`` and ``skip`` when frida is not installed, so on a frida-less CI
the most security-sensitive contract in this backend is unverified (skip !=
pass). They also assert only the ``permission_denied`` code, not the ordering:
if a refactor moved ``_resolve_device`` above the gate, an unauthorized call
would still end in an error -- just a ``not_found`` from a failed device lookup,
after the device was already touched -- and a code-only assertion could still
pass on a machine with a device attached.

These tests close both gaps. They drive the gate with a *fake* frida
(``_available=True``, ``_frida=object()``) so they run everywhere without the
android extra, cover every authorization entry point, and install spies on
``_resolve_device`` and ``_attach_local`` (plus ``_frida.attach``) that fail the
test if either runs. The contract they pin: an unauthorized pid raises
``permission_denied`` and nothing is resolved or attached on the way out.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _client_with_tripwires() -> tuple[FridaClient, dict[str, int]]:
    """A fake-frida client whose device/attach paths explode if reached.

    The gate runs before any of these, so on authorized-code they stay at zero.
    A reordering that resolved a device or attached first would raise
    AssertionError from inside the spy -- surfaced as a plain error, never a
    ``permission_denied`` -- and every test below would fail loudly.
    """
    client = FridaClient()
    client._available = True
    client._frida = _ExplodingFrida()  # type: ignore[assignment]
    touched = {"resolve": 0, "attach": 0}

    def spy_resolve(device_id: str | None) -> Any:
        touched["resolve"] += 1
        raise AssertionError(
            f"_resolve_device({device_id!r}) ran on an unauthorized pid"
        )

    def spy_attach(pid: int, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        touched["attach"] += 1
        raise AssertionError(f"_attach_local({pid}) ran on an unauthorized pid")

    client._resolve_device = spy_resolve  # type: ignore[method-assign]
    client._attach_local = spy_attach  # type: ignore[method-assign]
    return client, touched


class _ExplodingFrida:
    """Stands in for the frida module; its attach must never be called."""

    def attach(self, pid: int, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise AssertionError(f"frida.attach({pid}) ran on an unauthorized pid")


# Each case names an entry point and an unauthorized call: the pid asked for is
# never the one(s) granted, so the gate must refuse it. device_id is "usb" for
# the device-aware ops precisely so a swapped order would try (and, with the
# spy, be caught) resolving a real device before denying.
_UNAUTHORIZED_CALLS: list[tuple[str, Callable[[FridaClient], Any]]] = [
    ("attach", lambda c: c.attach(4242, allowed_pid=4243)),
    ("modules", lambda c: c.modules(4242, allowed_pid=4243, limit=1)),
    ("exports", lambda c: c.exports(4242, "libc.so", allowed_pid=4243, limit=1)),
    ("memory_read", lambda c: c.memory_read(4242, 0x1000, 16, allowed_pid=4243)),
    ("hook_template", lambda c: c.hook_template(4242, "noop", allowed_pid=4243)),
    (
        "java_enumerate",
        lambda c: c.java_enumerate(
            "usb", 4242, allowed_pids=[1, 2, 3], mode="classes", limit=1
        ),
    ),
    (
        "hook_template_device",
        lambda c: c.hook_template_device("usb", 99, "noop", allowed_pids=[7]),
    ),
]


@pytest.mark.parametrize("name, call", _UNAUTHORIZED_CALLS, ids=[c[0] for c in _UNAUTHORIZED_CALLS])
def test_unauthorized_pid_is_denied_before_any_device_or_attach(
    name: str, call: Callable[[FridaClient], Any]
) -> None:
    client, touched = _client_with_tripwires()

    with pytest.raises(FridaError) as caught:
        call(client)

    # The gate, not a downstream failure: a swapped order would raise the spy's
    # AssertionError (not a FridaError) or a not_found from a failed lookup.
    assert caught.value.code == "permission_denied", name
    assert caught.value.details.get("pid") in {4242, 99}, name
    # Nothing was resolved or attached on the way to the refusal.
    assert touched["resolve"] == 0, f"{name} resolved a device before denying"
    assert touched["attach"] == 0, f"{name} attached before denying"


def test_device_gate_lists_the_authorized_set_it_refused_against() -> None:
    """A denied device op has to say which pids were allowed, for the log.

    The single-pid local path reports ``pid``; the device path additionally
    reports the ``allowed_pids`` it checked against, so an operator reading the
    incident can see the caller asked for a pid outside the session's set rather
    than guessing whether the set was empty.
    """
    client, _ = _client_with_tripwires()
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4242, allowed_pids=[1, 2, 3], mode="classes")
    assert caught.value.code == "permission_denied"
    assert caught.value.details["pid"] == 4242
    assert caught.value.details["allowed_pids"] == [1, 2, 3]


def test_an_authorized_pid_is_not_refused_by_the_gate() -> None:
    """The gate must pass an authorized pid through -- proving the deny is the
    pid check, not a fake that rejects everything.

    With the spies in place an authorized call gets *past* the gate and trips
    the ``_attach_local`` spy (AssertionError), never a ``permission_denied``.
    That is the negative control for the tests above: it shows the refusals they
    assert come from the pid not matching, not from the harness failing closed.
    """
    client, touched = _client_with_tripwires()
    with pytest.raises(AssertionError):
        client.modules(4242, allowed_pid=4242, limit=1)
    assert touched["attach"] == 1
    assert touched["resolve"] == 0
