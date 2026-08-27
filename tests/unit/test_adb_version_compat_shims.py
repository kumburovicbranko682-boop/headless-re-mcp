"""The adbutils compatibility shims must guess kwargs right, or a call hangs 10 min.

adbutils' method signatures drift across versions: some accept ``timeout``, some
take ``**kwargs``, some are C-accelerated with no introspectable signature, and
``open_transport`` variously takes ``(command, timeout)`` by keyword, by
position, or ``command`` alone. The client probes each signature before calling
so it can pass a deadline where one is accepted and withhold it where it is not.
Guess wrong and the failure is not loud: passing an unaccepted ``timeout`` raises
TypeError, which the transport binding treats as "no timeout supported" and falls
through to adbutils' 600-second default -- the exact multi-minute hang these
shims exist to prevent. None of them had direct coverage.

These call the pure shims with hand-built callables that mimic each adbutils
shape -- no device, no adb server.
"""

from __future__ import annotations

from inspect import signature
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import (
    _accepted_kwargs,
    _accepts_timeout,
    _bind_open_transport,
)


def test_accepts_timeout_true_for_an_explicit_param_or_var_keyword() -> None:
    """A method is safe to hand a timeout when it names one or takes **kwargs."""

    def named(a: int, timeout: float | None = None) -> None:
        del a, timeout

    def var_kw(a: int, **kwargs: Any) -> None:
        del a, kwargs

    assert _accepts_timeout(named) is True
    assert _accepts_timeout(var_kw) is True


def test_accepts_timeout_false_when_the_method_cannot_take_one() -> None:
    """A method with neither a timeout param nor **kwargs must not be handed one.

    Passing ``timeout=`` to such a method raises TypeError, and the caller reads
    that as "this adbutils version has no deadline support" and waits out the
    600s default -- so the honest answer here is False, keep the timeout back.
    """

    def plain(a: int, b: int) -> None:
        del a, b

    assert _accepts_timeout(plain) is False


def test_accepts_timeout_false_for_an_uninspectable_builtin() -> None:
    """A C-accelerated adbutils method has no Python signature to inspect.

    ``signature()`` raises ValueError on a C callable with no ``__text_signature__``;
    that must degrade to False (do not pass timeout) rather than propagate, because a
    raise here would abort a call the client could otherwise make without a deadline.
    ``dict`` stands in for the unsignaturable C method -- its premise (that
    ``signature`` really refuses it) is asserted so a future Python that starts
    signing it fails this test loudly instead of silently skipping the branch.
    """
    with pytest.raises((TypeError, ValueError)):
        signature(dict)
    assert _accepts_timeout(dict) is False


def test_accepted_kwargs_filters_to_the_named_parameters() -> None:
    """Only kwargs the target actually declares are forwarded."""

    def target(a: int, timeout: float | None = None) -> None:
        del a, timeout

    assert _accepted_kwargs(target, {"timeout": 5, "unknown": 1}) == {"timeout": 5}


def test_accepted_kwargs_passes_everything_through_a_var_keyword_method() -> None:
    """A **kwargs method takes whatever it is given, so nothing is filtered out."""

    def var_kw(a: int, **kwargs: Any) -> None:
        del a, kwargs

    extra = {"timeout": 5, "transport_id": 9}
    assert _accepted_kwargs(var_kw, extra) == extra


def test_accepted_kwargs_forwards_nothing_when_the_signature_is_opaque() -> None:
    """An uninspectable method gets no kwargs rather than a TypeError.

    If the signature cannot be read, forwarding a guessed kwarg could raise; the
    safe degradation is to forward none, matching the timeout shim's caution.
    ``dict`` is again the unsignaturable stand-in, premise asserted.
    """
    with pytest.raises((TypeError, ValueError)):
        signature(dict)
    assert _accepted_kwargs(dict, {"timeout": 5}) == {}


class _KwargsTransport:
    """open_transport that accepts command and timeout by keyword (modern adbutils)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Any, Any]] = []

    def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
        self.calls.append(("kw", command, timeout))
        return "ok"


def test_bind_open_transport_injects_the_bounded_timeout_as_the_default() -> None:
    """A no-argument open_transport() call carries the client's deadline, not 600s.

    adbutils invokes ``open_transport()`` internally with no timeout during
    get_state/forward/install, so the wrapper's job is to make the bounded value
    the *default* -- that is what actually replaces the 600s ceiling. Calling the
    rebound method with no args must reach the original with the bound timeout.
    """
    dev = _KwargsTransport()
    result = _bind_open_transport(dev, 5.0)
    assert result is dev
    assert dev.open_transport() == "ok"
    assert dev.calls == [("kw", None, 5.0)]


class _PositionalTransport:
    """open_transport that rejects keywords but takes positionals (older adbutils)."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def open_transport(self, *args: Any) -> str:
        self.calls.append(args)
        return "ok"


def test_bind_open_transport_falls_back_to_positional_args() -> None:
    """When command=/timeout= raise TypeError, the shim retries positionally.

    An adbutils build whose open_transport is ``(*args)`` or positional-only
    rejects the keyword call; the wrapper must retry as ``original(command,
    timeout)`` so the deadline still reaches it rather than being lost to the
    TypeError-means-no-timeout fall-through.
    """
    dev = _PositionalTransport()
    _bind_open_transport(dev, 7.0)
    assert dev.open_transport() == "ok"
    assert dev.calls == [(None, 7.0)]


class _CommandOnlyTransport:
    """open_transport that takes exactly one positional (the command)."""

    def __init__(self) -> None:
        self.calls: list[Any] = []

    def open_transport(self, command: Any) -> str:
        self.calls.append(command)
        return "ok"


def test_bind_open_transport_falls_back_to_command_only() -> None:
    """The last resort is ``original(command)`` when even (command, timeout) fails.

    The oldest signature takes only the command; both the keyword and the
    two-positional retries raise TypeError, so the wrapper must still make the
    call -- without a timeout it cannot bound, but a working call beats a raise.
    """
    dev = _CommandOnlyTransport()
    _bind_open_transport(dev, 9.0)
    assert dev.open_transport() == "ok"
    assert dev.calls == [None]


def test_bind_open_transport_leaves_a_device_without_the_method_untouched() -> None:
    """Nothing to rebind means the device is returned unchanged, no attr invented."""

    class _NoTransport:
        pass

    dev = _NoTransport()
    assert _bind_open_transport(dev, 3.0) is dev
    assert not hasattr(dev, "open_transport")


def test_bind_open_transport_tolerates_a_read_only_open_transport() -> None:
    """A device that refuses the rebind is returned as-is, not raised through.

    Some adbutils device objects expose open_transport as a property with no
    setter; assigning the wrapper raises AttributeError. That is swallowed and
    the original device returned, so a version that cannot be rebound simply runs
    unbounded rather than failing the whole operation.
    """

    class _ReadOnly:
        @property
        def open_transport(self) -> Any:
            return lambda command=None, timeout=None: "orig"

    dev = _ReadOnly()
    result = _bind_open_transport(dev, 3.0)
    assert result is dev
    # The property is intact: the rebind was refused, not half-applied.
    assert dev.open_transport() == "orig"
