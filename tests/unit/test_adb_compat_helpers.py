"""Cross-version adbutils compatibility shims, pinned without a device.

adbutils changes method signatures and device-list shapes across releases, so
the adb backend probes each call site before it trusts it. Those probes are
pure and decide real behavior, yet only ran on a live-device path:

* ``_accepts_timeout`` decides whether a ``timeout=`` may be passed. Guess wrong
  the optimistic way and the call raises TypeError and falls through to a
  ten-minute transport wait; so when a signature cannot be read at all it must
  answer False (do not pass it), not assume it is safe.
* ``_accepted_kwargs`` filters extra kwargs down to what a method actually
  names -- everything for a ``**kwargs`` method, nothing when the signature is
  unreadable -- so a newer keyword never reaches an older method as a TypeError.
* ``_is_timeout`` classifies an arbitrary adbutils/adb exception as a timeout by
  its type name or message, since the library raises many unrelated types.
* ``_device_info_row`` normalizes one entry from ``list_devices`` whether the
  library handed back an object with ``.serial``/``.state`` or a bare tuple, and
  fills ``state`` with ``unknown`` rather than leaving it blank.
"""

from __future__ import annotations

from headless_re_mcp.backends.adb.client import (
    _accepted_kwargs,
    _accepts_timeout,
    _bind_open_transport,
    _device_info_row,
    _is_timeout,
)


def test_is_timeout_matches_on_type_name_or_message() -> None:
    # Type name carrying "timeout" (e.g. TimeoutError) matches...
    assert _is_timeout(TimeoutError()) is True
    # ...as does a message carrying the phrase "timed out".
    assert _is_timeout(RuntimeError("the read timed out waiting")) is True
    # But an unrelated exception is not a timeout. The message check keys on the
    # phrase "timed out": a bare "timeout" in the text of a non-timeout type is
    # deliberately not enough, so a real failure is not misread as a deadline.
    assert _is_timeout(Exception("connection timeout value was ignored")) is False
    assert _is_timeout(ValueError("bad argument")) is False


def test_accepts_timeout_true_for_a_named_or_varkw_parameter() -> None:
    def named(timeout: float = 1.0) -> None: ...

    def var_kw(**kwargs: object) -> None: ...

    assert _accepts_timeout(named) is True
    assert _accepts_timeout(var_kw) is True


def test_accepts_timeout_false_when_the_parameter_is_absent() -> None:
    def positional(serial: str) -> None: ...

    assert _accepts_timeout(positional) is False


def test_accepts_timeout_defaults_to_false_when_the_signature_is_unreadable() -> None:
    """A callable whose signature cannot be introspected must be treated as not
    accepting timeout -- the conservative choice that avoids a TypeError."""
    # int is a builtin type with no readable signature (ValueError); object() is
    # not callable at all (TypeError). Both must fall to the safe default.
    assert _accepts_timeout(int) is False
    assert _accepts_timeout(object()) is False


def test_accepted_kwargs_filters_to_the_named_parameters() -> None:
    def method(serial: str, reinstall: bool = False) -> None: ...

    filtered = _accepted_kwargs(method, {"reinstall": True, "downgrade": True})
    assert filtered == {"reinstall": True}


def test_accepted_kwargs_passes_everything_through_for_varkw() -> None:
    def method(**kwargs: object) -> None: ...

    extra = {"reinstall": True, "downgrade": True}
    assert _accepted_kwargs(method, extra) == extra


def test_accepted_kwargs_is_empty_when_the_signature_is_unreadable() -> None:
    """An unreadable signature drops every extra kwarg rather than risk handing
    a newer keyword to an older method as a TypeError."""
    assert _accepted_kwargs(int, {"reinstall": True}) == {}


class _Info:
    def __init__(self, serial: str, state: str = "") -> None:
        self.serial = serial
        self.state = state


def test_device_info_row_reads_serial_and_state_from_an_object() -> None:
    row = _device_info_row(_Info("emulator-5554", "device"))
    assert row == {"serial": "emulator-5554", "state": "device"}


def test_device_info_row_defaults_a_missing_state_to_unknown() -> None:
    row = _device_info_row(_Info("emulator-5554"))
    assert row == {"serial": "emulator-5554", "state": "unknown"}


def test_device_info_row_reads_a_serial_and_state_tuple() -> None:
    row = _device_info_row(("R58N123", "unauthorized"))
    assert row == {"serial": "R58N123", "state": "unauthorized"}


def test_device_info_row_tolerates_a_serial_only_tuple() -> None:
    """A one-element tuple carries no state; it must still yield a serial and the
    ``unknown`` default rather than IndexError on the absent second field."""
    row = _device_info_row(("R58N123",))
    assert row == {"serial": "R58N123", "state": "unknown"}


class _NoTransport:
    """A device that offers no open_transport to wrap."""


def test_bind_open_transport_leaves_a_device_without_the_method_untouched() -> None:
    dev = _NoTransport()
    assert _bind_open_transport(dev, 5.0) is dev
    assert not hasattr(dev, "open_transport")


class _RecDev:
    """Records how its open_transport was ultimately invoked."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def open_transport(self, command: object = None, timeout: object = None) -> str:
        self.calls.append({"command": command, "timeout": timeout})
        return "transport"


def test_bind_open_transport_supplies_the_hang_ceiling_as_the_default() -> None:
    """The wrapped call, made with no timeout, must reach the real method with
    the ceiling in place of adbutils' ten-minute default."""
    dev = _RecDev()
    bound = _bind_open_transport(dev, 7.5)
    assert bound is dev
    assert dev.open_transport() == "transport"
    assert dev.calls == [{"command": None, "timeout": 7.5}]


class _PositionalOnlyDev:
    """open_transport that rejects keyword args but accepts them positionally."""

    def __init__(self) -> None:
        self.args: tuple[object, ...] | None = None

    def open_transport(self, command: object = None, timeout: object = None, /) -> str:
        self.args = (command, timeout)
        return "transport"


def test_bind_open_transport_falls_back_to_positional_args() -> None:
    """An adbutils build whose open_transport takes command/timeout positionally
    (rejecting the keyword form) must still receive both, via the fallback."""
    dev = _PositionalOnlyDev()
    _bind_open_transport(dev, 3.0)
    assert dev.open_transport() == "transport"
    assert dev.args == (None, 3.0)


class _CommandOnlyDev:
    """open_transport that accepts only a single positional command."""

    def __init__(self) -> None:
        self.command: object = "unset"

    def open_transport(self, command: object = None, /) -> str:
        self.command = command
        return "transport"


def test_bind_open_transport_falls_back_to_command_only() -> None:
    """The oldest shape takes just a command; both timeout-carrying forms raise
    TypeError and the wrapper must degrade to the single-argument call."""
    dev = _CommandOnlyDev()
    _bind_open_transport(dev, 3.0)
    assert dev.open_transport() == "transport"
    assert dev.command is None


class _UnassignableDev:
    """A slotless device whose open_transport attribute cannot be reassigned."""

    __slots__ = ()

    def open_transport(self, command: object = None, timeout: object = None) -> str:
        return "transport"


def test_bind_open_transport_returns_the_device_when_it_cannot_be_rebound() -> None:
    """If the wrapper cannot be installed (a slotless device), binding must give
    the device back rather than raise -- the caller still has a usable device."""
    dev = _UnassignableDev()
    assert _bind_open_transport(dev, 5.0) is dev
