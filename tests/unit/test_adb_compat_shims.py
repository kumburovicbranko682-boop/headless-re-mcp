"""Device-free coverage for the ADB backend's adbutils compat shims.

Every operation on a device flows through a handful of module-level wrappers
whose whole job is to make adbutils' version drift and a device's tendency to
stall *not* turn into a wrong argument, an unwrapped crash, or a ten-minute
hang. None of them were exercised: the higher-level tests either skip without
adbutils or stub the device out, so the shims that decide

- whether ``timeout=`` is safe to pass to a given adbutils method
  (``_accepts_timeout`` / ``_accepted_kwargs``) -- old adbutils raised
  ``TypeError`` when handed a keyword it did not know, so guessing wrong is a
  hard failure, not a slow one;
- how ``device.shell`` / a bound adbutils method map their failures onto the
  structured error contract (``_device_shell`` / ``_call``): a stall becomes
  ``timeout``, an ``AdbError`` passes through untouched, and -- the part worth
  pinning -- ``_call`` wraps *only* timeouts and re-raises everything else
  unchanged so callers keep their own error mapping;
- how a device stall is bounded (``_bind_open_transport`` replaces adbutils'
  600s ``open_transport`` default and degrades across its three call shapes);
- how the frida-server probe and ``pm path`` reader tolerate a shell that
  errors or returns junk;

had no coverage at all. These are pure functions over fakes, so they pin the
contracts without a device.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.adb import client as adb_client
from headless_re_mcp.backends.adb.client import (
    AdbError,
    _accepted_kwargs,
    _accepts_timeout,
    _bind_open_transport,
    _call,
    _device_shell,
    _frida_server_visible,
    _pm_path,
)

# --- _accepts_timeout / _accepted_kwargs ------------------------------------


def test_accepts_timeout_true_for_an_explicit_timeout_param() -> None:
    def f(args: object, timeout: float = 1.0) -> None: ...

    assert _accepts_timeout(f) is True


def test_accepts_timeout_true_for_var_keyword() -> None:
    def f(args: object, **kwargs: object) -> None: ...

    assert _accepts_timeout(f) is True


def test_accepts_timeout_false_without_timeout_or_kwargs() -> None:
    def f(args: object) -> None: ...

    assert _accepts_timeout(f) is False


def test_accepts_timeout_false_when_signature_is_unintrospectable() -> None:
    # A C builtin whose signature() raises must be treated as "cannot pass
    # timeout" rather than raising out of the introspection itself; range is
    # the reliably-unintrospectable callable in CPython.
    assert _accepts_timeout(range) is False


def test_accepts_timeout_reads_through_a_bound_method() -> None:
    class Dev:
        def shell(self, args: object, timeout: float = 1.0) -> None: ...

    assert _accepts_timeout(Dev().shell) is True


def test_accepted_kwargs_filters_to_the_named_parameters() -> None:
    def install(path: str, nolaunch: bool = False, flags: object = None) -> None: ...

    got = _accepted_kwargs(install, {"nolaunch": True, "uninstall": False, "flags": ["-r"]})
    assert got == {"nolaunch": True, "flags": ["-r"]}


def test_accepted_kwargs_passes_everything_through_var_keyword() -> None:
    def install(path: str, **kwargs: object) -> None: ...

    extra = {"nolaunch": True, "uninstall": False}
    assert _accepted_kwargs(install, extra) == extra


def test_accepted_kwargs_is_empty_when_signature_is_unintrospectable() -> None:
    assert _accepted_kwargs(range, {"nolaunch": True}) == {}


# --- _device_shell ----------------------------------------------------------


class _Shell:
    """A device whose shell() records how it was called and can raise."""

    def __init__(self, *, accepts_timeout: bool, raises: BaseException | None = None) -> None:
        self.calls: list[tuple[object, object]] = []
        self._raises = raises
        if accepts_timeout:

            def shell(args: object, timeout: float | None = None) -> str:
                self.calls.append((args, timeout))
                if self._raises is not None:
                    raise self._raises
                return "ok"

        else:

            def shell(args: object) -> str:  # type: ignore[misc]
                self.calls.append((args, "no-timeout-param"))
                if self._raises is not None:
                    raise self._raises
                return "ok"

        self.shell = shell


def test_device_shell_passes_the_deadline_when_the_method_accepts_it() -> None:
    dev = _Shell(accepts_timeout=True)
    assert _device_shell(dev, "getprop", timeout=9.0) == "ok"
    assert dev.calls == [("getprop", 9.0)]


def test_device_shell_omits_timeout_for_older_adbutils() -> None:
    dev = _Shell(accepts_timeout=False)
    assert _device_shell(dev, "getprop", timeout=9.0) == "ok"
    assert dev.calls == [("getprop", "no-timeout-param")]


def test_device_shell_lets_an_adb_error_pass_through() -> None:
    sentinel = AdbError("invalid_params", "nope")
    dev = _Shell(accepts_timeout=True, raises=sentinel)
    with pytest.raises(AdbError) as caught:
        _device_shell(dev, "getprop")
    assert caught.value is sentinel


def test_device_shell_maps_a_stall_to_timeout() -> None:
    dev = _Shell(accepts_timeout=True, raises=TimeoutError("read timed out"))
    with pytest.raises(AdbError) as caught:
        _device_shell(dev, "getprop", timeout=3.0)
    assert caught.value.code == "timeout"


def test_device_shell_maps_a_generic_failure_to_backend_error() -> None:
    dev = _Shell(accepts_timeout=True, raises=RuntimeError("broken pipe"))
    with pytest.raises(AdbError) as caught:
        _device_shell(dev, "getprop")
    assert caught.value.code == "backend_error"
    assert "broken pipe" in caught.value.message


# --- _call ------------------------------------------------------------------


def test_call_passes_timeout_only_when_the_signature_allows_it() -> None:
    seen: dict[str, object] = {}

    def with_timeout(*, timeout: float | None = None) -> str:
        seen["timeout"] = timeout
        return "a"

    def without_timeout() -> str:
        seen["timeout"] = "absent"
        return "b"

    assert _call(with_timeout, timeout=5.0) == "a"
    assert seen["timeout"] == 5.0
    assert _call(without_timeout, timeout=5.0) == "b"
    assert seen["timeout"] == "absent"


def test_call_does_not_pass_timeout_when_it_is_none() -> None:
    seen: dict[str, object] = {}

    def m(**kwargs: object) -> str:
        seen.update(kwargs)
        return "ok"

    assert _call(m, timeout=None) == "ok"
    assert "timeout" not in seen


def test_call_lets_an_adb_error_pass_through() -> None:
    sentinel = AdbError("not_found", "gone")

    def m() -> None:
        raise sentinel

    with pytest.raises(AdbError) as caught:
        _call(m, timeout=1.0)
    assert caught.value is sentinel


def test_call_maps_a_stall_to_timeout() -> None:
    def m(*, timeout: float | None = None) -> None:
        raise TimeoutError("timed out")

    with pytest.raises(AdbError) as caught:
        _call(m, timeout=2.0)
    assert caught.value.code == "timeout"


def test_call_re_raises_a_generic_failure_unchanged() -> None:
    # The contract is that _call wraps *only* timeouts: any other exception is
    # re-raised as-is so the calling method keeps its own error mapping.
    class Boom(RuntimeError):
        pass

    def m(*, timeout: float | None = None) -> None:
        raise Boom("device offline")

    with pytest.raises(Boom):
        _call(m, timeout=2.0)


def test_call_re_raises_generic_even_without_a_deadline() -> None:
    def m() -> None:
        raise ValueError("bad state")

    with pytest.raises(ValueError):
        _call(m, timeout=None)


# --- _frida_server_visible --------------------------------------------------


class _ProbeDev:
    def __init__(self, responses: dict[object, object]) -> None:
        self._responses = responses

    def shell(self, args: object, timeout: float | None = None) -> str:
        del timeout
        key = tuple(args) if isinstance(args, list) else args
        value = self._responses[key]
        if isinstance(value, BaseException):
            raise value
        return str(value)


def test_frida_server_visible_true_from_ps_dash_a() -> None:
    dev = _ProbeDev({"ps -A": "root 1 0 init\nshell 900 1 frida-server\n"})
    assert _frida_server_visible(dev) is True


def test_frida_server_visible_falls_back_to_plain_ps() -> None:
    dev = _ProbeDev(
        {
            "ps -A": "root 1 0 init\n",
            "ps": "shell 900 1 frida-server\n",
        }
    )
    assert _frida_server_visible(dev) is True


def test_frida_server_visible_reports_false_when_absent_from_both() -> None:
    dev = _ProbeDev({"ps -A": "root 1 0 init\n", "ps": "root 1 0 init\n"})
    assert _frida_server_visible(dev) is False


def test_frida_server_visible_degrades_to_none_on_error() -> None:
    dev = _ProbeDev({"ps -A": RuntimeError("device offline")})
    assert _frida_server_visible(dev) is None


# --- _bind_open_transport ---------------------------------------------------


def test_bind_open_transport_returns_dev_unchanged_without_the_method() -> None:
    class NoTransport:
        pass

    dev = NoTransport()
    assert _bind_open_transport(dev, 5.0) is dev


def test_bind_open_transport_uses_the_modern_keyword_form() -> None:
    calls: list[tuple[str, object, object]] = []

    class Dev:
        def open_transport(self, command: object = None, timeout: float | None = None) -> str:
            calls.append(("kw", command, timeout))
            return "modern"

    dev = _bind_open_transport(Dev(), 7.0)
    assert dev.open_transport() == "modern"
    # The bound default carries the ceiling in place of adbutils' 600s.
    assert calls == [("kw", None, 7.0)]


def test_bind_open_transport_falls_back_to_positional() -> None:
    calls: list[tuple[object, object]] = []

    class Dev:
        # Rejects the command=/timeout= keywords, forcing the positional retry.
        def open_transport(self, cmd: object = None, t: float | None = None) -> str:
            calls.append((cmd, t))
            return "positional"

    dev = _bind_open_transport(Dev(), 7.0)
    assert dev.open_transport() == "positional"
    assert calls == [(None, 7.0)]


def test_bind_open_transport_falls_back_to_command_only() -> None:
    calls: list[object] = []

    class Dev:
        # One positional only: both the keyword and the two-arg positional
        # calls raise TypeError, leaving the single-argument shape.
        def open_transport(self, command: object = None) -> str:
            calls.append(command)
            return "command-only"

    dev = _bind_open_transport(Dev(), 7.0)
    assert dev.open_transport() == "command-only"
    assert calls == [None]


def test_bind_open_transport_tolerates_an_unassignable_attribute() -> None:
    # A __slots__ device forbids setting the wrapped method; binding must give
    # back the device with its original transport rather than raising.
    class Slotted:
        __slots__ = ()

        def open_transport(self, command: object = None, timeout: float | None = None) -> str:
            return "original"

    dev = Slotted()
    bound = _bind_open_transport(dev, 7.0)
    assert bound is dev
    assert bound.open_transport() == "original"


# --- _pm_path ---------------------------------------------------------------


def test_pm_path_extracts_the_apk_path() -> None:
    dev = _ProbeDev({("pm", "path", "com.example.app"): "package:/data/app/base.apk\n"})
    assert _pm_path(dev, "com.example.app") == "/data/app/base.apk"


def test_pm_path_returns_the_line_when_the_path_is_empty() -> None:
    dev = _ProbeDev({("pm", "path", "com.example.app"): "package:\n"})
    assert _pm_path(dev, "com.example.app") == "package:"


def test_pm_path_is_none_without_a_package_line() -> None:
    dev = _ProbeDev({("pm", "path", "com.example.app"): "Unknown package\n"})
    assert _pm_path(dev, "com.example.app") is None


def test_module_exports_the_expected_shims() -> None:
    # Guard against a rename silently dropping any of these from the surface
    # this file pins; import-time failure here beats a confusing collection error.
    for name in (
        "_accepts_timeout",
        "_accepted_kwargs",
        "_device_shell",
        "_call",
        "_frida_server_visible",
        "_bind_open_transport",
        "_pm_path",
    ):
        assert callable(getattr(adb_client, name))
