"""device.info assembles a getprop read-out; properties/packages skip junk lines.

device.info fans several ``getprop`` reads plus ``get_state`` into one summary,
and it had no test: a success must carry state and every prop it queried, and any
failure in that fan-out is a backend_error rather than a raw exception. The
list read-outs (properties, packages) parse line-oriented shell dumps, and a line
that is not a well-formed entry -- a blank, a banner, a ``package:`` with no name
-- must be skipped, not counted or emitted, so the counts and pages stay honest.

Driven by a fake device exposing ``shell`` and ``get_state`` -- no adbutils, no
emulator.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


class _ReadoutDev:
    """A device answering ``shell`` from a command->output map, plus get_state."""

    def __init__(
        self,
        responses: dict[str, str],
        *,
        state: str = "device",
        get_state_raises: bool = False,
    ) -> None:
        self._responses = responses
        self._state = state
        self._get_state_raises = get_state_raises

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        key = args if isinstance(args, str) else " ".join(args)
        return self._responses.get(key, "")

    def get_state(self, timeout: float | None = None) -> str:
        del timeout
        if self._get_state_raises:
            raise RuntimeError("device offline")
        return self._state


def _backend_with(dev: _ReadoutDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_info_reports_state_and_every_getprop_value() -> None:
    """A healthy device yields state plus the model/device/sdk/release/abi props.

    Each field is a separate getprop; the summary must thread every one through
    (trimmed of its trailing newline), so a caller sees the whole identity of the
    device rather than a partial record.
    """
    dev = _ReadoutDev(
        {
            "getprop ro.product.model": "Pixel 7\n",
            "getprop ro.product.device": "panther\n",
            "getprop ro.build.version.sdk": "34\n",
            "getprop ro.build.version.release": "14\n",
            "getprop ro.product.cpu.abi": "arm64-v8a\n",
        }
    )
    result = _backend_with(dev).info("emulator-5554")
    assert result == {
        "serial": "emulator-5554",
        "state": "device",
        "model": "Pixel 7",
        "device": "panther",
        "sdk": "34",
        "release": "14",
        "abi": "arm64-v8a",
    }


def test_info_maps_a_failure_to_backend_error() -> None:
    """A failure anywhere in the fan-out is a backend_error, not a raw exception.

    Here get_state throws (an offline device); left unclassified it would reach
    the service envelope as an internal_error incident instead of the honest
    device outcome.
    """
    dev = _ReadoutDev({}, get_state_raises=True)
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).info("emulator-5554")
    assert caught.value.code == "backend_error"
    assert "failed to read device info" in caught.value.message


def test_properties_skips_lines_that_are_not_getprop_pairs() -> None:
    """A line that is not ``[key]: [value]`` is noise and must not be counted.

    getprop output can carry blanks and banner lines; only bracketed pairs are
    real properties, so count reflects the pairs, not the raw line total.
    """
    dev = _ReadoutDev(
        {"getprop": "[ro.a]: [1]\ngarbage line without brackets\n[ro.b]: [2]\n"}
    )
    result = _backend_with(dev).properties("emulator-5554")
    assert result["properties"] == {"ro.a": "1", "ro.b": "2"}
    assert result["count"] == 2
    assert result["has_more"] is False


def test_packages_skips_non_package_and_empty_lines() -> None:
    """Only ``package:<name>`` lines with a real name are kept.

    ``pm list packages`` can interleave non-package output and, on some devices, a
    bare ``package:`` with no id; both are dropped so the list is exactly the
    installed packages, counted and sorted.
    """
    dev = _ReadoutDev(
        {"pm list packages": "package:com.b\nnot-a-package-line\npackage:\npackage:com.a\n"}
    )
    result = _backend_with(dev).packages("emulator-5554")
    assert result["packages"] == ["com.a", "com.b"]
    assert result["count"] == 2
