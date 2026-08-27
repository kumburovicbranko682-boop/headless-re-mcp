"""getprop and `pm list packages` parsing contracts, pinned with fixtures.

These two ADB readers turn raw device shell text into structured results an
agent branches on. They are pure string parsers (the same shape as the
``ps -A`` fallback that used to mis-read the PID column), so pin their contract
against realistic and adversarial output: bracketed/empty property values, a
missing space after the colon, junk lines, the ``package:`` prefix, empty
entries, the third-party ``-3`` flag, and the cap/has_more bound.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import AdbBackend

_GETPROP = """[ro.build.version.sdk]: [33]
[ro.product.model]: [Pixel 7]
[persist.weird]: [a[b]c]
[empty.prop]: []
[nospace]:[x]
garbage line without brackets
"""


class _Dev:
    """Fake adbutils device that records shell commands and returns canned text."""

    def __init__(self, out: str) -> None:
        self.out = out
        self.commands: list[Any] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.commands.append(args)
        return self.out


def _backend(dev: _Dev) -> AdbBackend:
    backend = AdbBackend()
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_getprop_decodes_values_and_ignores_junk() -> None:
    result = _backend(_Dev(_GETPROP)).properties("emulator-5554")
    props = result["properties"]
    assert props["ro.build.version.sdk"] == "33"
    assert props["ro.product.model"] == "Pixel 7"  # value may contain spaces
    assert props["persist.weird"] == "a[b]c"  # value may contain brackets
    assert props["empty.prop"] == ""  # empty value is kept, not dropped
    assert props["nospace"] == "x"  # colon need not be followed by a space
    assert "garbage line without brackets" not in props
    assert result["count"] == 5
    assert result["has_more"] is False


def test_getprop_respects_the_limit_and_flags_more() -> None:
    dev = _Dev("\n".join(f"[k{i}]: [v{i}]" for i in range(10)))
    result = _backend(dev).properties("emulator-5554", limit=4)
    assert result["count"] == 4
    assert result["has_more"] is True


def test_packages_strips_prefix_and_skips_empty_and_noise() -> None:
    dev = _Dev("package:com.foo.bar\npackage:com.example.app\npackage:\nnot-a-package\n")
    result = _backend(dev).packages("emulator-5554")
    assert result["packages"] == ["com.example.app", "com.foo.bar"]  # sorted
    assert result["count"] == 2
    assert result["has_more"] is False
    assert result["third_party_only"] is False


def test_packages_third_party_only_passes_the_dash_three_flag() -> None:
    dev = _Dev("package:com.third.party\n")
    result = _backend(dev).packages("emulator-5554", third_party_only=True)
    assert result["third_party_only"] is True
    assert result["packages"] == ["com.third.party"]
    # The -3 filter must actually be handed to pm, not just reported.
    assert any("pm list packages -3" in str(cmd) for cmd in dev.commands)


def test_packages_respects_the_limit_and_flags_more() -> None:
    dev = _Dev("\n".join(f"package:com.z{i:02d}" for i in range(10)))
    result = _backend(dev).packages("emulator-5554", limit=3)
    assert result["count"] == 3
    assert result["has_more"] is True
