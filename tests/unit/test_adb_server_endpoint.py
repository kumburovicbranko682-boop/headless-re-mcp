"""The adb server address must honor the standard adb environment overrides.

``adb`` itself, Android Studio, and adbutils all read
``ANDROID_ADB_SERVER_HOST`` / ``ANDROID_ADB_SERVER_PORT``. The client used to
hardcode 127.0.0.1:5037, so an operator whose server listens elsewhere --
multiple emulators, containerised CI, or the hermetic device gate -- could
reach it with every adb tool except device.*. Pinned here: the defaults when
nothing is set, the override when set, and a refusal (naming the variable)
rather than a silent fallback when the port value cannot address a server the
operator explicitly chose.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.adb.client import AdbError, _adb_server_endpoint


def test_defaults_to_loopback_5037_when_nothing_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANDROID_ADB_SERVER_HOST", raising=False)
    monkeypatch.delenv("ANDROID_ADB_SERVER_PORT", raising=False)
    assert _adb_server_endpoint() == ("127.0.0.1", 5037)


def test_env_overrides_are_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANDROID_ADB_SERVER_HOST", "10.0.0.7")
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "16000")
    assert _adb_server_endpoint() == ("10.0.0.7", 16000)


def test_blank_values_fall_back_to_the_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whitespace-only values read as unset, matching adb's own tolerance."""
    monkeypatch.setenv("ANDROID_ADB_SERVER_HOST", "  ")
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "")
    assert _adb_server_endpoint() == ("127.0.0.1", 5037)


@pytest.mark.parametrize("value", ["nonsense", "0", "-1", "65536", "80 81"])
def test_an_unusable_port_is_refused_by_name_not_silently_replaced(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Falling back to 5037 would aim commands at a server the operator moved
    away from; the refusal must say which variable to fix."""
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", value)
    with pytest.raises(AdbError) as info:
        _adb_server_endpoint()
    assert info.value.code == "invalid_params"
    assert "ANDROID_ADB_SERVER_PORT" in info.value.message
