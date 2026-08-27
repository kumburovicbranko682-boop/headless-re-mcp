"""Serial / package / APK validators are the adb shell-injection boundary.

Serials and package names are interpolated into ``adb -s <serial> shell ...``
and ``am``/``pm``/``monkey`` command vectors. The grammars are deliberately
narrow -- no whitespace, no shell metacharacters, no path separators -- so a
model-supplied value can never carry ``;``/``$()``/backticks/``|`` into a shell,
and a non-zip cannot be shipped to ``pm install`` only to fail opaquely after the
whole transfer. These pin the accept set, the reject set (with hostile inputs),
and that the returned value is the trimmed original.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.adb.client import (
    AdbError,
    _check_package,
    _check_serial,
    _require_apk_zip,
)

_INJECTIONS = (
    "emulator-5554; rm -rf /",
    "$(reboot)",
    "`id`",
    "a|b",
    "a&b",
    "a b",
    "a\nb",
    'a"b',
    "a'b",
    "a/b",
    "a>b",
    "../secret",
)


def test_check_serial_accepts_real_device_serials() -> None:
    for good in ("emulator-5554", "192.168.0.2:5555", "ABC123DEF", "a.b_c-d:1", "0" * 128):
        assert _check_serial(good) == good


def test_check_serial_trims_then_returns_the_clean_value() -> None:
    assert _check_serial("  emulator-5554  ") == "emulator-5554"


def test_check_serial_rejects_injection_and_out_of_range_lengths() -> None:
    for bad in ("", "   ", "0" * 129, *_INJECTIONS):
        with pytest.raises(AdbError) as info:
            _check_serial(bad)
        assert info.value.code == "invalid_params"
        assert info.value.details.get("serial") == bad


def test_check_package_accepts_valid_ids() -> None:
    for good in ("com.example.app", "a.b", "com.example_app.v2", "org.chromium.chrome"):
        assert _check_package(good) == good


def test_check_package_trims_then_returns_the_clean_value() -> None:
    assert _check_package("  com.example.app  ") == "com.example.app"


def test_check_package_rejects_malformed_and_hostile_names() -> None:
    bad_names = (
        "",
        "com",  # a single segment is not a package id
        "1com.example",  # must start with a letter
        "com.exa-mple",  # hyphen is not in the grammar
        "/system/bin/sh",
        "com.example; rm -rf /",
        "com.example app",
        "com..example",  # empty segment
    )
    for bad in bad_names:
        with pytest.raises(AdbError) as info:
            _check_package(bad)
        assert info.value.code == "invalid_params"
        assert info.value.details.get("package") == bad


def test_require_apk_zip_accepts_a_zip_archive(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"binary-xml")
    _require_apk_zip(apk)  # does not raise


def test_require_apk_zip_refuses_a_non_zip_before_transfer(tmp_path: Path) -> None:
    """A truncated download or wrong file is refused up front, not after upload."""
    not_apk = tmp_path / "app.apk"
    not_apk.write_text("this is not a zip", encoding="utf-8")
    with pytest.raises(AdbError) as info:
        _require_apk_zip(not_apk)
    assert info.value.code == "invalid_params"
    assert info.value.details.get("path") == str(not_apk)
