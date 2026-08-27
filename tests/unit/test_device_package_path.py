"""device.package_path resolves a package to its on-device APK path(s).

This is the bridge between "what is installed" (device.packages) and "pull the
APK to analyze it statically" (device.pull -> apk.*). The gap it closes:
device.packages listed names only, and the backend's internal _pm_path helper
grabs just the first ``package:`` line, which for a split app (base.apk plus
config splits) silently drops the splits. These tests pin that every path is
returned, that an offline device is not misread as an uninstalled app, and that
a device returning junk cannot flood the reply.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.adb.client import _MAX_PACKAGE_PATHS, AdbBackend, AdbError


def _adb_with_shell(output: str) -> AdbBackend:
    class _Dev:
        def shell(self, cmd: object, timeout: float | None = None) -> str:
            del cmd, timeout
            return output

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = object()
    backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
    return backend


def test_split_app_returns_every_path_not_just_the_base() -> None:
    raw = (
        "package:/data/app/~~ab==/com.example-1/base.apk\n"
        "package:/data/app/~~ab==/com.example-1/split_config.arm64_v8a.apk\n"
        "package:/data/app/~~ab==/com.example-1/split_config.xxhdpi.apk\n"
    )
    result = _adb_with_shell(raw).package_path("emulator-5554", "com.example")
    assert result["paths"] == [
        "/data/app/~~ab==/com.example-1/base.apk",
        "/data/app/~~ab==/com.example-1/split_config.arm64_v8a.apk",
        "/data/app/~~ab==/com.example-1/split_config.xxhdpi.apk",
    ]
    assert result["count"] == 3
    assert result["installed"] is True
    assert result["has_more"] is False
    assert result["package"] == "com.example"


def test_no_path_lines_is_an_uninstalled_app_not_an_error() -> None:
    result = _adb_with_shell("").package_path("emulator-5554", "com.absent")
    assert result["paths"] == []
    assert result["count"] == 0
    assert result["installed"] is False
    assert result["has_more"] is False


def test_an_adb_error_line_is_not_an_uninstalled_app() -> None:
    with pytest.raises(AdbError) as info:
        _adb_with_shell("adb: device 'emulator-5554' not found").package_path(
            "emulator-5554", "com.example"
        )
    assert info.value.code == "backend_error"
    assert "pm path failed" in info.value.message
    assert "not found" in str(info.value.details.get("output", ""))


def test_a_flood_of_paths_is_capped_and_flagged() -> None:
    raw = "".join(f"package:/data/app/base{i}.apk\n" for i in range(_MAX_PACKAGE_PATHS + 20))
    result = _adb_with_shell(raw).package_path("emulator-5554", "com.example")
    assert result["count"] == _MAX_PACKAGE_PATHS
    assert result["has_more"] is True
    assert result["installed"] is True


def test_a_malformed_package_id_is_rejected() -> None:
    with pytest.raises(AdbError) as info:
        _adb_with_shell("").package_path("emulator-5554", "not a package")
    assert info.value.code == "invalid_params"
