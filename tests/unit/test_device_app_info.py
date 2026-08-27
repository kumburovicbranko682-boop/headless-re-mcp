"""device.app_info must read installed state and runtime grants honestly."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_device_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _FakeDev:
    def __init__(self, text: str) -> None:
        self._text = text

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        return self._text


def _backend(text: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True  # type: ignore[attr-defined]
    backend._device = lambda serial: _FakeDev(text)  # type: ignore[method-assign]
    return backend


_INSTALLED_DUMP = """DUMP OF SERVICE package:
Packages:
  Package [com.example.app] (a1b2c3):
    userId=10234
    codePath=/data/app/~~abc==/com.example.app-xyz==
    primaryCpuAbi=arm64-v8a
    secondaryCpuAbi=null
    versionCode=4501 minSdk=23 targetSdk=33
    versionName=4.5.1
    dataDir=/data/user/0/com.example.app
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA DEBUGGABLE ]
    privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE ]
    firstInstallTime=2023-01-02 03:04:05
    lastUpdateTime=2023-06-07 08:09:10
    installerPackageName=com.android.vending
    install permissions:
      android.permission.INTERNET: granted=true
      android.permission.ACCESS_NETWORK_STATE: granted=true
    runtime permissions:
      android.permission.CAMERA: granted=true
      android.permission.ACCESS_FINE_LOCATION: granted=false
      android.permission.CAMERA: granted=true
"""


def test_installed_package_reports_version_uid_flags_and_grants() -> None:
    payload = _backend(_INSTALLED_DUMP).app_info("emulator-5554", "com.example.app")
    assert payload["package"] == "com.example.app"
    assert payload["installed"] is True
    assert payload["version_name"] == "4.5.1"
    assert payload["version_code"] == 4501
    assert payload["min_sdk"] == 23
    assert payload["target_sdk"] == 33
    assert payload["uid"] == 10234
    assert payload["data_dir"] == "/data/user/0/com.example.app"
    assert payload["code_path"] == "/data/app/~~abc==/com.example.app-xyz=="
    assert payload["primary_abi"] == "arm64-v8a"
    assert payload["installer"] == "com.android.vending"
    assert payload["first_install_time"] == "2023-01-02 03:04:05"
    assert payload["last_update_time"] == "2023-06-07 08:09:10"
    assert payload["debuggable"] is True
    assert payload["system"] is False


def test_granted_permissions_are_only_true_deduped_and_sorted() -> None:
    payload = _backend(_INSTALLED_DUMP).app_info("emulator-5554", "com.example.app")
    # granted=false is excluded; CAMERA appears twice but is deduped.
    assert payload["granted_permissions"] == [
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.CAMERA",
        "android.permission.INTERNET",
    ]
    assert payload["granted_permissions_count"] == 3
    assert payload["granted_permissions_has_more"] is False
    assert "android.permission.ACCESS_FINE_LOCATION" not in payload["granted_permissions"]


def test_system_flag_is_true_when_flags_block_says_so() -> None:
    dump = _INSTALLED_DUMP.replace(
        "flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA DEBUGGABLE ]",
        "flags=[ HAS_CODE SYSTEM ]",
    )
    payload = _backend(dump).app_info("emulator-5554", "com.example.app")
    assert payload["system"] is True
    assert payload["debuggable"] is False


def test_missing_field_is_omitted_not_guessed() -> None:
    # A dump without version/flags/grants keeps installed True but names no
    # version_name, no debuggable, and an empty (not absent) grant list.
    dump = "Packages:\n  Package [com.example.app] (a1b2c3):\n    userId=10234\n"
    payload = _backend(dump).app_info("emulator-5554", "com.example.app")
    assert payload["installed"] is True
    assert payload["uid"] == 10234
    assert "version_name" not in payload
    assert "debuggable" not in payload
    assert "system" not in payload
    assert payload["granted_permissions"] == []
    assert payload["granted_permissions_count"] == 0


def test_unknown_package_reports_installed_false() -> None:
    payload = _backend("Unable to find package: com.example.app\n").app_info(
        "emulator-5554", "com.example.app"
    )
    assert payload == {"package": "com.example.app", "installed": False}


def test_unclassifiable_output_reports_installed_null() -> None:
    payload = _backend("some unexpected dumpsys shape\n").app_info(
        "emulator-5554", "com.example.app"
    )
    assert payload == {"package": "com.example.app", "installed": None}


def test_host_error_output_is_a_backend_error_not_a_result() -> None:
    with pytest.raises(AdbError) as excinfo:
        _backend("error: device 'emulator-5554' not found\n").app_info(
            "emulator-5554", "com.example.app"
        )
    assert excinfo.value.code == "backend_error"


def test_docstring_names_installed_and_granted_permissions() -> None:
    doc = _tool_docstring("device.app_info")
    assert "installed" in doc
    assert "granted_permissions" in doc
    assert "dumpsys" in doc
