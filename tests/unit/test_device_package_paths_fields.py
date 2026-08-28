"""device.package_paths locates an installed app's APK(s) on the device.

device.packages reports only names; device.package_paths runs `pm path` to
return the on-device APK path(s) -- the base APK plus every split -- so
device.pull can fetch the file and the apk.* tools can analyse it, bridging the
dynamic device line to the static apk line. These cover the base+split parse,
the base_apk pick, the not-installed and invalid-id refusals, the path cap, the
argv (no-shell-injection) contract, service routing, and read-only class.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adb_client
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


class _Dev:
    """A device whose shell() returns canned pm-path output and records argv."""

    def __init__(self, output: str, calls: list[Any] | None = None) -> None:
        self._output = output
        self._calls = calls if calls is not None else []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self._calls.append(args)
        return self._output


def _backend(output: str, calls: list[Any] | None = None) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _Dev(output, calls)  # type: ignore[method-assign]
    return backend


def test_package_paths_lists_base_and_splits() -> None:
    output = (
        "package:/data/app/~~ab==/com.x-1/base.apk\n"
        "package:/data/app/~~ab==/com.x-1/split_config.arm64_v8a.apk\n"
        "package:/data/app/~~ab==/com.x-1/split_config.xxhdpi.apk\n"
    )
    payload = _backend(output).package_paths("emulator-5554", "com.x")
    assert payload["package"] == "com.x"
    assert payload["count"] == 3
    assert payload["split"] is True
    assert payload["base_apk"] == "/data/app/~~ab==/com.x-1/base.apk"
    assert payload["paths"][0] == "/data/app/~~ab==/com.x-1/base.apk"
    assert "paths_truncated" not in payload


def test_package_paths_single_base_is_not_split() -> None:
    payload = _backend("package:/data/app/com.y-1/base.apk\n").package_paths(
        "emulator-5554", "com.y"
    )
    assert payload["count"] == 1
    assert payload["split"] is False
    assert payload["base_apk"] == "/data/app/com.y-1/base.apk"


def test_package_paths_base_apk_falls_back_to_first_path() -> None:
    # No member literally named base.apk: base_apk is the first path, not empty.
    output = (
        "package:/system/app/Foo/Foo.apk\n"
        "package:/system/app/Foo/split_x.apk\n"
    )
    payload = _backend(output).package_paths("emulator-5554", "com.foo")
    assert payload["base_apk"] == "/system/app/Foo/Foo.apk"


def test_package_paths_not_installed_is_not_found() -> None:
    # pm path prints nothing for a package that is not installed.
    with pytest.raises(AdbError) as info:
        _backend("").package_paths("emulator-5554", "com.absent")
    assert info.value.code == "not_found"


def test_package_paths_invalid_id_is_refused_before_the_device() -> None:
    def boom(serial: str) -> Any:  # pragma: no cover - must never run
        del serial
        raise AssertionError("an invalid package id must be refused before _device")

    backend = AdbBackend()
    backend._available = True
    backend._device = boom  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend.package_paths("emulator-5554", "com.evil; rm -rf /")
    assert info.value.code == "invalid_params"


def test_package_paths_passes_the_id_as_argv_not_a_shell_string() -> None:
    """The id reaches pm path as a list element, so it cannot inject a command."""
    calls: list[Any] = []
    _backend("package:/data/app/com.z-1/base.apk\n", calls).package_paths(
        "emulator-5554", "com.z"
    )
    assert calls == [["pm", "path", "com.z"]]


def test_package_paths_caps_a_pathological_count(monkeypatch: Any) -> None:
    monkeypatch.setattr(adb_client, "_MAX_PACKAGE_PATHS", 3)
    output = "".join(
        f"package:/data/app/com.big-1/split_{index}.apk\n" for index in range(6)
    )
    payload = _backend(output).package_paths("emulator-5554", "com.big")
    assert payload["count"] == 3
    assert payload["paths_truncated"] is True


def test_service_device_package_paths_routes_to_the_owned_backend() -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        calls: list[tuple[str, str]] = []
        service._adb_backend.package_paths = (  # type: ignore[method-assign]
            lambda serial, package: calls.append((serial, package))
            or {"package": package, "paths": ["/a/base.apk"], "count": 1,
                "base_apk": "/a/base.apk", "split": False}
        )
        result = service.device_package_paths("emulator-5554", "com.x")
        assert result.ok and result.data is not None
        assert result.data["base_apk"] == "/a/base.apk"
        assert calls == [("emulator-5554", "com.x")]
    finally:
        service.close_all()


def test_package_paths_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("device.package_paths").split())
    assert "base_apk" in doc
    assert "device.pull" in doc
    assert "not_found" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "device.package_paths" in _READ_ONLY_NAMES
