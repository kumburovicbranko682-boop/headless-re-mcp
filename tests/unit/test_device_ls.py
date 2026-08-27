"""device.ls lists a device directory honestly and refuses unsafe paths.

The listing is driven entirely by ``ls -1ap`` text, so it is pinned here with an
injected fake device -- no adbutils, no emulator -- exactly where the parsing
and the path validation live.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError, _check_ls_path
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


class _ScriptedDev:
    def __init__(self, output: str) -> None:
        self._output = output
        self.calls: list[str] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.calls.append(args if isinstance(args, str) else " ".join(args))
        return self._output


def _backend_with(dev: _ScriptedDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_device_ls_lists_entries_with_dir_flags_sorted() -> None:
    """Directories carry is_dir True; . and .. are dropped; names come sorted.

    Measured: a mixed listing with ./ ../ filtered -> five entries, the ones
    ls marked with a trailing / reported as is_dir, and the fixed command was
    ``ls -1ap <path>`` with only the path varying.
    """
    out = "\n".join(["./", "../", "shared_prefs/", "databases/", "somefile.txt", ".hidden", "lib/"])
    dev = _ScriptedDev(out)
    backend = _backend_with(dev)
    payload = backend.list_dir("emulator-5554", "/data/data/com.example", offset=0, limit=50)
    names = [entry["name"] for entry in payload["entries"]]
    assert names == [".hidden", "databases", "lib", "shared_prefs", "somefile.txt"]
    is_dir = {entry["name"]: entry["is_dir"] for entry in payload["entries"]}
    assert is_dir["databases"] is True
    assert is_dir["lib"] is True
    assert is_dir["shared_prefs"] is True
    assert is_dir["somefile.txt"] is False
    assert is_dir[".hidden"] is False
    assert payload["path"] == "/data/data/com.example"
    assert payload["total"] == 5
    assert payload["count"] == 5
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert dev.calls == ["ls -1ap /data/data/com.example"]
    doc = _tool_docstring("device.ls")
    assert "entries" in doc
    assert "is_dir" in doc
    assert "has_more" in doc


def test_device_ls_reports_an_empty_directory_as_total_zero() -> None:
    """A directory with only . and .. is a real empty listing, not an error."""
    payload = _backend_with(_ScriptedDev("./\n../\n")).list_dir("emulator-5554", "/data/local/tmp")
    assert payload["entries"] == []
    assert payload["total"] == 0
    assert payload["count"] == 0
    assert payload["has_more"] is False


def test_device_ls_raises_not_found_for_a_missing_path() -> None:
    dev = _ScriptedDev("ls: /nope: No such file or directory")
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).list_dir("emulator-5554", "/nope")
    assert caught.value.code == "not_found"


def test_device_ls_raises_permission_denied() -> None:
    dev = _ScriptedDev("ls: /data/data/com.other: Permission denied")
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).list_dir("emulator-5554", "/data/data/com.other")
    assert caught.value.code == "permission_denied"


def test_device_ls_raises_for_a_non_directory() -> None:
    dev = _ScriptedDev("ls: /system/build.prop/x: Not a directory")
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).list_dir("emulator-5554", "/system/build.prop/x")
    assert caught.value.code == "invalid_params"


def test_device_ls_paginates() -> None:
    out = "\n".join(f"file{index:03d}.bin" for index in range(25))
    backend = _backend_with(_ScriptedDev(out))
    page0 = backend.list_dir("emulator-5554", "/sdcard", offset=0, limit=10)
    assert page0["count"] == 10
    assert page0["total"] == 25
    assert page0["has_more"] is True
    tail = backend.list_dir("emulator-5554", "/sdcard", offset=20, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False


@pytest.mark.parametrize(
    "path",
    [
        "",
        "relative/path",
        "/data/local/tmp; rm -rf /",
        "/x$(whoami)",
        "/a`id`",
        "/p|q",
        "/with space",
        "/a&b",
        "/a>b",
        "/glob*",
        '/a"b',
        "/a'b",
    ],
)
def test_device_ls_rejects_hostile_paths(path: str) -> None:
    with pytest.raises(AdbError) as caught:
        _check_ls_path(path)
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/data/local/tmp",
        "/data/data/com.example.app",
        "/sdcard/Download",
        "/system/lib64",
        "/data/app/~~aBcD==/com.foo-1/base.apk",
    ],
)
def test_device_ls_accepts_safe_absolute_paths(path: str) -> None:
    assert _check_ls_path(path) == path
