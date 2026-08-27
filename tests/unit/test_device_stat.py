"""device.stat maps the sync STAT record and tells absent from empty."""

from __future__ import annotations

import ast
import datetime
import stat
from pathlib import Path
from types import SimpleNamespace
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


def _backend_over(info: Any, monkeypatch: pytest.MonkeyPatch) -> AdbBackend:
    backend = AdbBackend()

    class _Sync:
        def stat(self, remote: str, **_: Any) -> Any:
            return info

    fake = SimpleNamespace(sync=_Sync())
    monkeypatch.setattr(backend, "_device", lambda serial: fake)
    return backend


def test_stat_maps_a_regular_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """The catalog named mode_string, perm_octal, size and mtime.

    Measured: a 0644 regular file -> type file, mode_string -rw-r--r--,
    perm_octal 0644, no set*id/sticky, and an ISO mtime the device gave.
    """
    when = datetime.datetime(2026, 8, 27, 20, 0, 0)
    info = SimpleNamespace(mode=stat.S_IFREG | 0o644, size=4096, mtime=when)
    backend = _backend_over(info, monkeypatch)
    payload = backend.stat("emulator-5554", "/data/local/tmp/x.so")
    assert payload["exists"] is True
    assert payload["type"] == "file"
    assert payload["size"] == 4096
    assert payload["mode_string"] == "-rw-r--r--"
    assert payload["perm_octal"] == "0644"
    assert payload["setuid"] is False
    assert payload["setgid"] is False
    assert payload["sticky"] is False
    assert payload["mtime"] == when.isoformat()


def test_stat_names_a_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    info = SimpleNamespace(mode=stat.S_IFDIR | 0o755, size=0, mtime=None)
    backend = _backend_over(info, monkeypatch)
    payload = backend.stat("emulator-5554", "/data/local/tmp")
    assert payload["type"] == "directory"
    assert payload["mode_string"] == "drwxr-xr-x"
    assert payload["perm_octal"] == "0755"


def test_stat_flags_a_setuid_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    """A setuid root file is worth noticing; perm_octal keeps the leading bit."""
    info = SimpleNamespace(mode=stat.S_IFREG | stat.S_ISUID | 0o755, size=1, mtime=None)
    backend = _backend_over(info, monkeypatch)
    payload = backend.stat("emulator-5554", "/system/bin/su")
    assert payload["setuid"] is True
    assert payload["perm_octal"] == "4755"
    assert payload["mode_string"] == "-rwsr-xr-x"


def test_stat_reports_a_symlink_as_a_link_not_its_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    info = SimpleNamespace(mode=stat.S_IFLNK | 0o777, size=7, mtime=None)
    backend = _backend_over(info, monkeypatch)
    payload = backend.stat("emulator-5554", "/system/etc/hosts")
    assert payload["type"] == "symlink"
    assert payload["mode_string"].startswith("l")


def test_stat_of_a_missing_path_is_absent_not_an_empty_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """adb's STAT answers a missing path with an all-zero record.

    Reporting mode 0 as a real file of size 0 would read as an existing empty
    file with no permissions; say it is absent instead.
    """
    info = SimpleNamespace(mode=0, size=0, mtime=None)
    backend = _backend_over(info, monkeypatch)
    payload = backend.stat("emulator-5554", "/data/local/tmp/missing")
    assert payload == {"path": "/data/local/tmp/missing", "exists": False}


def test_stat_omits_mtime_when_the_device_gave_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sync mtime of 0 becomes None; leave the field out rather than fake it."""
    info = SimpleNamespace(mode=stat.S_IFREG | 0o600, size=2, mtime=None)
    backend = _backend_over(info, monkeypatch)
    payload = backend.stat("emulator-5554", "/data/local/tmp/y")
    assert "mtime" not in payload
    assert payload["exists"] is True


@pytest.mark.parametrize("bad", ["relative/path", "", "/etc/pass\nwd", "no-slash"])
def test_stat_refuses_a_non_absolute_or_control_char_path(bad: str) -> None:
    """Validation runs before any device round-trip, so a bare backend suffices."""
    backend = AdbBackend()
    with pytest.raises(AdbError) as caught:
        backend.stat("emulator-5554", bad)
    assert caught.value.code == "invalid_params"


def test_stat_description_names_its_honesty(monkeypatch: pytest.MonkeyPatch) -> None:
    del monkeypatch
    doc = _tool_docstring("device.stat")
    assert "exists" in doc
    assert "mode_string" in doc
    assert "sync" in doc
    assert "setuid" in doc
    assert "symlink" in doc.lower()
