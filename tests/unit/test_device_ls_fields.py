"""device.ls browses the device filesystem to find the file worth pulling.

device.package_paths/device.processes tell you which app or process; device.ls
lists a directory over the adb file-sync LIST/STAT channel (not a shell) so
device.pull can then fetch a specific sqlite db / shared_prefs xml / token cache.
These cover the typed+sorted listing, the dot-entry skip, the file-path case, the
not-found and invalid-path refusals, the collection cap and paging, the octal
mode shaping, the empty (inaccessible) directory, service routing, and read-only.
"""

from __future__ import annotations

import ast
import datetime
import stat
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


class _FI:
    """A stand-in for adbutils FileInfo (mode, size, mtime, path)."""

    def __init__(self, mode: int, size: int, mtime: Any, path: str) -> None:
        self.mode = mode
        self.size = size
        self.mtime = mtime
        self.path = path


class _Sync:
    def __init__(self, stat_info: _FI, listing: list[_FI]) -> None:
        self._stat = stat_info
        self._listing = listing
        self.calls: list[tuple[str, str]] = []

    def stat(self, path: str) -> _FI:
        self.calls.append(("stat", path))
        return self._stat

    def list(self, path: str) -> list[_FI]:
        self.calls.append(("list", path))
        return self._listing


class _Dev:
    def __init__(self, sync: _Sync) -> None:
        self.sync = sync


def _backend(sync: _Sync) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _Dev(sync)  # type: ignore[method-assign]
    return backend


_DIR = _FI(stat.S_IFDIR | 0o755, 4096, None, "/sdcard")
_MTIME = datetime.datetime(2021, 6, 1, 12, 0, 0)


def test_ls_lists_directory_entries_typed_and_dirs_first() -> None:
    listing = [
        _FI(stat.S_IFREG | 0o644, 12, _MTIME, "app.db"),
        _FI(stat.S_IFDIR | 0o755, 4096, _MTIME, "cache"),
        _FI(stat.S_IFLNK | 0o777, 7, None, "link"),
    ]
    out = _backend(_Sync(_DIR, listing)).ls("emulator-5554", "/sdcard")
    assert out["is_dir"] is True
    assert out["path"] == "/sdcard"
    assert out["count"] == 3
    assert out["total"] == 3
    # Directories first, then by name.
    assert [e["name"] for e in out["entries"]] == ["cache", "app.db", "link"]
    kinds = {e["name"]: e["type"] for e in out["entries"]}
    assert kinds == {"cache": "dir", "app.db": "file", "link": "symlink"}
    db = next(e for e in out["entries"] if e["name"] == "app.db")
    assert db["size"] == 12
    assert db["mode"] == "0644"
    assert db["mtime"] == int(_MTIME.timestamp())
    # An entry the device reported without an mtime keeps that field off.
    link = next(e for e in out["entries"] if e["name"] == "link")
    assert "mtime" not in link


def test_ls_skips_dot_and_dotdot() -> None:
    listing = [
        _FI(stat.S_IFDIR | 0o755, 4096, _MTIME, "."),
        _FI(stat.S_IFDIR | 0o755, 4096, _MTIME, ".."),
        _FI(stat.S_IFREG | 0o600, 1, _MTIME, "real"),
    ]
    out = _backend(_Sync(_DIR, listing)).ls("emulator-5554", "/sdcard")
    assert [e["name"] for e in out["entries"]] == ["real"]


def test_ls_on_a_file_lists_just_itself() -> None:
    file_info = _FI(stat.S_IFREG | 0o640, 2048, _MTIME, "/data/local/tmp/x.db")
    out = _backend(_Sync(file_info, [])).ls("emulator-5554", "/data/local/tmp/x.db")
    assert out["is_dir"] is False
    assert out["count"] == 1
    row = out["entries"][0]
    assert row["name"] == "x.db"
    assert row["type"] == "file"
    assert row["mode"] == "0640"
    assert row["size"] == 2048


def test_ls_not_found_when_stat_reports_mode_zero() -> None:
    missing = _FI(0, 0, None, "/nope")
    with pytest.raises(AdbError) as info:
        _backend(_Sync(missing, [])).ls("emulator-5554", "/nope")
    assert info.value.code == "not_found"


def test_ls_empty_directory_is_ok_not_an_error() -> None:
    # An app-private dir adbd cannot read reports no entries, not a fault.
    out = _backend(_Sync(_DIR, [])).ls("emulator-5554", "/data/data/com.x")
    assert out["is_dir"] is True
    assert out["entries"] == []
    assert out["count"] == 0
    assert out["total"] == 0
    assert out["has_more"] is False


@pytest.mark.parametrize("bad", ["relative/path", "", "   ", "/with\x00nul", "/ctrl\x01char"])
def test_ls_invalid_path_is_refused_before_the_device(bad: str) -> None:
    def boom(serial: str) -> Any:  # pragma: no cover - must never run
        del serial
        raise AssertionError("an invalid path must be refused before _device")

    backend = AdbBackend()
    backend._available = True
    backend._device = boom  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend.ls("emulator-5554", bad)
    assert info.value.code == "invalid_params"


def test_ls_caps_a_pathological_directory(monkeypatch: Any) -> None:
    monkeypatch.setattr(adb_client, "_MAX_LS_ENTRIES", 2)
    listing = [_FI(stat.S_IFREG | 0o644, 1, _MTIME, f"f{i}") for i in range(5)]
    out = _backend(_Sync(_DIR, listing)).ls("emulator-5554", "/sdcard", limit=1000)
    assert out["total"] == 2
    assert out["collection_truncated"] is True


def test_ls_pages_with_offset_and_limit() -> None:
    listing = [_FI(stat.S_IFREG | 0o644, 1, _MTIME, f"f{i}") for i in range(5)]
    out = _backend(_Sync(_DIR, listing)).ls("emulator-5554", "/sdcard", offset=1, limit=2)
    assert out["offset"] == 1
    assert out["count"] == 2
    assert out["total"] == 5
    assert out["has_more"] is True
    assert [e["name"] for e in out["entries"]] == ["f1", "f2"]


def test_ls_reads_over_sync_not_a_shell() -> None:
    """The path reaches the sync stat/list calls, never a device shell."""
    sync = _Sync(_DIR, [_FI(stat.S_IFREG | 0o644, 1, _MTIME, "a")])
    _backend(sync).ls("emulator-5554", "/sdcard/Download")
    assert ("stat", "/sdcard/Download") in sync.calls
    assert ("list", "/sdcard/Download") in sync.calls


def test_service_device_ls_routes_to_the_owned_backend() -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        calls: list[Any] = []

        def fake(serial: str, *, path: str, offset: int, limit: int) -> Any:
            calls.append((serial, path, offset, limit))
            return {
                "path": path,
                "is_dir": True,
                "entries": [{"name": "a", "type": "file", "size": 1, "mode": "0644"}],
                "count": 1,
                "total": 1,
                "offset": 0,
                "has_more": False,
            }

        service._adb_backend.ls = fake  # type: ignore[method-assign]
        result = service.device_ls("emulator-5554", "/sdcard", offset=0, limit=50)
        assert result.ok and result.data is not None
        assert result.data["entries"][0]["name"] == "a"
        assert calls == [("emulator-5554", "/sdcard", 0, 50)]
    finally:
        service.close_all()


def test_ls_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("device.ls").split())
    assert "device.pull" in doc
    assert "entries" in doc
    assert "sync" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "device.ls" in _READ_ONLY_NAMES
