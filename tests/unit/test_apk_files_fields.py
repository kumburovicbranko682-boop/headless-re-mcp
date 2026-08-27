"""apk.files lists the whole APK archive with sizes, not only lib/*.so.

apk.native_libs reports only native libraries; assets, raw resources, extra
DEX and embedded payloads were invisible short of unpacking. These pin the new
reader's shape: a name/size/compressed_size list sorted for stable paging,
null sizes for a name the central directory does not describe (and if the
directory cannot be read at all), and the collection cap surfaced as
scan_capped. The docstring must name the fields the parser returns.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _FakeCDEntry:
    def __init__(self, uncompressed: int, compressed: int) -> None:
        self.uncompressed_size = uncompressed
        self.compressed_size = compressed


class _FakeZip:
    def __init__(self, infos: dict[str, _FakeCDEntry], *, raises: bool = False) -> None:
        self._infos = infos
        self._raises = raises

    def infolist(self) -> dict[str, _FakeCDEntry]:
        if self._raises:
            raise RuntimeError("bad central directory")
        return self._infos


class _FakeApk:
    def __init__(self, names: list[str], zip_obj: _FakeZip) -> None:
        self._names = names
        self.zip = zip_obj

    def get_files(self) -> list[str]:
        return self._names


def _client_with(names: list[str], infos: dict[str, _FakeCDEntry], **kw: Any) -> ApkClient:
    client = ApkClient()
    apk = _FakeApk(names, _FakeZip(infos, **kw))
    client._apk = lambda _path: apk  # type: ignore[method-assign, assignment]
    return client


def test_files_lists_entries_with_sizes_sorted_by_name() -> None:
    names = ["res/raw/config.json", "assets/data.bin", "classes.dex"]
    infos = {
        "assets/data.bin": _FakeCDEntry(1000, 400),
        "classes.dex": _FakeCDEntry(2048, 900),
        "res/raw/config.json": _FakeCDEntry(64, 40),
    }
    client = _client_with(names, infos)
    payload = client.files(Path("dummy.apk"), offset=0, limit=100)
    assert "libs" not in payload
    assert "entries" not in payload
    listed = [e["name"] for e in payload["files"]]
    assert listed == ["assets/data.bin", "classes.dex", "res/raw/config.json"]
    first = payload["files"][0]
    assert first == {"name": "assets/data.bin", "size": 1000, "compressed_size": 400}
    assert payload["count"] == 3
    assert payload["total"] == 3
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_files_reports_null_sizes_for_a_name_absent_from_the_directory() -> None:
    """A name in get_files() with no central-directory entry keeps its row."""
    names = ["assets/only_name"]
    client = _client_with(names, {})
    payload = client.files(Path("dummy.apk"), offset=0, limit=10)
    assert payload["files"] == [
        {"name": "assets/only_name", "size": None, "compressed_size": None}
    ]


def test_files_survives_an_unreadable_central_directory() -> None:
    names = ["a", "b"]
    client = _client_with(names, {}, raises=True)
    payload = client.files(Path("dummy.apk"), offset=0, limit=10)
    assert payload["count"] == 2
    assert all(entry["size"] is None for entry in payload["files"])


def test_files_pagination_reports_has_more() -> None:
    names = [f"f{index:03d}" for index in range(25)]
    infos = {name: _FakeCDEntry(index, index) for index, name in enumerate(names)}
    client = _client_with(names, infos)
    payload = client.files(Path("dummy.apk"), offset=0, limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True
    page2 = client.files(Path("dummy.apk"), offset=10, limit=10)
    assert page2["files"][0]["name"] == "f010"


def test_files_scan_capped_when_collection_hits_the_cap(monkeypatch: Any) -> None:
    monkeypatch.setattr(apk_client, "_MAX_FILES_COLLECT", 5)
    names = [f"f{index:03d}" for index in range(20)]
    client = _client_with(names, {})
    payload = client.files(Path("dummy.apk"), offset=0, limit=100)
    assert payload["total"] == 5
    assert payload["scan_capped"] is True


def test_files_docstring_names_the_returned_fields() -> None:
    doc = _tool_docstring("apk.files")
    assert "Answers with files" in doc
    assert "compressed_size" in doc
    assert "has_more" in doc
