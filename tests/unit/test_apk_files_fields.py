"""apk.files lists every zip entry with honest, bounded, degradable sizes."""

from __future__ import annotations

import ast
import io
import zipfile
from pathlib import Path
from typing import Any

import headless_re_mcp.backends.apk.client as apk_client
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


class _CDE:
    """A central-directory entry shaped like androguard 4.x's."""

    def __init__(self, filename: str, uncompressed_size: int, compressed_size: int) -> None:
        self.filename = filename
        self.uncompressed_size = uncompressed_size
        self.compressed_size = compressed_size


class _DictZip:
    def __init__(self, entries: list[_CDE]) -> None:
        self._entries = {entry.filename: entry for entry in entries}

    def infolist(self) -> dict[str, _CDE]:
        return self._entries


class _ApkDict:
    def __init__(self, names: list[str], entries: list[_CDE]) -> None:
        self._names = names
        self.zip = _DictZip(entries)

    def get_files(self) -> list[str]:
        return list(self._names)


def _bind(client: ApkClient, apk: Any) -> None:
    client._apk = lambda _path: apk  # type: ignore[method-assign]


def test_apk_files_lists_entries_with_sizes_from_the_central_directory() -> None:
    names = ["classes.dex", "AndroidManifest.xml", "lib/arm64-v8a/libfoo.so", "assets/config.json"]
    entries = [
        _CDE("classes.dex", 107, 12),
        _CDE("AndroidManifest.xml", 10, 8),
        _CDE("lib/arm64-v8a/libfoo.so", 504, 40),
        _CDE("assets/config.json", 7, 9),
    ]
    client = ApkClient()
    _bind(client, _ApkDict(names, entries))

    payload = client.files(Path("x.apk"))

    assert [item["name"] for item in payload["files"]] == sorted(names)
    dex = next(item for item in payload["files"] if item["name"] == "classes.dex")
    assert dex["size"] == 107
    assert dex["compressed"] == 12
    assert payload["count"] == 4
    assert payload["total"] == 4
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False

    doc = _tool_docstring("apk.files")
    for token in ("files", "size", "compressed", "total", "has_more", "scan_capped"):
        assert token in doc


class _RealZipApk:
    def __init__(self, raw: bytes) -> None:
        self.zip = zipfile.ZipFile(io.BytesIO(raw))

    def get_files(self) -> list[str]:
        return self.zip.namelist()


def test_apk_files_reads_sizes_from_a_stdlib_zipfile() -> None:
    """The older androguard exposed a stdlib ZipFile: ZipInfo, not our CDE."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("classes.dex", b"d" * 200)
        archive.writestr("assets/a.json", b"{}")
    client = ApkClient()
    _bind(client, _RealZipApk(buf.getvalue()))

    payload = client.files(Path("x.apk"))

    dex = next(item for item in payload["files"] if item["name"] == "classes.dex")
    assert dex["size"] == 200
    assert "compressed" in dex


def test_apk_files_omits_size_when_the_directory_lacks_the_entry() -> None:
    """A missing directory row leaves the entry sizeless, not zero-byte."""
    client = ApkClient()
    _bind(client, _ApkDict(["classes.dex", "stub.txt"], [_CDE("classes.dex", 100, 50)]))

    payload = client.files(Path("x.apk"))

    stub = next(item for item in payload["files"] if item["name"] == "stub.txt")
    assert stub == {"name": "stub.txt"}


class _RaisingZip:
    def infolist(self) -> Any:
        raise RuntimeError("zip internal shape not recognised")


class _ApkRaise:
    def __init__(self, names: list[str]) -> None:
        self._names = names
        self.zip = _RaisingZip()

    def get_files(self) -> list[str]:
        return list(self._names)


def test_apk_files_degrades_to_names_when_sizes_are_unavailable() -> None:
    client = ApkClient()
    _bind(client, _ApkRaise(["a.dex", "b.so"]))

    payload = client.files(Path("x.apk"))

    assert [item["name"] for item in payload["files"]] == ["a.dex", "b.so"]
    assert all(set(item) == {"name"} for item in payload["files"])


def test_apk_files_pages_the_sorted_list() -> None:
    names = [f"f{index:03d}.bin" for index in range(5)]
    client = ApkClient()
    _bind(client, _ApkDict(names, []))

    page = client.files(Path("x.apk"), offset=0, limit=2)
    assert [item["name"] for item in page["files"]] == ["f000.bin", "f001.bin"]
    assert page["total"] == 5
    assert page["offset"] == 0
    assert page["has_more"] is True

    tail = client.files(Path("x.apk"), offset=4, limit=2)
    assert [item["name"] for item in tail["files"]] == ["f004.bin"]
    assert tail["has_more"] is False


def test_apk_files_reports_scan_capped_when_the_archive_is_huge(monkeypatch: Any) -> None:
    monkeypatch.setattr(apk_client, "_MAX_FILES_COLLECT", 3)
    client = ApkClient()
    _bind(client, _ApkDict([f"f{index}.bin" for index in range(10)], []))

    payload = client.files(Path("x.apk"))

    assert payload["scan_capped"] is True
    assert payload["total"] == 3
