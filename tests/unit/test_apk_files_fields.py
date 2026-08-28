"""apk.files inventories the APK zip with per-entry size and coarse type.

Like the other apk.* field tests it mocks the cheap _apk parse, so it needs no
androguard or JRE. It pins the path-based classification, the size/total sums
read from the (mocked) central directory, sorting, pagination, graceful handling
when the central directory is unreadable, the collection cap, plus the tool
docstring.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp.backends.apk.client as client_module
from headless_re_mcp.backends.apk.client import ApkClient, _classify_apk_file
from headless_re_mcp.tools.apk import build_apk_tools

_FILES = [
    "classes.dex",
    "classes2.dex",
    "lib/arm64-v8a/libfoo.so",
    "res/layout/main.xml",
    "assets/config.json",
    "resources.arsc",
    "AndroidManifest.xml",
    "META-INF/CERT.RSA",
    "META-INF/CERT.SF",
    "META-INF/MANIFEST.MF",
    "META-INF/kotlin.kotlin_module",
    "root_file.txt",
]


class _Entry:
    def __init__(self, uncompressed_size: int, compressed_size: int) -> None:
        self.uncompressed_size = uncompressed_size
        self.compressed_size = compressed_size


class _Zip:
    def __init__(self, info: dict[str, _Entry], *, raise_exc: bool = False) -> None:
        self._info = info
        self._raise = raise_exc

    def infolist(self) -> dict[str, _Entry]:
        if self._raise:
            raise RuntimeError("central directory unreadable")
        return self._info


class _FakeApk:
    def __init__(
        self,
        files: list[str] | None = None,
        info: dict[str, _Entry] | None = None,
        *,
        raise_infolist: bool = False,
    ) -> None:
        self._files = _FILES if files is None else files
        self.zip = _Zip(info or {}, raise_exc=raise_infolist)

    def get_package(self) -> str:
        return "com.example.app"

    def get_files(self) -> list[str]:
        return list(self._files)


def _client(apk: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


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


def test_classify_covers_every_bucket() -> None:
    assert _classify_apk_file("AndroidManifest.xml") == "manifest"
    assert _classify_apk_file("resources.arsc") == "arsc"
    assert _classify_apk_file("classes.dex") == "dex"
    assert _classify_apk_file("classes9.dex") == "dex"
    assert _classify_apk_file("lib/x86/libc.so") == "native_lib"
    assert _classify_apk_file("res/layout/a.xml") == "resource"
    assert _classify_apk_file("assets/x/y.json") == "asset"
    assert _classify_apk_file("META-INF/CERT.RSA") == "signature"
    assert _classify_apk_file("META-INF/MANIFEST.MF") == "signature"
    assert _classify_apk_file("META-INF/foo.kotlin_module") == "other"
    assert _classify_apk_file("top.txt") == "other"


def test_counts_over_the_whole_archive() -> None:
    payload = _client(_FakeApk()).files(Path("d.apk"), limit=1000)
    assert payload["total"] == 12
    assert payload["counts"] == {
        "dex": 2,
        "native_lib": 1,
        "resource": 1,
        "asset": 1,
        "arsc": 1,
        "manifest": 1,
        "signature": 3,
        "other": 2,
    }


def test_sizes_and_totals_from_central_directory() -> None:
    info = {
        "classes.dex": _Entry(1000, 400),
        "lib/arm64-v8a/libfoo.so": _Entry(2000, 800),
    }
    payload = _client(_FakeApk(info=info)).files(Path("d"), limit=1000)
    by_name = {row["name"]: row for row in payload["files"]}
    assert by_name["classes.dex"]["size"] == 1000
    assert by_name["classes.dex"]["compressed_size"] == 400
    assert by_name["lib/arm64-v8a/libfoo.so"]["size"] == 2000
    # An entry absent from the central directory reports null sizes.
    assert by_name["resources.arsc"]["size"] is None
    assert by_name["resources.arsc"]["compressed_size"] is None
    # Totals sum only the readable entries.
    assert payload["total_size"] == 3000
    assert payload["total_compressed_size"] == 1200


def test_files_are_sorted_by_name() -> None:
    names = [row["name"] for row in _client(_FakeApk()).files(Path("d"), limit=1000)["files"]]
    assert names == sorted(names)


def test_pagination_windows_the_listing() -> None:
    first = _client(_FakeApk()).files(Path("d"), offset=0, limit=5)
    assert first["count"] == 5
    assert first["total"] == 12
    assert first["has_more"] is True
    assert first["offset"] == 0
    tail = _client(_FakeApk()).files(Path("d"), offset=10, limit=5)
    assert tail["count"] == 2
    assert tail["has_more"] is False


def test_unreadable_central_directory_degrades_to_null_sizes() -> None:
    payload = _client(_FakeApk(raise_infolist=True)).files(Path("d"), limit=1000)
    assert payload["total"] == 12
    assert payload["total_size"] == 0
    assert all(row["size"] is None for row in payload["files"])


def test_collection_cap_sets_scan_capped(monkeypatch) -> None:
    monkeypatch.setattr(client_module, "_MAX_FILES_COLLECT", 3)
    payload = _client(_FakeApk()).files(Path("d"), limit=1000)
    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.files")
    assert "Answers with files" in doc
    assert "counts" in doc and "total_size" in doc
    assert "compressed_size" in doc
    assert "has_more" in doc
