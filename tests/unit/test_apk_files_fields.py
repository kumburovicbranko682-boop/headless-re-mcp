"""apk.files lists the whole archive, bucketed, with best-effort sizes.

Exercised through the _apk-injection seam the other apk field tests use, so no
real APK is needed. These pin the categorisation, the central-directory size
lookup (and its null fallback), pagination, and the category roll-up.
"""

from __future__ import annotations

import ast
from pathlib import Path

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


class _Entry:
    def __init__(self, size: int) -> None:
        self.uncompressed_size = size


class _Zip:
    def __init__(self, sizes: dict[str, int]) -> None:
        self._sizes = sizes

    def infolist(self) -> dict[str, _Entry]:
        return {name: _Entry(size) for name, size in self._sizes.items()}


class _FakeApk:
    _NAMES = [
        "AndroidManifest.xml",
        "resources.arsc",
        "classes.dex",
        "classes2.dex",
        "lib/arm64-v8a/libnative.so",
        "res/layout/main.xml",
        "assets/config.json",
        "assets/embedded.apk",
        "kotlin/kotlin.kotlin_builtins",
        "META-INF/CERT.RSA",
        "unknown.bin",
    ]

    def __init__(self, *, with_zip: bool = True) -> None:
        if with_zip:
            self.zip = _Zip({name: 100 for name in self._NAMES})

    def get_files(self) -> list[str]:
        return list(self._NAMES)


def _client_with(apk: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


def test_files_categorises_the_whole_archive() -> None:
    payload = _client_with(_FakeApk()).files(Path("d.apk"))

    assert payload["total"] == 11
    assert payload["categories"] == {
        "manifest": 1,
        "arsc": 1,
        "dex": 2,
        "native_lib": 1,
        "resource": 1,
        "asset": 2,
        "kotlin": 1,
        "signature": 1,
        "other": 1,
    }
    by_name = {row["name"]: row for row in payload["files"]}
    assert by_name["classes2.dex"]["category"] == "dex"
    assert by_name["assets/embedded.apk"]["category"] == "asset"
    assert by_name["lib/arm64-v8a/libnative.so"]["category"] == "native_lib"


def test_files_reports_sizes_from_the_central_directory() -> None:
    payload = _client_with(_FakeApk()).files(Path("d.apk"))
    assert all(row["size"] == 100 for row in payload["files"])
    assert payload["total_uncompressed"] == 1100


def test_files_sizes_are_null_when_the_zip_is_unavailable() -> None:
    """No central directory -> size null, never read by inflating each entry."""
    payload = _client_with(_FakeApk(with_zip=False)).files(Path("d.apk"))
    assert all(row["size"] is None for row in payload["files"])
    assert payload["total_uncompressed"] == 0
    # Categorisation still works without sizes.
    assert payload["categories"]["dex"] == 2


def test_files_pages_the_listing() -> None:
    payload = _client_with(_FakeApk()).files(Path("d.apk"), offset=0, limit=3)
    assert payload["count"] == 3
    assert payload["total"] == 11
    assert payload["has_more"] is True
    # Names are sorted, so the page is stable across calls.
    second = _client_with(_FakeApk()).files(Path("d.apk"), offset=3, limit=3)
    assert second["offset"] == 3
    assert payload["files"][0]["name"] < second["files"][0]["name"]


def test_files_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.files")
    assert "categories" in doc
    assert "total_uncompressed" in doc
    assert "native_lib" in doc
    assert "has_more" in doc
