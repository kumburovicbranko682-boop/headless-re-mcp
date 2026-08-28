"""apk.dex_headers parses each classesN.dex header (version + id counts)."""

from __future__ import annotations

import ast
import struct
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient, _parse_dex_header
from headless_re_mcp.tools.apk import build_apk_tools


def _make_dex(
    *,
    version: str = "035",
    checksum: int = 0xDEADBEEF,
    file_size: int = 112,
    string_count: int = 10,
    type_count: int = 5,
    proto_count: int = 3,
    field_count: int = 4,
    method_count: int = 8,
    class_def_count: int = 2,
    data_size: int = 100,
) -> bytes:
    buf = bytearray(112)
    buf[0:4] = b"dex\n"
    buf[4:7] = version.encode("ascii")
    buf[7] = 0
    struct.pack_into("<I", buf, 8, checksum)
    struct.pack_into("<I", buf, 32, file_size)
    struct.pack_into("<I", buf, 36, 0x70)
    struct.pack_into("<I", buf, 40, 0x12345678)
    struct.pack_into("<I", buf, 56, string_count)
    struct.pack_into("<I", buf, 64, type_count)
    struct.pack_into("<I", buf, 72, proto_count)
    struct.pack_into("<I", buf, 80, field_count)
    struct.pack_into("<I", buf, 88, method_count)
    struct.pack_into("<I", buf, 96, class_def_count)
    struct.pack_into("<I", buf, 104, data_size)
    return bytes(buf)


class _FakeApk:
    def __init__(self, names: list[str], dexes: list[bytes]) -> None:
        self._names = names
        self._dexes = dexes

    def get_dex_names(self) -> list[str]:
        return self._names

    def get_all_dex(self) -> list[bytes]:
        return self._dexes


def _client_over(fake: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._apk = lambda path: fake  # type: ignore[method-assign]
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


def test_parse_dex_header_reads_counts() -> None:
    header = _parse_dex_header(_make_dex(version="038", string_count=42))
    assert header["valid"] is True
    assert header["version"] == "038"
    assert header["checksum"] == "deadbeef"
    assert header["string_count"] == 42
    assert header["class_def_count"] == 2
    assert header["method_count"] == 8
    assert header["data_size"] == 100


def test_parse_dex_header_rejects_non_dex() -> None:
    assert _parse_dex_header(b"PK\x03\x04not a dex")["valid"] is False
    # Right magic but too short for the full header: version reads, counts do not.
    short = _parse_dex_header(b"dex\n035\x00" + b"\x00" * 4)
    assert short["valid"] is False
    assert short["version"] == "035"
    assert short["string_count"] is None


def test_dex_headers_single_dex() -> None:
    fake = _FakeApk(["classes.dex"], [_make_dex(class_def_count=7, method_count=20)])
    result = _client_over(fake).dex_headers(Path("app.apk"))
    assert result["dex_count"] == 1
    assert result["multidex"] is False
    assert result["total_classes"] == 7
    assert result["total_methods"] == 20
    assert result["dex_files"][0]["name"] == "classes.dex"


def test_dex_headers_multidex_sums_valid_entries() -> None:
    fake = _FakeApk(
        ["classes.dex", "classes2.dex"],
        [
            _make_dex(class_def_count=3, method_count=10, string_count=100),
            _make_dex(class_def_count=4, method_count=15, string_count=200),
        ],
    )
    result = _client_over(fake).dex_headers(Path("app.apk"))
    assert result["dex_count"] == 2
    assert result["multidex"] is True
    assert result["total_classes"] == 7
    assert result["total_methods"] == 25
    assert result["total_strings"] == 300
    assert [e["name"] for e in result["dex_files"]] == ["classes.dex", "classes2.dex"]


def test_dex_headers_skips_malformed_dex_in_totals() -> None:
    fake = _FakeApk(
        ["classes.dex", "classes2.dex"],
        [_make_dex(class_def_count=5), b"garbage-not-a-dex"],
    )
    result = _client_over(fake).dex_headers(Path("app.apk"))
    assert result["dex_count"] == 2
    assert result["total_classes"] == 5  # the garbage dex contributes nothing
    assert result["dex_files"][1]["valid"] is False
    assert result["dex_files"][1]["name"] == "classes2.dex"


def test_dex_headers_names_unnamed_by_index() -> None:
    fake = _FakeApk([], [_make_dex()])
    result = _client_over(fake).dex_headers(Path("app.apk"))
    assert result["dex_files"][0]["name"] == "dex[0]"


def test_dex_headers_survives_androguard_errors() -> None:
    class _Boom:
        def get_dex_names(self) -> Any:
            raise RuntimeError("boom")

        def get_all_dex(self) -> Any:
            raise RuntimeError("boom")

    result = _client_over(_Boom()).dex_headers(Path("app.apk"))  # type: ignore[arg-type]
    assert result["dex_count"] == 0
    assert result["dex_files"] == []


def test_apk_dex_headers_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.dex_headers")
    assert "dex_files" in doc
    assert "multidex" in doc
    assert "version" in doc
