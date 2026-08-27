"""apk.dex_files parses DEX headers safely and is honest about bad entries."""

from __future__ import annotations

import ast
import struct
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import (
    ApkClient,
    _parse_dex_header,
)
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


def _dex(
    *,
    string_ids: int = 1,
    type_ids: int = 1,
    proto_ids: int = 1,
    field_ids: int = 1,
    method_ids: int = 1,
    class_defs: int = 1,
    data_size: int = 0,
    version: bytes = b"035",
    trailing: int = 0,
) -> bytes:
    head = bytearray(112)
    head[0:8] = b"dex\n" + version + b"\x00"
    head[36:40] = struct.pack("<I", 0x70)
    head[40:44] = b"\x78\x56\x34\x12"
    head[56:112] = struct.pack(
        "<14I",
        string_ids,
        0,
        type_ids,
        0,
        proto_ids,
        0,
        field_ids,
        0,
        method_ids,
        0,
        class_defs,
        0,
        data_size,
        0,
    )
    return bytes(head) + b"\x00" * trailing


class _FakeApk:
    def __init__(self, names: list[str]) -> None:
        self._names = names

    def get_dex_names(self) -> list[str]:
        return list(self._names)


def _client_over(
    tmp_path: Path,
    entries: dict[str, bytes],
    names: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ApkClient, Path]:
    apk_path = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    client = ApkClient()
    client._available = True
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk(names))
    return client, apk_path


def test_parse_dex_header_reads_the_counts() -> None:
    header = _dex(string_ids=11, type_ids=22, method_ids=65500, class_defs=7)
    parsed = _parse_dex_header(header)
    assert parsed is not None
    assert parsed["dex_version"] == "035"
    assert parsed["string_ids"] == 11
    assert parsed["type_ids"] == 22
    assert parsed["method_ids"] == 65500
    assert parsed["class_defs"] == 7


def test_parse_dex_header_rejects_bad_magic_and_short_windows() -> None:
    assert _parse_dex_header(b"NOTADEX!" + b"\x00" * 200) is None
    assert _parse_dex_header(b"dex\n035\x00" + b"\x00" * 10) is None


def test_dex_files_lists_multidex_with_per_dex_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two valid dex files -> multidex, per-dex counts, and the id-table sum."""
    entries = {
        "classes.dex": _dex(method_ids=100, class_defs=5, trailing=32),
        "classes2.dex": _dex(method_ids=200, class_defs=9, trailing=8),
    }
    client, apk_path = _client_over(tmp_path, entries, ["classes2.dex", "classes.dex"], monkeypatch)
    payload = client.dex_files(apk_path)
    assert payload["count"] == 2
    assert payload["multidex"] is True
    # classes.dex sorts before classes2.dex regardless of get_dex_names order.
    assert [item["name"] for item in payload["dex_files"]] == [
        "classes.dex",
        "classes2.dex",
    ]
    first = payload["dex_files"][0]
    assert first["valid"] is True
    assert first["method_ids"] == 100
    assert first["class_defs"] == 5
    assert first["size"] == 112 + 32
    assert payload["method_ids_total"] == 300


def test_dex_files_flags_a_non_dex_entry_without_faking_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entries = {
        "classes.dex": _dex(method_ids=50),
        "classes2.dex": b"PK\x03\x04 not a dex " + b"\x00" * 120,
    }
    client, apk_path = _client_over(tmp_path, entries, ["classes.dex", "classes2.dex"], monkeypatch)
    payload = client.dex_files(apk_path)
    bad = payload["dex_files"][1]
    assert bad["name"] == "classes2.dex"
    assert bad["valid"] is False
    assert "not a DEX" in bad["error"]
    assert "method_ids" not in bad
    # The bad entry contributes nothing to the sum.
    assert payload["method_ids_total"] == 50


def test_dex_files_reports_a_named_entry_missing_from_the_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """get_dex_names can name an entry the zip does not hold; say so."""
    entries = {"classes.dex": _dex(method_ids=10)}
    client, apk_path = _client_over(tmp_path, entries, ["classes.dex", "classes9.dex"], monkeypatch)
    payload = client.dex_files(apk_path)
    ghost = [item for item in payload["dex_files"] if item["name"] == "classes9.dex"][0]
    assert ghost["valid"] is False
    assert "not present" in ghost["error"]
    assert "size" not in ghost


def test_dex_files_of_a_single_dex_is_not_multidex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entries = {"classes.dex": _dex(method_ids=10)}
    client, apk_path = _client_over(tmp_path, entries, ["classes.dex"], monkeypatch)
    payload = client.dex_files(apk_path)
    assert payload["count"] == 1
    assert payload["multidex"] is False


def test_dex_files_description_names_its_fields() -> None:
    doc = _tool_docstring("apk.dex_files")
    assert "method_ids" in doc
    assert "multidex" in doc
    assert "valid" in doc
    assert "112-byte header" in doc
