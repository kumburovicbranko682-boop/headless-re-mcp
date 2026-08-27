"""apk.files must list the archive honestly: sizes, pagination, prefix."""

from __future__ import annotations

import ast
import zipfile
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


class _FakeApk:
    def __init__(self, names: list[str]) -> None:
        self._names = names

    def get_files(self) -> list[str]:
        return self._names


def _client_for(names: list[str]) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk(names)  # type: ignore[method-assign]
    return client


def test_apk_files_lists_names_with_sizes_from_the_central_directory(
    tmp_path: Path,
) -> None:
    """Every entry comes back sorted with its uncompressed size.

    Before this tool the archive contents were invisible short of a full
    apktool decode: native_libs covers lib/ only, and secondary payloads hide
    in assets/. Sizes come from the zip central directory, so nothing is
    decompressed to answer.
    """
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("classes.dex", b"d" * 10)
        archive.writestr("assets/payload.bin", b"p" * 20)
    client = _client_for(["classes.dex", "assets/payload.bin"])
    payload = client.files(apk_path)
    assert payload["files"] == [
        {"name": "assets/payload.bin", "size": 20},
        {"name": "classes.dex", "size": 10},
    ]
    assert payload["total"] == 2
    assert payload["has_more"] is False
    doc = _tool_docstring("apk.files")
    assert "Answers with files" in doc
    assert "has_more" in doc
    assert "prefix" in doc


def test_apk_files_prefix_narrows_and_total_counts_the_narrowed_list(
    tmp_path: Path,
) -> None:
    """prefix scopes the listing and pagination reports the narrowed truth.

    Five assets plus two other entries, prefix assets/ with offset 2 and
    limit 2: the page holds the third and fourth asset, total says five (the
    narrowed list, not the archive), and has_more says one more page exists.
    """
    names = [f"assets/a{index:02d}.bin" for index in range(5)]
    names += ["classes.dex", "res/x.xml"]
    client = _client_for(names)
    payload = client.files(tmp_path / "missing.apk", prefix="assets/", offset=2, limit=2)
    assert [entry["name"] for entry in payload["files"]] == [
        "assets/a02.bin",
        "assets/a03.bin",
    ]
    assert payload["total"] == 5
    assert payload["offset"] == 2
    assert payload["has_more"] is True


def test_apk_files_keeps_names_and_duplicates_when_sizes_cannot_be_read(
    tmp_path: Path,
) -> None:
    """A broken central directory costs the sizes, never the listing.

    The path is not a zip the stdlib can read, so no entry carries size --
    absence means could-not-describe, not zero bytes. The duplicated name is
    kept: entry shadowing is a real hostile-zip signal, not noise to dedup.
    """
    bad = tmp_path / "broken.apk"
    bad.write_bytes(b"not a zip")
    client = _client_for(["classes.dex", "classes.dex"])
    payload = client.files(bad)
    assert [entry["name"] for entry in payload["files"]] == [
        "classes.dex",
        "classes.dex",
    ]
    assert all("size" not in entry for entry in payload["files"])
    assert payload["total"] == 2
