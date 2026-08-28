"""apk.files lists the whole archive and names members by magic, not extension.

apk.native_libs only enumerates lib/*.so; a bundled payload -- a second
classesN.dex, an ELF or nested apk/zip hidden under assets/, an oversized blob --
had no tool that would show it. apk.files reads the zip central directory and
sniffs the leading magic of the returned page. These cover the listing, the
kind sniff (ignoring extension), sizes/stored, filtering, paging/caps, and the
malformed-archive path.
"""

from __future__ import annotations

import ast
import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_mod
from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.tools.apk import build_apk_tools

_DEX = b"dex\n035\x00" + b"\x00" * 16
_ELF = b"\x7fELF" + b"\x01" * 16
_ZIP = b"PK\x03\x04" + b"\x00" * 16
_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8


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


def _write_apk(
    path: Path,
    members: dict[str, bytes],
    *,
    stored: tuple[str, ...] = (),
    dirs: tuple[str, ...] = (),
) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in dirs:
            archive.writestr(name, b"")
        for name, data in members.items():
            ctype = zipfile.ZIP_STORED if name in stored else zipfile.ZIP_DEFLATED
            archive.writestr(name, data, compress_type=ctype)


def test_apk_files_lists_every_member_and_sniffs_kind_by_magic(tmp_path: Path) -> None:
    """The point over native_libs: see the dex/elf/zip payloads, not just lib/."""
    apk = tmp_path / "app.apk"
    _write_apk(
        apk,
        {
            "classes.dex": _DEX,
            "classes2.dex": _DEX,
            "lib/arm64-v8a/libfoo.so": _ELF,
            "assets/payload.jar": _ZIP,
            "res/drawable/icon.png": _PNG,
            "AndroidManifest.xml": b"\x03\x00\x08\x00rest",
        },
        stored=("assets/payload.jar",),
        dirs=("assets/",),
    )
    payload = ApkClient().files(apk, limit=100)
    by_path = {row["path"]: row for row in payload["files"]}
    # The directory entry is not a file.
    assert "assets/" not in by_path
    assert payload["total"] == 6
    assert by_path["classes.dex"]["kind"] == "dex"
    assert by_path["classes2.dex"]["kind"] == "dex"
    assert by_path["lib/arm64-v8a/libfoo.so"]["kind"] == "elf"
    assert by_path["assets/payload.jar"]["kind"] == "zip"
    assert by_path["res/drawable/icon.png"]["kind"] == "png"
    assert by_path["AndroidManifest.xml"]["kind"] == "axml"
    # sizes and the stored tell are present.
    assert by_path["classes.dex"]["size"] == len(_DEX)
    assert "compressed_size" in by_path["classes.dex"]
    assert by_path["assets/payload.jar"]["stored"] is True
    assert by_path["classes.dex"]["stored"] is False
    doc = " ".join(_tool_docstring("apk.files").split())
    assert "list field is files" in doc
    assert "kind" in doc
    assert "scan_capped" in doc


def test_apk_files_names_a_payload_by_bytes_not_extension(tmp_path: Path) -> None:
    """A renamed payload is called what it is: an ELF dropped in as a .png."""
    apk = tmp_path / "app.apk"
    _write_apk(apk, {"assets/logo.png": _ELF, "assets/note.txt": b"just text here"})
    rows = {row["path"]: row for row in ApkClient().files(apk, limit=100)["files"]}
    assert rows["assets/logo.png"]["kind"] == "elf"
    # An unrecognised head gets no kind key rather than a guess.
    assert "kind" not in rows["assets/note.txt"]


def test_apk_files_name_filter_narrows_before_paging(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _write_apk(
        apk,
        {
            "assets/a.dat": _ELF,
            "assets/b.dat": _ZIP,
            "res/x.png": _PNG,
            "classes.dex": _DEX,
        },
    )
    payload = ApkClient().files(apk, name_filter="assets/")
    assert payload["total"] == 2
    assert {row["path"] for row in payload["files"]} == {"assets/a.dat", "assets/b.dat"}


def test_apk_files_pages_and_reports_has_more(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _write_apk(apk, {f"assets/f{index}.bin": _PNG for index in range(25)})
    payload = ApkClient().files(apk, offset=0, limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True
    assert payload["offset"] == 0
    assert payload["scan_capped"] is False


def test_apk_files_marks_scan_capped_at_the_collect_ceiling(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(apk_mod, "_MAX_FILES_COLLECT", 3)
    apk = tmp_path / "app.apk"
    _write_apk(apk, {f"m{index}.bin": _PNG for index in range(6)})
    payload = ApkClient().files(apk, limit=100)
    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_apk_files_refuses_a_non_archive(tmp_path: Path) -> None:
    not_zip = tmp_path / "broken.apk"
    not_zip.write_bytes(b"this is not a zip file at all")
    with pytest.raises(ApkError) as info:
        ApkClient().files(not_zip, limit=100)
    assert info.value.code == "backend_error"


def test_apk_files_is_classified_read_only() -> None:
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "apk.files" in _READ_ONLY_NAMES
