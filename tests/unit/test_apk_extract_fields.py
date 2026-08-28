"""apk.extract pulls one named archive member out to a bounded, safe file.

apk.files names a bundled payload (a nested apk/zip, an ELF, a hidden dex);
apk.extract is what gets that one member on disk so the next tool can read it.
These cover the copy + metadata (member/size/path/sha256/kind), the zip-slip
guard (a crafted member path cannot escape the out dir), the not_found /
directory / empty-member refusals, the size cap, and the read-only class.
"""

from __future__ import annotations

import ast
import hashlib
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.tools.apk import build_apk_tools

_DEX = b"dex\n035\x00" + b"\x00" * 32
_ELF = b"\x7fELF" + b"\x01" * 32
_ZIP = b"PK\x03\x04" + b"\x00" * 32


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


def test_apk_extract_copies_member_and_reports_metadata(tmp_path: Path) -> None:
    """The point over apk.files: get the flagged member's bytes on disk."""
    apk = tmp_path / "app.apk"
    _write_apk(apk, {"assets/payload.jar": _ZIP, "classes.dex": _DEX})
    out = tmp_path / "out"
    result = ApkClient().extract(apk, "assets/payload.jar", out)
    assert result["member"] == "assets/payload.jar"
    assert result["size"] == len(_ZIP)
    assert result["kind"] == "zip"
    assert result["sha256"] == hashlib.sha256(_ZIP).hexdigest()
    written = Path(result["path"])
    # It landed under the out dir, keeping a recognisable extension.
    assert written.parent == out
    assert written.suffix == ".jar"
    assert written.read_bytes() == _ZIP


def test_apk_extract_names_member_by_bytes_not_extension(tmp_path: Path) -> None:
    """kind is the magic classification, so a renamed ELF is still an elf."""
    apk = tmp_path / "app.apk"
    _write_apk(apk, {"assets/logo.png": _ELF, "assets/note.txt": b"plain text here"})
    out = tmp_path / "out"
    assert ApkClient().extract(apk, "assets/logo.png", out)["kind"] == "elf"
    # An unrecognised head gets no kind key rather than a guess.
    assert "kind" not in ApkClient().extract(apk, "assets/note.txt", out)


def test_apk_extract_zip_slip_cannot_escape_out_dir(tmp_path: Path) -> None:
    """A member path of ../.. must not write outside the out dir."""
    apk = tmp_path / "app.apk"
    # zipfile.writestr keeps the traversal name verbatim in the central dir.
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("../../evil.bin", _DEX)
    out = tmp_path / "nested" / "out"
    result = ApkClient().extract(apk, "../../evil.bin", out)
    written = Path(result["path"])
    assert written.parent == out
    assert out in written.resolve().parents
    # Nothing was written to the traversal target.
    assert not (tmp_path / "evil.bin").exists()


def test_apk_extract_missing_member_is_not_found(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _write_apk(apk, {"classes.dex": _DEX})
    with pytest.raises(ApkError) as info:
        ApkClient().extract(apk, "assets/nope.bin", tmp_path / "out")
    assert info.value.code == "not_found"


def test_apk_extract_directory_member_is_invalid_params(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _write_apk(apk, {"assets/x.bin": _DEX}, dirs=("assets/",))
    with pytest.raises(ApkError) as info:
        ApkClient().extract(apk, "assets/", tmp_path / "out")
    assert info.value.code == "invalid_params"


def test_apk_extract_empty_member_is_invalid_params(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _write_apk(apk, {"classes.dex": _DEX})
    with pytest.raises(ApkError) as info:
        ApkClient().extract(apk, "   ", tmp_path / "out")
    assert info.value.code == "invalid_params"


def test_apk_extract_refuses_a_member_over_the_cap(tmp_path: Path) -> None:
    """A member whose declared size is over the cap is refused before the read."""
    apk = tmp_path / "app.apk"
    big = b"A" * 4096
    _write_apk(apk, {"assets/big.bin": big})
    with pytest.raises(ApkError) as info:
        ApkClient().extract(apk, "assets/big.bin", tmp_path / "out", max_bytes=1024)
    assert info.value.code == "too_large"
    # Nothing was written for a refused extract.
    out = tmp_path / "out"
    assert not out.exists() or not any(out.iterdir())


def test_apk_extract_refuses_a_non_archive(tmp_path: Path) -> None:
    not_zip = tmp_path / "broken.apk"
    not_zip.write_bytes(b"this is not a zip file at all")
    with pytest.raises(ApkError) as info:
        ApkClient().extract(not_zip, "classes.dex", tmp_path / "out")
    assert info.value.code == "backend_error"


def test_apk_extract_tool_docstring_documents_safety() -> None:
    doc = " ".join(_tool_docstring("apk.extract").split())
    assert "cannot escape" in doc
    assert "sha256" in doc
    assert "too_large" in doc


def test_apk_extract_is_classified_read_only() -> None:
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "apk.extract" in _READ_ONLY_NAMES
