"""apk.repack descriptions must name the fields apktool actually returns."""

from __future__ import annotations

import ast
import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.tools.apk import build_apk_tools


def _write_minimal_apk(path: Path) -> None:
    """A real (if tiny) zip, so is_zipfile accepts it like an apktool output."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")


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


def test_apk_repack_names_apk_and_says_it_is_still_unsigned(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said rebuild and never named the payload.

    Measured: build keys are apk, note, signed, size. signed is False.
    output/path/repacked are absent. Looking for output after a successful
    rebuild reads as no APK, and signed False without note reads as a failed
    sign rather than an unsigned tree that still needs apk.sign.
    """
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("@echo off\n", encoding="utf-8")
    source = tmp_path / "decoded"
    source.mkdir()
    (source / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    out = tmp_path / "out.apk"

    def fake_run(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        _write_minimal_apk(out)
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
    client = ApktoolClient(fake_tool, None)
    payload = client.build(source, out)
    assert "output" not in payload
    assert "path" not in payload
    assert "repacked" not in payload
    assert payload["apk"] == str(out)
    assert payload["signed"] is False
    assert payload["size"] == out.stat().st_size
    doc = _tool_docstring("apk.repack")
    assert "Answers with apk" in doc
    assert "unsigned" in doc


def _make_client(tmp_path: Path) -> tuple[ApktoolClient, Path, Path]:
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("@echo off\n", encoding="utf-8")
    source = tmp_path / "decoded"
    source.mkdir()
    (source / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    out = tmp_path / "out.apk"
    return ApktoolClient(fake_tool, None), source, out


def test_apk_repack_rejects_an_empty_output_even_when_apktool_exits_zero(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """apktool can exit 0 yet leave a zero-byte file (aborted build, full disk).

    Before this the client read is_file() as success and returned size 0, so a
    caller would hand an empty file to apk.sign and only learn there that the
    rebuild had failed. Now the empty output is a backend_error at repack time.
    """
    client, source, out = _make_client(tmp_path)

    def fake_run(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        out.write_bytes(b"")
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
    with pytest.raises(ApktoolError) as caught:
        client.build(source, out)
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("size") == 0


def test_apk_repack_rejects_a_nonzip_output_even_when_apktool_exits_zero(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A truncated, non-zip output is a failed rebuild, not a rebuilt apk."""
    client, source, out = _make_client(tmp_path)

    def fake_run(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        out.write_bytes(b"not a zip file at all")
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
    with pytest.raises(ApktoolError) as caught:
        client.build(source, out)
    assert caught.value.code == "backend_error"
    assert "empty or invalid" in caught.value.message


def test_apk_decode_rejects_an_empty_manifest_even_when_apktool_exits_zero(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """apktool can exit 0 yet leave a zero-byte AndroidManifest.xml.

    Before this the client read is_file() as success, so a caller would edit
    and rebuild a tree that never decoded. Now the empty manifest is a
    backend_error at decode time -- the same failure the rebuild path rejects.
    """
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("@echo off\n", encoding="utf-8")
    apk = tmp_path / "app.apk"
    _write_minimal_apk(apk)
    out_dir = tmp_path / "decoded"

    def fake_run(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_bytes(b"")
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
    client = ApktoolClient(fake_tool, None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(apk, out_dir)
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("size") == 0


def test_apk_decode_accepts_a_nonempty_manifest(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A real decode (non-empty manifest) still succeeds and names its fields."""
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("@echo off\n", encoding="utf-8")
    apk = tmp_path / "app.apk"
    _write_minimal_apk(apk)
    out_dir = tmp_path / "decoded"

    def fake_run(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        (out_dir / "smali").mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
    client = ApktoolClient(fake_tool, None)
    payload = client.decode(apk, out_dir)
    assert payload["decoded_dir"] == str(out_dir)
    assert payload["manifest"].endswith("AndroidManifest.xml")
    assert payload["smali_dirs"] == ["smali"]
    doc = _tool_docstring("apk.decode")
    assert "backend_error" in doc
