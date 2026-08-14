"""apk.repack descriptions must name the fields apktool actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apktool.client import ApktoolClient
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
        out.write_bytes(b"PK" + b"\x00" * 20)
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
