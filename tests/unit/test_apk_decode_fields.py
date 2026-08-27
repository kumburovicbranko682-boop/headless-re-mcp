"""apk.decode descriptions must name the fields apktool actually returns."""

from __future__ import annotations

import ast
import zipfile
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


def test_apk_decode_names_decoded_dir_not_output(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said editable tree and never named the payload.

    Measured: decode keys are decoded_dir, has_resources, manifest,
    smali_dirs. output/path/tree/decoded are absent. Looking for output
    after a successful decode reads as no tree, so the agent skips smali
    edits or re-decodes.
    """
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("@echo off\n", encoding="utf-8")
    # A readable zip, not two magic bytes: decode now checks the declared
    # expansion before running apktool, and an unreadable archive is refused.
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
    out = tmp_path / "decoded"
    out.mkdir()
    (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    (out / "smali").mkdir()

    monkeypatch.setattr(
        "headless_re_mcp.backends.apktool.client._run",
        lambda *_args, **_kwargs: ("", "", 0),
    )
    client = ApktoolClient(fake_tool, None)
    payload = client.decode(apk, out)
    assert "output" not in payload
    assert "path" not in payload
    assert "tree" not in payload
    assert payload["decoded_dir"] == str(out)
    assert payload["smali_dirs"] == ["smali"]
    assert payload["has_resources"] is False
    doc = _tool_docstring("apk.decode")
    assert "Answers with decoded_dir" in doc
    assert "smali_dirs" in doc
