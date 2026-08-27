"""apk.decode descriptions must name the fields apktool actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import headless_re_mcp.backends.apktool.client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.tools.apk import build_apk_tools


def test_configured_but_missing_apktool_falls_back_to_path(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A stale HEADLESS_RE_APKTOOL must not hide an apktool that is on PATH.

    __init__ kept any configured path verbatim, so a typo'd or stale
    HEADLESS_RE_APKTOOL left available False and every apk.decode/repack call
    capability_unavailable even with apktool on PATH -- while doctor's
    probe_optional_tool and the r2/jadx/webcrack/wabt resolvers fall back to
    PATH, so doctor reported apktool detected while the tools said missing.
    """
    on_path = tmp_path / "path-apktool"
    on_path.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        apktool_client, "_discover", lambda name: on_path if name == "apktool" else None
    )

    client = ApktoolClient(tmp_path / "missing-apktool", None)

    assert client.available is True
    assert client.apktool == on_path


def test_configured_but_missing_apksigner_falls_back_to_path(
    tmp_path: Path, monkeypatch: Any
) -> None:
    on_path = tmp_path / "path-apksigner"
    on_path.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        apktool_client, "_discover", lambda name: on_path if name == "apksigner" else None
    )

    client = ApktoolClient(None, tmp_path / "missing-apksigner")

    assert client.signer_available is True
    assert client.apksigner == on_path


def test_missing_apktool_and_apksigner_are_unavailable(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(apktool_client, "_discover", lambda name: None)

    client = ApktoolClient(tmp_path / "nope-apktool", tmp_path / "nope-apksigner")

    assert client.available is False
    assert client.signer_available is False


def test_configured_apktool_and_apksigner_that_exist_are_used(tmp_path: Path) -> None:
    apktool = tmp_path / "apktool"
    apktool.write_text("#!/bin/sh\n", encoding="utf-8")
    apksigner = tmp_path / "apksigner"
    apksigner.write_text("#!/bin/sh\n", encoding="utf-8")

    client = ApktoolClient(apktool, apksigner)

    assert client.available is True
    assert client.signer_available is True


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
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
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
