"""apk.decode must not report skipped resources as absent resources.

``apktool d`` writes a ``res/`` tree unless ``-r`` (``no_resources``) tells it
to skip resource decoding. ``decode`` reports ``has_resources`` from whether
that tree exists, so with ``no_resources`` the flag is False no matter what the
APK actually holds -- a caller reading it would conclude the APK has no
resources when they were merely not decoded. These lock in that the reply also
carries ``resources_decoded`` (False exactly when decoding was skipped), so the
two cases are distinguishable, and that the tool docstring names the field.
"""

from __future__ import annotations

import ast
import zipfile
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.tools.apk import build_apk_tools


def _write_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


def _decoded_tree(tmp_path: Path, *, with_res: bool) -> Path:
    out = tmp_path / "decoded"
    out.mkdir()
    (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    (out / "smali").mkdir()
    if with_res:
        (out / "res").mkdir()
    return out


def _client(tmp_path: Path, monkeypatch: Any) -> ApktoolClient:
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setattr(
        "headless_re_mcp.backends.apktool.client._run",
        lambda *_args, **_kwargs: ("", "", 0),
    )
    return ApktoolClient(fake_tool, None)


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


def test_decode_reports_resources_decoded_true_by_default(
    tmp_path: Path, monkeypatch: Any
) -> None:
    apk = _write_apk(tmp_path / "a.apk")
    out = _decoded_tree(tmp_path, with_res=True)
    client = _client(tmp_path, monkeypatch)

    payload = client.decode(apk, out)

    assert payload["resources_decoded"] is True
    assert payload["has_resources"] is True


def test_decode_decoded_but_no_res_dir_is_genuinely_no_resources(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # Resources were decoded (no_resources left False) and still no res/ tree:
    # this is the one case has_resources: False truthfully means "none".
    apk = _write_apk(tmp_path / "a.apk")
    out = _decoded_tree(tmp_path, with_res=False)
    client = _client(tmp_path, monkeypatch)

    payload = client.decode(apk, out)

    assert payload["resources_decoded"] is True
    assert payload["has_resources"] is False


def test_decode_skipped_resources_are_not_reported_as_absent(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # no_resources passes -r, so apktool writes no res/ regardless of the APK.
    # has_resources is False, but resources_decoded: False makes clear that is
    # "skipped", not "the APK has no resources".
    apk = _write_apk(tmp_path / "a.apk")
    out = _decoded_tree(tmp_path, with_res=False)
    client = _client(tmp_path, monkeypatch)

    payload = client.decode(apk, out, no_resources=True)

    assert payload["resources_decoded"] is False
    assert payload["has_resources"] is False


def test_docstring_names_resources_decoded() -> None:
    doc = _tool_docstring("apk.decode")
    assert "resources_decoded" in doc
