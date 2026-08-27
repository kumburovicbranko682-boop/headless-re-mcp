"""jadx must not report a partial decompile as a complete source export.

jadx exits non-zero when it fails to decompile some classes but still writes
the ones it could. ``_run`` deliberately tolerates that (it only fails hard
when *nothing* landed), so the export succeeds -- but a caller reading
``java_files`` as the complete class list would silently miss the classes jadx
gave up on. These tests pin the ``partial`` disclosure that says so.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient, JadxError


def _tool_docstring(name: str) -> str:
    from headless_re_mcp.tools.apk import build_apk_tools

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


def _tree_with_sources(out: Path, count: int = 2) -> None:
    sources = out / "sources" / "com" / "example"
    sources.mkdir(parents=True)
    for index in range(count):
        (sources / f"C{index}.java").write_text("class C {}", encoding="utf-8")


def test_export_sources_flags_a_non_zero_exit_that_still_wrote_sources(
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    _tree_with_sources(out)
    client = JadxClient(tmp_path / "jadx.bat")
    (tmp_path / "jadx.bat").write_text("x", encoding="utf-8")
    client._run = lambda *a, **k: ("", "ERROR: failed to decompile Foo", 1)  # type: ignore[method-assign]

    result = client.export_sources(tmp_path / "app.apk", out)

    assert result["partial"] is True
    assert result["exit_code"] == 1
    assert "note" in result and result["note"]
    assert "failed to decompile Foo" in result["stderr"]
    # The classes that did land are still reported; partial is not empty.
    assert result["java_file_count"] == 2


def test_export_sources_clean_exit_is_not_partial(tmp_path: Path) -> None:
    out = tmp_path / "out"
    _tree_with_sources(out)
    client = JadxClient(tmp_path / "jadx.bat")
    (tmp_path / "jadx.bat").write_text("x", encoding="utf-8")
    client._run = lambda *a, **k: ("", "", 0)  # type: ignore[method-assign]

    result = client.export_sources(tmp_path / "app.apk", out)

    assert result["partial"] is False
    assert "exit_code" not in result
    assert "note" not in result
    assert "stderr" not in result


def test_decompile_carries_partial_onto_a_class_that_read_back(tmp_path: Path) -> None:
    out = tmp_path / "out"
    src = out / "sources" / "com" / "example"
    src.mkdir(parents=True)
    (src / "Main.java").write_text("class Main {}", encoding="utf-8")
    client = JadxClient(tmp_path / "jadx.bat")
    (tmp_path / "jadx.bat").write_text("x", encoding="utf-8")
    client._run = lambda *a, **k: ("", "ERROR: partial", 1)  # type: ignore[method-assign]

    result = client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert result["class_name"] == "com.example.Main"
    assert result["partial"] is True
    assert "note" in result and result["note"]


def test_decompile_missing_class_says_the_run_was_partial(tmp_path: Path) -> None:
    out = tmp_path / "out"
    _tree_with_sources(out)
    client = JadxClient(tmp_path / "jadx.bat")
    (tmp_path / "jadx.bat").write_text("x", encoding="utf-8")
    client._run = lambda *a, **k: ("", "ERROR: partial", 1)  # type: ignore[method-assign]

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Missing")

    assert caught.value.code == "not_found"
    assert caught.value.details.get("partial") is True
    assert "partial" in caught.value.message


def test_decompile_missing_class_on_a_clean_run_is_a_plain_not_found(
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    _tree_with_sources(out)
    client = JadxClient(tmp_path / "jadx.bat")
    (tmp_path / "jadx.bat").write_text("x", encoding="utf-8")
    client._run = lambda *a, **k: ("", "", 0)  # type: ignore[method-assign]

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Missing")

    assert caught.value.code == "not_found"
    assert "partial" not in caught.value.details
    assert caught.value.message == "decompiled class not found"


def test_tool_docstrings_name_the_partial_disclosure() -> None:
    export_doc = " ".join(_tool_docstring("apk.export_sources").split())
    assert "partial" in export_doc
    assert "java_files" in export_doc
    decompile_doc = " ".join(_tool_docstring("apk.decompile").split())
    assert "partial" in decompile_doc
    assert "source" in decompile_doc


def test_stderr_left_off_when_partial_but_jadx_was_silent(tmp_path: Path) -> None:
    out = tmp_path / "out"
    _tree_with_sources(out)
    client = JadxClient(tmp_path / "jadx.bat")
    (tmp_path / "jadx.bat").write_text("x", encoding="utf-8")
    client._run = lambda *a, **k: ("", "   ", 1)  # type: ignore[method-assign]

    result = client.export_sources(tmp_path / "app.apk", out)

    assert result["partial"] is True
    assert "stderr" not in result
