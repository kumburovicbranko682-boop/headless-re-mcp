"""An ambiguous simple class name must not be reported as a missing class.

``apk.decompile`` resolves a ``class_name`` to an exact source path, and when
that path does not exist it falls back to a simple-name walk of the decompiled
tree. A single hit is used. Several hits used to collapse to the same
``not_found`` a genuinely absent class raises -- so a caller who named a class
by its bare simple name (``Widget`` rather than ``com.a.Widget``) was told the
class is absent when it was in fact decompiled several times over, one per
package. These lock in that the ambiguous case is surfaced as ``invalid_params``
with the candidate paths, that a truly missing class still raises ``not_found``,
and that the unambiguous single-match fallback is preserved.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient, JadxError
from headless_re_mcp.tools.apk import build_apk_tools


def _client_with_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> JadxClient:
    """A client whose whole-APK decompile is a no-op, leaving the caller to
    populate ``out/sources`` with whatever tree the test needs."""
    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {})
    return client


def _write_class(out: Path, package: str, simple: str, body: str) -> None:
    directory = out / "sources" / Path(package)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{simple}.java").write_text(body, encoding="utf-8")


def test_decompile_reports_an_ambiguous_simple_name_with_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _write_class(out, "com/a", "Widget", "package com.a; class Widget {}")
    _write_class(out, "com/b", "Widget", "package com.b; class Widget {}")
    client = _client_with_sources(tmp_path, monkeypatch)

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "Widget")

    error = caught.value
    assert error.code == "invalid_params"
    assert "ambiguous" in error.message
    assert error.details["candidate_count"] == 2
    assert set(error.details["candidates"]) == {
        str(Path("com/a/Widget.java")),
        str(Path("com/b/Widget.java")),
    }


def test_decompile_still_reports_a_truly_missing_class_as_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    (out / "sources").mkdir(parents=True)
    client = _client_with_sources(tmp_path, monkeypatch)

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Missing")

    assert caught.value.code == "not_found"
    assert "candidates" not in caught.value.details


def test_decompile_qualified_missing_name_with_homonyms_is_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The caller already gave a package (com.missing.Widget); homonyms in other
    # packages are not the class it named, so this is not_found, not an
    # ambiguity the caller could resolve by qualifying a name it already
    # qualified.
    out = tmp_path / "out"
    _write_class(out, "com/a", "Widget", "class Widget {}")
    _write_class(out, "com/b", "Widget", "class Widget {}")
    client = _client_with_sources(tmp_path, monkeypatch)

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.missing.Widget")

    assert caught.value.code == "not_found"
    assert "candidates" not in caught.value.details


def test_decompile_uses_the_only_simple_name_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _write_class(out, "com/a", "Widget", "class Widget {}")
    client = _client_with_sources(tmp_path, monkeypatch)

    payload = client.decompile(tmp_path / "app.apk", out, "Widget")

    assert payload["class_name"] == "Widget"
    assert payload["source"] == "class Widget {}"


def test_decompile_candidate_list_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.backends.jadx import client as mod

    monkeypatch.setattr(mod, "_MAX_AMBIGUOUS_CANDIDATES", 3)
    out = tmp_path / "out"
    for index in range(6):
        _write_class(out, f"com/p{index}", "Widget", "class Widget {}")
    client = _client_with_sources(tmp_path, monkeypatch)

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "Widget")

    error = caught.value
    # The list is capped, but candidate_count still reports the true total so a
    # caller sees the bound was hit rather than believing there were only three.
    assert len(error.details["candidates"]) == 3
    assert error.details["candidate_count"] == 6


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


def test_docstring_names_the_ambiguous_class_fields() -> None:
    doc = _tool_docstring("apk.decompile")
    assert "ambiguous" in doc
    assert "candidates" in doc
