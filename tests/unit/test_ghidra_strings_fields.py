"""ghidra.strings lists Ghidra's defined strings in Ghidra's own address space.

Ghidra is not installed in CI, so these exercise the pieces that do not need a
live analyzeHeadless: the client's mode/arg plumbing and export shaping (with a
faked run that writes the export JSON), the ExportJson.py strings branch source,
the service routing to the "strings" mode, and the tool docstring / read-only
classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.tools.ghidra import build_ghidra_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_ghidra_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    return home


def _client(tmp_path: Path) -> ghidra_client.GhidraClient:
    client = ghidra_client.GhidraClient(home=_fake_home(tmp_path))
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")
    return client


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ")
    return path


def test_ghidra_strings_runs_the_strings_mode_and_shapes_the_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        argv = [str(part) for part in cmd]
        calls.append(argv)
        for arg in argv:
            if arg.endswith(".json"):
                Path(arg).write_text(
                    '{"mode": "strings", "items": '
                    '[{"address": "0x401000", "value": "\\"hello\\"", '
                    '"type": "string", "length": 6}], "count": 1, "has_more": false}',
                    encoding="utf-8",
                )
        return Completed(0, b"analyze ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    result = client.strings(_binary(tmp_path), tmp_path / "project")

    assert len(calls) == 1
    argv = calls[0]
    # The postScript is invoked with the strings mode and a strings export path.
    assert "ExportJson.py" in argv
    assert "strings" in argv
    assert any(a.endswith("export_strings.json") for a in argv)
    assert "-deleteProject" in argv
    assert result["items"][0]["address"] == "0x401000"
    assert result["items"][0]["type"] == "string"
    assert result["export_path"].endswith("export_strings.json")


def test_export_json_has_a_strings_branch() -> None:
    script = (
        Path(ghidra_client.__file__).resolve().parent / "scripts" / "ExportJson.py"
    ).read_text(encoding="utf-8")
    assert 'mode == "strings"' in script
    # It only lists data Ghidra marked as strings, keyed by the fields the tool names.
    assert "hasStringValue()" in script
    assert "getDefaultValueRepresentation()" in script
    assert "getDefinedData(True)" in script


def test_service_ghidra_strings_routes_to_strings_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    from headless_re_mcp.core import service_ext
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        captured: dict[str, Any] = {}

        def fake_export(svc: Any, session_id: str, mode: str, **kwargs: Any) -> Any:
            captured["session_id"] = session_id
            captured["mode"] = mode
            captured.update(kwargs)
            return "sentinel"

        monkeypatch.setattr(service_ext, "_ghidra_export", fake_export)
        result = service.ghidra_strings("sess", limit=32, timeout=90.0)
        assert result == "sentinel"
        assert captured["session_id"] == "sess"
        assert captured["mode"] == "strings"
        assert captured["limit"] == 32
        assert captured["timeout"] == 90.0
    finally:
        service.close_all()


def test_ghidra_strings_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("ghidra.strings").split())
    assert "address" in doc
    assert "value" in doc
    assert "has_more" in doc
    assert "ghidra.xrefs" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "ghidra.strings" in _READ_ONLY_NAMES
