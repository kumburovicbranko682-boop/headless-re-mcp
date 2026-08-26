"""Ghidra adapter behaviour without a real analyzeHeadless install."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.tools.ghidra import build_ghidra_tools


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    return home


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ")
    return path


def _client(tmp_path: Path) -> ghidra_client.GhidraClient:
    client = ghidra_client.GhidraClient(home=_fake_home(tmp_path))
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")
    return client


def _capture_run(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        argv = [str(part) for part in cmd]
        calls.append(argv)
        for arg in argv:
            if arg.endswith(".json"):
                Path(arg).write_text('{"items": []}', encoding="utf-8")
        return Completed(0, b"analyze ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    return calls


def test_ghidra_analyze_deletes_the_project_other_tools_cannot_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The catalog told the model to run analyze first so the rest could reuse it.

    Measured here: analyzeHeadless is invoked with -import and -deleteProject,
    then functions is invoked the same way against the same directory. The first
    call's project is gone before the second starts, so the recommended sequence
    is two full headless imports, default 120s then 180s, for one listing.
    """
    client = _client(tmp_path)
    calls = _capture_run(monkeypatch)
    project = tmp_path / "project"
    binary = _binary(tmp_path)

    analyzed = client.analyze_binary(binary, project)
    listed = client.functions(binary, project)

    assert len(calls) == 2
    analyze_cmd, functions_cmd = calls
    assert "-import" in analyze_cmd
    assert "-deleteProject" in analyze_cmd
    assert "-import" in functions_cmd
    assert "-deleteProject" in functions_cmd
    assert "deleted" in analyzed["note"]
    assert "import" in analyzed["note"]
    assert listed["export_path"]


def test_ghidra_analyze_description_does_not_tell_the_model_to_run_it_first() -> None:
    """A caller that believes the other tools read this project will spend minutes twice.

    The live description said they 'read what this produced, so run it first'.
    That is the opposite of -deleteProject.
    """
    source = Path(build_ghidra_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    described = ""
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
                    and keyword.value.value == "ghidra.analyze"
                ):
                    described = ast.get_docstring(node) or ""
    assert described, "ghidra.analyze must describe itself"
    lowered = described.casefold()
    assert "delete" in lowered
    assert "imports the binary again" in lowered
    assert "do not read what this produced" in lowered
    assert "run it first" not in lowered


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


def test_ghidra_list_descriptions_name_the_fields_the_export_returns() -> None:
    """The catalog said address/size; a 5000-function export had neither.

    Measured against ExportJson.py: 256 of 5000 functions, 0 items had address
    or size, all 256 had entry and body_size. Looking for address after a
    successful list reads as Ghidra finding no addresses. Symbols have type,
    not namespace. Xrefs are getReferencesTo only.
    """
    functions = _tool_docstring("ghidra.functions")
    assert "entry" in functions
    assert "body_size" in functions
    assert "has_more" in functions
    assert "address, size and name" not in functions

    symbols = _tool_docstring("ghidra.symbols")
    assert "type" in symbols
    assert "has_more" in symbols
    assert "with address and namespace" not in symbols

    xrefs = _tool_docstring("ghidra.xrefs")
    assert "from" in xrefs
    assert "has_more" in xrefs
    assert "to and from" not in xrefs
    assert "Outgoing refs are not listed" in xrefs

    decompile = _tool_docstring("ghidra.decompile")
    assert "decompiled" in decompile
    assert "truncated" in decompile


def test_ghidra_refuses_an_oversized_export_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "_MAX_EXPORT_BYTES", 64)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_text('{"items": ["' + ("x" * 80) + '"]}', encoding="utf-8")
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "too_large"


@pytest.mark.parametrize(
    ("payload", "error_type"),
    [
        (b"\xff", "UnicodeDecodeError"),
        (b"{", "JSONDecodeError"),
    ],
)
def test_ghidra_reports_corrupt_export_as_a_backend_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    error_type: str,
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_bytes(payload)
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert caught.value.message == "export JSON invalid"
    assert error_type in str(caught.value.details["error"])
