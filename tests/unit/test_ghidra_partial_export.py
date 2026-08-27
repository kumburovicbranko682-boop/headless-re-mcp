"""Ghidra must not report a partial headless run as a complete export.

analyzeHeadless can exit non-zero (killed near the timeout, a post-analysis
warning, a cleanup failure) while the ``ExportJson.py`` post-script has already
written valid JSON for whatever Ghidra managed to analyse. ``_export_unlocked``
only fails hard when the export file is *missing*, so that run succeeds -- but
a caller reading ``items``/``decompiled`` as the whole thing would miss that
the analysis errored. These tests pin the ``partial`` disclosure that says so.
"""

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


def _client(tmp_path: Path) -> ghidra_client.GhidraClient:
    client = ghidra_client.GhidraClient(home=_fake_home(tmp_path))
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")
    return client


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ")
    return path


def _run_that_exports(returncode: int, stderr: bytes = b"") -> Any:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_text(
                    '{"mode": "functions", "items": [{"name": "f"}], '
                    '"count": 1, "has_more": false}',
                    encoding="utf-8",
                )
        return Completed(returncode, b"analyze noise", stderr)

    return fake_run


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


def test_export_flags_a_non_zero_exit_that_still_wrote_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ghidra_client,
        "run_bounded",
        _run_that_exports(1, b"ERROR analysis aborted near timeout"),
    )
    payload = _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project")

    assert payload["partial"] is True
    assert payload["exit_code"] == 1
    assert payload["note"]
    assert "analysis aborted" in payload["stderr"]
    # The results the post-script did export still come back.
    assert payload["items"] == [{"name": "f"}]
    assert payload["count"] == 1


def test_export_clean_exit_is_not_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_that_exports(0))
    payload = _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project")

    assert payload["partial"] is False
    assert "exit_code" not in payload
    assert "note" not in payload
    assert "stderr" not in payload


def test_non_zero_exit_with_no_export_still_fails_hard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(2, b"", b"nothing written")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 2


def test_decompile_carries_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_text(
                    '{"mode": "decompile", "decompiled": "int main(){}", '
                    '"truncated": false}',
                    encoding="utf-8",
                )
        return Completed(1, b"", b"warning: partial")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    payload = _client(tmp_path).decompile(_binary(tmp_path), tmp_path / "project", "0x401000")

    assert payload["partial"] is True
    assert payload["decompiled"] == "int main(){}"
    # partial (analysis errored) is independent of truncated (text cut at cap).
    assert payload["truncated"] is False


def test_partial_stderr_left_off_when_analyzeheadless_was_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_that_exports(1, b"   "))
    payload = _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project")

    assert payload["partial"] is True
    assert "stderr" not in payload


def test_tool_docstrings_name_the_partial_disclosure() -> None:
    for name in ("ghidra.functions", "ghidra.symbols", "ghidra.xrefs", "ghidra.decompile"):
        assert "partial" in " ".join(_tool_docstring(name).split()), name
