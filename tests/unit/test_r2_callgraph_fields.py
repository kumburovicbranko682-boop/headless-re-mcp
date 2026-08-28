"""r2.callgraph must lift agCj's name-keyed nodes into calls/edge counts."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _require_allowed_command
from headless_re_mcp.tools.r2 import build_r2_tools

_AGCJ = [
    {"name": "entry0", "size": 38, "imports": ["reloc.__libc_start_main"]},
    {
        "name": "main",
        "size": 120,
        "imports": ["sym.helper", "sym.add", "sym.imp.printf"],
    },
    {"name": "sym.helper", "size": 20, "imports": ["sym.imp.strlen"]},
    {"name": "sym.add", "size": 16, "imports": []},
]


def _tool_docstring(name: str) -> str:
    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def _client_with_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> tuple[R2Client, Path, list[list[str]]]:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, stdout, b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    return R2Client(executable), binary, launched


def test_callgraph_lifts_nodes_and_renames_imports_to_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """imports here means callees; keep it distinct from r2.imports.

    agCj nodes are name-keyed with an ``imports`` list of callee names. A
    caller reading that as imported library symbols (what r2.imports returns)
    would misread the graph, so the field is surfaced as calls with a count.
    """
    client, binary, launched = _client_with_stdout(
        tmp_path, monkeypatch, json.dumps(_AGCJ).encode()
    )

    payload = client.callgraph(binary)

    assert payload["count"] == 4
    assert payload["edge_count"] == 5
    main = next(n for n in payload["items"] if n["name"] == "main")
    assert main["calls"] == ["sym.helper", "sym.add", "sym.imp.printf"]
    assert main["call_count"] == 3
    assert main["size"] == 120
    # No import-symbol confusion and no address on a name-keyed node.
    for node in payload["items"]:
        assert "imports" not in node
        assert "address" not in node
    leaf = next(n for n in payload["items"] if n["name"] == "sym.add")
    assert leaf["calls"] == []
    assert leaf["call_count"] == 0
    # Analysis then the graph command, one process.
    assert launched[0][3].endswith("agCj") or "agCj" in launched[0][3]


def test_callgraph_empty_when_no_functions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, binary, _ = _client_with_stdout(tmp_path, monkeypatch, b"[]")
    payload = client.callgraph(binary)
    assert payload["items"] == []
    assert payload["count"] == 0
    assert payload["edge_count"] == 0


def test_callgraph_tolerates_malformed_nodes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A node missing name/imports, or a stray non-dict, must not crash."""
    weird = [
        {"name": "ok", "imports": ["a", 5, "b"], "size": 4},
        {"size": 9},
        "not-a-dict",
        {"name": "noedges"},
    ]
    client, binary, _ = _client_with_stdout(tmp_path, monkeypatch, json.dumps(weird).encode())
    payload = client.callgraph(binary)
    assert payload["count"] == 3
    ok = next(n for n in payload["items"] if n["name"] == "ok")
    assert ok["calls"] == ["a", "b"]  # the int 5 is dropped
    nameless = next(n for n in payload["items"] if n["name"] == "")
    assert nameless["calls"] == [] and "size" in nameless
    noedges = next(n for n in payload["items"] if n["name"] == "noedges")
    assert noedges["call_count"] == 0


def test_agcj_is_whitelisted_and_composed_forms_are_not() -> None:
    _require_allowed_command("agCj")
    for bad in ("agCj @ 0", "agC", "agCd", "agCj;!echo x", "agCjj"):
        with pytest.raises(R2Error, match="not whitelisted"):
            _require_allowed_command(bad)


def test_callgraph_docstring_contract() -> None:
    doc = _tool_docstring("r2.callgraph")
    assert "agCj" in doc
    assert "calls" in doc
    assert "r2.imports" in doc
    assert "edge_count" in doc
    assert "items_truncated" in doc
