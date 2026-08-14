"""memory.protection description must name set vs protect_name."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.tools.dynamic_analysis import build_dynamic_analysis_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_dynamic_analysis_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_memory_protection_names_set_on_write_and_protect_name_on_query() -> None:
    """The catalog said query or set and never named either payload.

    Measured against MemoryProtection: no rights delegates to
    QueryMemoryProtect (protect_name/protect). A set answers with set,
    rights, rights_now and address; no ok, protection or region field.
    Looking for protect_name after a successful set reads as the rights
    not landing, so the agent retries SetPageRights on the same VA.
    """
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome MemoryProtection")
    chunk = native[start : native.index("} // namespace", start)]
    assert "return QueryMemoryProtect(params)" in chunk
    returned = chunk[chunk.index("auto result = JsonObject()") :]
    assert 'JsonSet(result.get(), "set"' in returned
    assert 'JsonSet(result.get(), "rights"' in returned
    assert 'JsonSet(result.get(), "rights_now"' in returned
    assert 'JsonSet(result.get(), "address"' in returned
    assert '"ok"' not in returned
    assert '"protection"' not in returned
    assert '"region"' not in returned
    region = native[
        native.index("JsonPtr MemoryRegionObject") : native.index(
            "Outcome ListMemoryRegions"
        )
    ]
    assert 'JsonSet(value.get(), "protect_name"' in region
    doc = _tool_docstring("memory.protection")
    assert "protect_name" in doc
    assert "Answers with set" in doc or "A set answers with set" in doc
    assert "rights_now" in doc
    assert "no ok" in doc
