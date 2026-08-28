"""memory.protection description must name set vs protect_name."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from unittest.mock import MagicMock

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.dynamic_analysis import build_dynamic_analysis_tools


def _rights_schema() -> dict:
    tools = build_dynamic_analysis_tools(MagicMock())
    handler = next(t.handler for t in tools if t.name == "memory.protection")
    return input_schema_for(handler)["properties"]["rights"]


def _native_page_rights() -> list[str]:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("bool IsAllowedPageRights")
    block = native[start : native.index("};", start)]
    return re.findall(r'"([A-Za-z]+)"', block)


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


def test_rights_is_an_enum_matching_the_native_allowlist() -> None:
    """rights must advertise the exact SetPageRights vocabulary, not a bare str.

    IsAllowedPageRights accepts only the eight x64dbg page-protection names and
    their guard-page ``G`` variants, and rejects everything else with "rights
    string is not in the allowlist". Typed as ``str | None`` the schema gave the
    agent no hint, so a natural guess like ``rw`` or ``rwx`` (which *is* a valid
    breakpoint type) round-tripped to a paused debuggee only to be refused there.
    The generated schema must expose those names as an enum -- and it must stay
    in lockstep with the native allowlist so the two never drift apart. ``None``
    stays allowed because that is the query path.
    """
    schema = _rights_schema()
    variants = schema["anyOf"]

    enum = next(v["enum"] for v in variants if "enum" in v)
    assert enum == _native_page_rights()
    # Short breakpoint-style spellings never belonged in this allowlist.
    assert "rw" not in enum and "rwx" not in enum and "r" not in enum
    # The query path (no rights) still validates.
    assert any(v.get("type") == "null" for v in variants)
    assert schema.get("default") is None
