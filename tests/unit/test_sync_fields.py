"""sync.static_to_runtime must name the nested address fields it actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.core.addressing import build_main_module_mapping
from headless_re_mcp.core.models import Architecture, Session
from headless_re_mcp.tools.meta import build_meta_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_meta_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def _payload() -> dict[str, object]:
    mapping = build_main_module_mapping(
        Session(
            binary=Path(r"C:\sample\fixtures\fixture.exe"),
            sha256="a" * 64,
            architecture=Architecture.X64,
        ),
        {"image_base": 0x140000000},
        {
            "modules": [
                {
                    "base": 0x7FF700000000,
                    "size": 0x6000,
                    "name": "fixture.exe",
                    "path": "c:/SAMPLE/FIXTURES/fixture.exe",
                }
            ],
            "count": 1,
        },
        {"architecture": Architecture.X64.value},
    )
    return mapping.translate("static", 0x140001234)


def test_sync_static_to_runtime_puts_the_va_under_runtime_not_runtime_address() -> None:
    """The catalog said it maps to a runtime address and never named the field.

    Measured: ModuleMapping.translate (what _sync_address returns) puts the
    mapped VA at runtime.address, with static.address, rva, rebase_delta,
    module, source, target and match_basis. There is no top-level
    runtime_address. That name belongs to sync.resolve_runtime_address.
    Looking for runtime_address after a successful sync reads as a failed
    rebase, so the agent retries or arms breakpoints at the static VA.
    """
    payload = _payload()
    assert "runtime_address" not in payload
    assert "static_address" not in payload
    assert payload["runtime"]["address"] == 0x7FF700001234
    assert payload["static"]["address"] == 0x140001234
    assert payload["rva"] == 0x1234
    described = _tool_docstring("sync.static_to_runtime")
    assert "Answers with" in described
    assert "runtime.address" in described
    assert "no runtime_address" in described
    described_back = _tool_docstring("sync.runtime_to_static")
    assert "Answers with" in described_back
    assert "static.address" in described_back
    assert "no runtime_address" in described_back

def test_sync_module_preferred_to_runtime_nests_address() -> None:
    """The live catalog omitted the nested address fields.

    tests/unit/test_dynamic_service.py already reads
    to_runtime.data['runtime']['address'] and
    to_preferred.data['preferred']['address']. There is no runtime_address
    field. A caller looking for runtime_address after a successful module
    sync reads the rebase as failed.
    """
    described = " ".join(_tool_docstring("sync.module_preferred_to_runtime").split())
    assert "Answers with runtime.address" in described
    assert "preferred.address" in described
    assert "no runtime_address field" in described
    described_back = " ".join(
        _tool_docstring("sync.module_runtime_to_preferred").split()
    )
    assert "preferred.address" in described_back
    assert "no runtime_address field" in described_back

