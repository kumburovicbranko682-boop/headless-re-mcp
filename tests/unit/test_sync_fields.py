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


def test_sync_schemas_match_the_non_negative_address_the_service_requires() -> None:
    """The catalog accepted negative addresses on every sync tool.

    Measured: _require_address raises invalid_address for a negative value, so
    the mapping refuses it after the tool is already dispatched. The input
    schemas carry no minimum, so a negative address is only caught once a
    session and both backends have been resolved.
    """
    from headless_re_mcp.core.addressing import _require_address
    from headless_re_mcp.tools.binding import input_schema_for

    guard = Path(_require_address.__code__.co_filename).read_text(encoding="utf-8")
    start = guard.index("def _require_address")
    assert "value < 0" in guard[start : start + 400]

    bindings = build_meta_tools(object())  # type: ignore[arg-type]
    named = {binding.name: binding.handler for binding in bindings}
    for name in (
        "sync.static_to_runtime",
        "sync.runtime_to_static",
        "sync.module_preferred_to_runtime",
        "sync.module_runtime_to_preferred",
        "sync.resolve_runtime_address",
    ):
        props = input_schema_for(named[name])["properties"]
        assert props["address"]["minimum"] == 0, name


def _service_address_sources() -> set[str]:
    import re

    from headless_re_mcp.core import service

    source = Path(service.__file__).read_text(encoding="utf-8")
    start = source.index("def resolve_runtime_address")
    # The guard reads: normalized not in {"static", "rva", "runtime"}.
    brace = source.index("normalized not in {", start) + len("normalized not in ")
    literal = source[brace : source.index("}", brace) + 1]
    return set(re.findall(r'"([a-z]+)"', literal))


def test_resolve_runtime_address_source_is_the_service_enum() -> None:
    """source was a bare str, so the schema advertised no coordinate vocabulary.

    resolve_runtime_address accepts exactly static|rva|runtime and the service
    rejects anything else with "source must be one of: static, rva, runtime",
    yet the tool typed source as ``str`` -- the schema said only "string", so an
    agent's natural guess ("virtual", "abs") passed the schema and failed one
    layer down. The schema must expose exactly the service's set as an enum, and
    stay in lockstep with it.
    """
    from headless_re_mcp.tools.binding import input_schema_for

    handler = next(
        binding.handler
        for binding in build_meta_tools(object())  # type: ignore[arg-type]
        if binding.name == "sync.resolve_runtime_address"
    )
    source = input_schema_for(handler)["properties"]["source"]

    assert set(source["enum"]) == _service_address_sources()
    assert source["default"] == "static"

