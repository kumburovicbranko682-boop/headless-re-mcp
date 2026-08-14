"""modules.resolve description must name module/preferred/runtime, not base."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.core.models import ModuleSelector
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


def test_modules_resolve_puts_bases_under_preferred_and_runtime(tmp_path: Path) -> None:
    """The catalog said resolve and never named the payload.

    Measured: keys are module, preferred, runtime, rebase_delta, match_basis.
    preferred.base is the PE ImageBase, runtime.base is the load VA. There is
    no top-level base, path or sha256. Looking for base after a successful
    resolve reads as the module not being loaded.
    """
    from tests.unit.test_dynamic_service import (
        FakeDynamicWorker,
        _create,
        _service,
        _write_minimal_pe,
    )

    binary = tmp_path / "f.exe"
    _write_minimal_pe(binary, preferred_base=0x180000000, image_size=0x5000)
    runtime_base = 0x7FF800000000
    worker = FakeDynamicWorker(
        module_name=binary.name,
        module_path=str(binary),
        module_base=runtime_base,
        module_size=0x5000,
    )
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    result = service.module_resolve(session_id, ModuleSelector(name=binary.name))
    assert result.ok and result.data is not None
    payload: dict[str, Any] = result.data
    assert sorted(payload) == [
        "match_basis",
        "module",
        "preferred",
        "rebase_delta",
        "runtime",
    ]
    assert payload["preferred"]["base"] == 0x180000000
    assert payload["runtime"]["base"] == runtime_base
    assert "base" not in payload
    assert "path" not in payload
    assert "sha256" not in payload
    doc = _tool_docstring("modules.resolve")
    assert "Answers with module" in doc
    assert "preferred" in doc
    assert "runtime" in doc
    assert "no top-level base" in doc
