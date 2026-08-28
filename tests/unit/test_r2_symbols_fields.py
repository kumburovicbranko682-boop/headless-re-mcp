"""r2.symbols lists the binary's full symbol table (imports/exports superset).

r2 is not installed in CI, so these exercise the pieces that do not need it:
the enrich_r2_payload mapping over a fake ``isj`` JSON payload (fields, address
mapping, the 4096 cap), the command whitelist (``isj`` allowed, a composed form
rejected before launch), the service routing to the ``isj`` command, and the
tool docstring / read-only classification.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_r2_payload
from headless_re_mcp.tools.r2 import build_r2_tools


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


def test_r2_symbols_maps_symbol_fields_and_address(tmp_path: Path) -> None:
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": "local_helper", "realname": "local_helper", "type": "FUNC",
         "bind": "LOCAL", "size": 0x40, "is_imported": False, "vaddr": 0x140001000},
        {"name": "imp.printf", "type": "FUNC", "bind": "GLOBAL",
         "size": 0, "is_imported": True, "vaddr": 0x140002000},
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["isj"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 2
    helper = payload["items"][0]
    assert helper["name"] == "local_helper"
    assert helper["type"] == "FUNC"
    assert helper["bind"] == "LOCAL"
    assert helper["is_imported"] is False
    # vaddr is mapped into the unified Address (va, plus rva off the PE base).
    assert helper["address"]["va"] == 0x140001000
    assert "symbols" not in payload
    assert "has_more" not in payload


def test_r2_symbols_says_when_the_list_was_cut(tmp_path: Path) -> None:
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": f"sym{index}", "type": "FUNC", "vaddr": 0x140001000 + index}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["isj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 3
    assert payload["items_limit"] == _MAX_ITEMS


def _client_and_binary(tmp_path: Path) -> tuple[R2Client, Path]:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    return R2Client(executable), binary


def test_r2_symbols_command_is_whitelisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    result = client.run(binary, ["isj"])
    assert result["commands"] == ["isj"]
    assert len(launched) == 1
    # A composed/parameterised form is still refused before any launch.
    with pytest.raises(R2Error, match="not whitelisted"):
        client.run(binary, ["isj anything"])


def test_service_r2_symbols_routes_to_isj_command(monkeypatch: pytest.MonkeyPatch) -> None:
    from headless_re_mcp.core import service_ext
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        captured: dict[str, Any] = {}

        def fake_request(
            svc: Any, session_id: str, commands: list[str], *, timeout: float
        ) -> Any:
            captured["session_id"] = session_id
            captured["commands"] = commands
            captured["timeout"] = timeout
            return "sentinel"

        monkeypatch.setattr(service_ext, "_r2_request", fake_request)
        result = service.r2_symbols("sess", timeout=15.0)
        assert result == "sentinel"
        assert captured["session_id"] == "sess"
        assert captured["commands"] == ["isj"]
        assert captured["timeout"] == 15.0
    finally:
        service.close_all()


def test_r2_symbols_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("r2.symbols").split())
    assert "bind" in doc
    assert "is_imported" in doc
    assert "items_truncated" in doc
    assert "no symbols" in doc.lower()
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "r2.symbols" in _READ_ONLY_NAMES
