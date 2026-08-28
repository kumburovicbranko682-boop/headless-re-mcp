"""r2.sections lists the binary's section/segment table (its memory layout).

r2 is not installed in CI, so these exercise the pieces that do not need it:
the enrich_r2_payload mapping over a fake ``iSj`` JSON payload (fields, address
mapping, the 4096 cap), the command whitelist (``iSj`` allowed, a composed form
rejected before launch), the service routing to the ``iSj`` command, and the
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


def test_r2_sections_maps_layout_fields_and_address(tmp_path: Path) -> None:
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": ".text", "size": 0x400, "vsize": 0x400,
         "paddr": 0x400, "vaddr": 0x140001000, "perm": "-r-x"},
        {"name": ".data", "size": 0x80, "vsize": 0x100,
         "paddr": 0x800, "vaddr": 0x140002000, "perm": "-rw-"},
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 2
    text = payload["items"][0]
    assert text["name"] == ".text"
    assert text["perm"] == "-r-x"
    assert text["vsize"] == 0x400
    assert text["paddr"] == 0x400
    # vaddr is mapped into the unified Address (va, plus rva off the PE base).
    assert text["address"]["va"] == 0x140001000
    # No integer address field replaces the structured one.
    assert "sections" not in payload
    assert "has_more" not in payload


def test_r2_sections_says_when_the_list_was_cut(tmp_path: Path) -> None:
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": f"s{index}", "vaddr": 0x140001000 + index, "perm": "-r--"}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
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


def test_r2_sections_command_is_whitelisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    result = client.run(binary, ["iSj"])
    assert result["commands"] == ["iSj"]
    assert len(launched) == 1
    # A composed/parameterised form is still refused before any launch.
    with pytest.raises(R2Error, match="not whitelisted"):
        client.run(binary, ["iS anything"])


def test_service_r2_sections_routes_to_iSj_command(monkeypatch: pytest.MonkeyPatch) -> None:
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
        result = service.r2_sections("sess", timeout=12.0)
        assert result == "sentinel"
        assert captured["session_id"] == "sess"
        assert captured["commands"] == ["iSj"]
        assert captured["timeout"] == 12.0
    finally:
        service.close_all()


def test_r2_sections_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("r2.sections").split())
    assert "perm" in doc
    assert "items_truncated" in doc
    assert "no sections" in doc.lower()
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "r2.sections" in _READ_ONLY_NAMES
