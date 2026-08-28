"""ghidra.endpoints / ghidra.secrets scan the strings Ghidra defined.

These extend the shared endpoint_scan.py / secret_scan.py to the Ghidra line via
the ghidra "strings" export: each finding carries the Ghidra address of the
string it came from, the form ghidra.xrefs expects. They exercise the pair
builder (value + address ref, non-dict / blank-address items dropped), the
service routing (strings export -> transform, scan_capped from has_more, and
failure passthrough), and the tool docstrings / read-only classification.

Secret-looking values are assembled from fragments at runtime so the contiguous
string never lands in the committed bytes (GitHub push protection).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_ext
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ext import _ghidra_scan_pairs
from headless_re_mcp.tools.ghidra import build_ghidra_tools

_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"


def _tool_docstring(func_name: str) -> str:
    source = Path(build_ghidra_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return ast.get_docstring(node) or ""
    return ""


def _item(address: str, value: str) -> dict[str, Any]:
    return {"address": address, "value": value, "type": "string", "length": len(value)}


def _strings(*items: dict[str, Any], has_more: bool = False) -> dict[str, Any]:
    return {"items": list(items), "has_more": has_more, "count": len(items)}


def test_scan_pairs_carry_address_and_drop_junk() -> None:
    data = _strings(
        _item("0x401000", "https://api.example.com/v1"),
        {"address": "", "value": "no address"},
        {"value": "missing address key"},
        "not a dict",
    )
    pairs = _ghidra_scan_pairs(data)
    assert ("https://api.example.com/v1", {"address": "0x401000"}) in pairs
    # A blank or absent address yields an empty ref (still scanned), never a crash.
    assert ("no address", {}) in pairs
    assert ("missing address key", {}) in pairs
    assert all(isinstance(text, str) for text, _ref in pairs)


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )


def test_service_ghidra_endpoints_transforms_strings(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        captured: dict[str, Any] = {}

        def fake_export(svc: Any, session_id: str, mode: str, *, limit: int, timeout: float):
            captured["mode"] = mode
            captured["limit"] = limit
            return _success(
                _strings(
                    _item("0x401000", "https://api.example.com/v1/users"),
                    _item("0x401100", "/api/health"),
                    has_more=True,
                ),
                session_id=session_id,
                backend="ghidra",
            )

        monkeypatch.setattr(service_ext, "_ghidra_export", fake_export)
        result = service.ghidra_endpoints("sess", name_filter="api")
        # The strings export feeds it, requested at the scan_limit ceiling.
        assert captured["mode"] == "strings"
        assert captured["limit"] == 1024
        assert result.ok and result.data is not None
        by_value = {e["value"]: e for e in result.data["endpoints"]}
        assert by_value["https://api.example.com/v1/users"]["address"] == "0x401000"
        assert by_value["https://api.example.com/v1/users"]["host"] == "api.example.com"
        # has_more on the underlying strings export becomes scan_capped.
        assert result.data["scan_capped"] is True
    finally:
        service.close_all()


def test_service_ghidra_secrets_transform(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        ok = _success(
            _strings(_item("0x402000", f"key={_AWS}")),
            session_id="sess",
            backend="ghidra",
        )
        monkeypatch.setattr(service_ext, "_ghidra_export", lambda *a, **k: ok)
        result = service.ghidra_secrets("sess")
        assert result.ok and result.data is not None
        row = result.data["secrets"][0]
        assert row["detector"] == "aws_access_key_id"
        assert row["value"] == _AWS
        assert row["address"] == "0x402000"

        failure = _failure(RuntimeError("boom"), session_id="sess")
        monkeypatch.setattr(service_ext, "_ghidra_export", lambda *a, **k: failure)
        passthrough = service.ghidra_secrets("sess")
        assert passthrough.ok is False
    finally:
        service.close_all()


def test_ghidra_endpoints_secrets_docstrings_and_read_only() -> None:
    ep = " ".join(_tool_docstring("ghidra_endpoints").split())
    assert "ghidra.xrefs" in ep and "address" in ep and "hosts" in ep
    se = " ".join(_tool_docstring("ghidra_secrets").split())
    assert "ghidra.xrefs" in se and "include_generic" in se and "detector" in se
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "ghidra.endpoints" in _READ_ONLY_NAMES
    assert "ghidra.secrets" in _READ_ONLY_NAMES
