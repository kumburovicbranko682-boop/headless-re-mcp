"""wasm.endpoints extracts the network surface from a module's data section.

wasm.summary gives structure, wasm.names gives symbols, wasm.strings gives the
raw rodata runs; wasm.endpoints is the "what backends does this module reach"
companion -- it runs the same URL/path recogniser js.endpoints and apk.endpoints
use over those runs, in-process (no wabt). These build a real data section and
cover URL/host extraction, dedup and counting, request paths, include_paths, the
host summary, the case-insensitive filter, the no-data-section case, the collect
cap, paging via the client, the error paths, service routing, and read-only.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import parse_data_endpoints
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

_HEADER = b"\x00asm\x01\x00\x00\x00"


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _section(sec_id: int, body: bytes) -> bytes:
    return bytes([sec_id]) + _uleb(len(body)) + body


def _data_section(payload: bytes) -> bytes:
    # One active segment: flags 0, offset expr `i32.const 0` `end`, then the raw
    # bytes. The parser skips the framing and scans only the payload.
    segment = b"\x00" + b"\x41\x00\x0b" + _uleb(len(payload)) + payload
    return _section(11, _uleb(1) + segment)


def _module_with_data(payload: bytes) -> bytes:
    return _HEADER + _section(1, _uleb(0)) + _data_section(payload)


def _module_without_data() -> bytes:
    return _HEADER + _section(1, _uleb(0))


def _tool_docstring(name: str) -> str:
    source = Path(build_js_wasm_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def _by_value(out_endpoints: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["value"]: row for row in out_endpoints}


_PAYLOAD = (
    b"https://api.example.com/v1/login\x00"
    b"http://cdn.example.net/asset.js\x00"
    b"wss://socket.example.io/ws\x00"
    b"/api/v2/users\x00"
    b"/x\x00"  # too short / not api-like: not an endpoint
    b"Content-Type\x00"  # ordinary token: not an endpoint
)


def test_wasm_endpoints_extracts_urls_with_scheme_and_host() -> None:
    endpoints, hosts, hosts_truncated, has_data, scan_capped = parse_data_endpoints(
        _module_with_data(_PAYLOAD)
    )
    assert has_data is True
    assert scan_capped is False
    assert hosts_truncated is False
    by_value = _by_value(endpoints)
    login = by_value["https://api.example.com/v1/login"]
    assert login["kind"] == "url"
    assert login["scheme"] == "https"
    assert login["host"] == "api.example.com"
    assert by_value["http://cdn.example.net/asset.js"]["scheme"] == "http"
    assert by_value["wss://socket.example.io/ws"]["scheme"] == "wss"
    assert hosts == ["api.example.com", "cdn.example.net", "socket.example.io"]


def test_wasm_endpoints_extracts_request_paths() -> None:
    endpoints, _hosts, _ht, _has, _capped = parse_data_endpoints(_module_with_data(_PAYLOAD))
    by_value = _by_value(endpoints)
    assert "/api/v2/users" in by_value
    path = by_value["/api/v2/users"]
    assert path["kind"] == "path"
    assert path["scheme"] == ""
    assert path["host"] == ""
    # Non-api-like short path and an ordinary token are not endpoints.
    assert "/x" not in by_value
    assert "Content-Type" not in by_value


def test_wasm_endpoints_include_paths_false_drops_paths() -> None:
    endpoints, _hosts, _ht, _has, _capped = parse_data_endpoints(
        _module_with_data(_PAYLOAD), include_paths=False
    )
    kinds = {row["kind"] for row in endpoints}
    assert kinds == {"url"}
    assert "/api/v2/users" not in _by_value(endpoints)


def test_wasm_endpoints_dedupes_and_counts() -> None:
    url = b"https://api.example.com/v1/login\x00"
    payload = url + b"noise-between\x00" + url
    endpoints, _hosts, _ht, _has, _capped = parse_data_endpoints(_module_with_data(payload))
    row = _by_value(endpoints)["https://api.example.com/v1/login"]
    assert row["count"] == 2
    # first_offset pins the earliest run the URL was seen in.
    all_offsets = [r["first_offset"] for r in endpoints]
    assert row["first_offset"] == min(all_offsets)


def test_wasm_endpoints_host_summary_is_distinct() -> None:
    payload = (
        b"https://api.example.com/a\x00"
        b"https://api.example.com/b\x00"
        b"https://other.example.org/c\x00"
    )
    _endpoints, hosts, _ht, _has, _capped = parse_data_endpoints(_module_with_data(payload))
    assert hosts == ["api.example.com", "other.example.org"]


def test_wasm_endpoints_name_filter_matches_host_or_value() -> None:
    endpoints, _hosts, _ht, _has, _capped = parse_data_endpoints(
        _module_with_data(_PAYLOAD), name_filter="socket.example.io"
    )
    assert [row["value"] for row in endpoints] == ["wss://socket.example.io/ws"]


def test_wasm_endpoints_sorted_by_count_descending() -> None:
    dup = b"https://busy.example.com/api\x00"
    payload = dup + b"https://rare.example.com/x\x00" + dup
    endpoints, _hosts, _ht, _has, _capped = parse_data_endpoints(_module_with_data(payload))
    assert endpoints[0]["value"] == "https://busy.example.com/api"
    assert endpoints[0]["count"] == 2


def test_wasm_endpoints_no_data_section_is_empty_not_error() -> None:
    endpoints, hosts, hosts_truncated, has_data, scan_capped = parse_data_endpoints(
        _module_without_data()
    )
    assert endpoints == []
    assert hosts == []
    assert hosts_truncated is False
    assert has_data is False
    assert scan_capped is False


def test_wasm_endpoints_collection_cap_sets_scan_capped(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.jsre import wasm_summary

    monkeypatch.setattr(wasm_summary, "_MAX_DATA_ENDPOINTS_COLLECT", 1)
    payload = b"https://a.example.com/1\x00https://b.example.com/2\x00"
    endpoints, _hosts, _ht, _has, scan_capped = parse_data_endpoints(_module_with_data(payload))
    assert scan_capped is True
    assert len(endpoints) == 1


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "mod.wasm"
    p.write_bytes(data)
    return p


def test_wasm_client_endpoints_pages_and_totals(tmp_path: Path) -> None:
    payload = b"".join(f"https://h{i:03d}.example.com/p\x00".encode() for i in range(10))
    out = WasmClient().endpoints(_write(tmp_path, _module_with_data(payload)), limit=3)
    assert out["has_data_section"] is True
    assert out["count"] == 3
    assert out["total"] == 10
    assert out["offset"] == 0
    assert out["has_more"] is True
    assert out["scan_capped"] is False
    assert len(out["hosts"]) == 10
    page2 = WasmClient().endpoints(
        _write(tmp_path, _module_with_data(payload)), offset=9, limit=3
    )
    assert page2["count"] == 1
    assert page2["has_more"] is False


def test_wasm_client_endpoints_stripped_module_is_the_answer(tmp_path: Path) -> None:
    out = WasmClient().endpoints(_write(tmp_path, _module_without_data()))
    assert out["has_data_section"] is False
    assert out["endpoints"] == []
    assert out["hosts"] == []
    assert out["total"] == 0


def test_wasm_client_endpoints_not_a_module_is_invalid_params(tmp_path: Path) -> None:
    from headless_re_mcp.backends.jsre.client import JsReError

    p = tmp_path / "notwasm.bin"
    p.write_bytes(b"MZ\x90\x00 this is not a wasm module at all")
    with pytest.raises(JsReError) as info:
        WasmClient().endpoints(p)
    assert info.value.code == "invalid_params"


def test_wasm_client_endpoints_missing_file_is_not_found(tmp_path: Path) -> None:
    from headless_re_mcp.backends.jsre.client import JsReError

    with pytest.raises(JsReError) as info:
        WasmClient().endpoints(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_wasm_client_endpoints_page_limit_is_capped(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_ENDPOINTS_PAGE", 2)
    payload = b"".join(f"https://h{i:03d}.example.com/p\x00".encode() for i in range(6))
    out = WasmClient().endpoints(_write(tmp_path, _module_with_data(payload)), limit=1000)
    assert out["count"] == 2
    assert out["total"] == 6
    assert out["has_more"] is True


def test_service_wasm_endpoints_routes_to_the_client(tmp_path: Path) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        payload = b"https://api.example.com/token\x00https://cdn.other.net/x\x00"
        p = _write(tmp_path, _module_with_data(payload))
        result = service.wasm_endpoints(str(p), name_filter="api.example")
        assert result.ok and result.data is not None
        assert [r["value"] for r in result.data["endpoints"]] == [
            "https://api.example.com/token"
        ]
        assert result.data["total"] == 1
    finally:
        service.close_all()


def test_wasm_endpoints_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("wasm.endpoints").split())
    assert "endpoints" in doc
    assert "hosts" in doc
    assert "has_data_section" in doc
    assert "include_paths" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "wasm.endpoints" in _READ_ONLY_NAMES
