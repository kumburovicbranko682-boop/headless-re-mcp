"""wasm.secrets detects embedded credentials in a module's data (rodata) section.

wasm.strings gives the raw runs and wasm.endpoints the network surface; wasm.secrets
is the credential companion -- it runs the same high-precision detector table
js.secrets and apk.secrets use over those runs, in-process (no wabt). These build a
real data section and cover specific-detector hits, dedup and counting, the
detector summary, the case-insensitive filter, include_generic, value truncation,
the no-data-section case, the collect cap, paging via the client, the error paths,
service routing, and read-only.

Secret-looking test values are assembled from fragments at runtime so the
contiguous string never appears in the committed bytes (GitHub push protection).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import parse_data_secrets
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

_HEADER = b"\x00asm\x01\x00\x00\x00"

# Assembled so the whole secret never appears contiguously in this file.
_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_STRIPE = "sk_" + "live_" + "0123456789abcdef0123"
_JWT = (
    "ey" + "JhbGciOiJIUzI1NiJ9"
    + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0"
    + "." + "dozjgNryP4J3jVmNHl0w5N" + "_XgL0n3I9PlFUP0THsR8U"
)
_HIGH_ENTROPY = "aB3xK9pQ7wZ2mN5vR8tY1cF4gH6jL0dS"


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


def _by_detector(secrets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["detector"]: row for row in secrets}


def test_wasm_secrets_detects_specific_credentials() -> None:
    payload = f"k1={_AWS}\x00s={_STRIPE}\x00t={_JWT}\x00hello world\x00".encode()
    secrets, detectors, has_data, scan_capped = parse_data_secrets(_module_with_data(payload))
    assert has_data is True
    assert scan_capped is False
    by_kind = _by_detector(secrets)
    assert by_kind["aws_access_key_id"]["value"] == _AWS
    assert by_kind["stripe_secret_key"]["value"] == _STRIPE
    assert by_kind["jwt"]["value"] == _JWT
    assert detectors == ["aws_access_key_id", "jwt", "stripe_secret_key"]


def test_wasm_secrets_dedupes_and_counts() -> None:
    run = f"key={_AWS}\x00".encode()
    payload = run + b"noise-between\x00" + run
    secrets, _detectors, _has, _capped = parse_data_secrets(_module_with_data(payload))
    assert len(secrets) == 1
    row = secrets[0]
    assert row["count"] == 2
    all_offsets = [s["first_offset"] for s in secrets]
    assert row["first_offset"] == min(all_offsets)


def test_wasm_secrets_no_secrets_is_empty_not_error() -> None:
    payload = b"nothing sensitive here\x00just plain text\x00"
    secrets, detectors, has_data, scan_capped = parse_data_secrets(_module_with_data(payload))
    assert secrets == []
    assert detectors == []
    assert has_data is True
    assert scan_capped is False


def test_wasm_secrets_name_filter_matches_detector_or_value() -> None:
    payload = f"a={_AWS}\x00s={_STRIPE}\x00".encode()
    by_kind = parse_data_secrets(_module_with_data(payload), name_filter="STRIPE")[0]
    assert [r["detector"] for r in by_kind] == ["stripe_secret_key"]
    by_value = parse_data_secrets(_module_with_data(payload), name_filter=_AWS.lower())[0]
    assert [r["detector"] for r in by_value] == ["aws_access_key_id"]


def test_wasm_secrets_include_generic_is_opt_in() -> None:
    payload = f"{_HIGH_ENTROPY}\x00".encode()
    assert parse_data_secrets(_module_with_data(payload))[0] == []
    secrets = parse_data_secrets(_module_with_data(payload), include_generic=True)[0]
    assert [r["detector"] for r in secrets] == ["generic_high_entropy"]
    assert secrets[0]["value"] == _HIGH_ENTROPY


def test_wasm_secrets_value_truncated(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.jsre import wasm_summary

    monkeypatch.setattr(wasm_summary, "_MAX_DATA_SECRET_VALUE", 8)
    payload = f"t={_JWT}\x00".encode()
    row = parse_data_secrets(_module_with_data(payload))[0][0]
    assert row["value_truncated"] is True
    assert len(row["value"]) == 8


def test_wasm_secrets_sorted_by_detector_then_count() -> None:
    run = f"a={_AWS}\x00".encode()
    payload = run + f"s={_STRIPE}\x00".encode() + run
    secrets, _detectors, _has, _capped = parse_data_secrets(_module_with_data(payload))
    assert secrets[0]["detector"] == "aws_access_key_id"
    assert secrets[0]["count"] == 2


def test_wasm_secrets_collection_cap_sets_scan_capped(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.jsre import wasm_summary

    monkeypatch.setattr(wasm_summary, "_MAX_DATA_SECRETS_COLLECT", 1)
    payload = f"a={_AWS}\x00s={_STRIPE}\x00".encode()
    secrets, _detectors, _has, scan_capped = parse_data_secrets(_module_with_data(payload))
    assert scan_capped is True
    assert len(secrets) == 1


def test_wasm_secrets_no_data_section_is_empty_not_error() -> None:
    secrets, detectors, has_data, scan_capped = parse_data_secrets(_module_without_data())
    assert secrets == []
    assert detectors == []
    assert has_data is False
    assert scan_capped is False


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "mod.wasm"
    p.write_bytes(data)
    return p


def test_wasm_client_secrets_pages_and_totals(tmp_path: Path) -> None:
    # Ten distinct JWTs (distinct signature segment) -> ten findings.
    parts = [f"{_JWT}{i:02d}\x00".encode() for i in range(10)]
    out = WasmClient().secrets(_write(tmp_path, _module_with_data(b"".join(parts))), limit=3)
    assert out["has_data_section"] is True
    assert out["count"] == 3
    assert out["total"] == 10
    assert out["offset"] == 0
    assert out["has_more"] is True
    assert out["detectors"] == ["jwt"]
    page2 = WasmClient().secrets(
        _write(tmp_path, _module_with_data(b"".join(parts))), offset=9, limit=3
    )
    assert page2["count"] == 1
    assert page2["has_more"] is False


def test_wasm_client_secrets_stripped_module_is_the_answer(tmp_path: Path) -> None:
    out = WasmClient().secrets(_write(tmp_path, _module_without_data()))
    assert out["has_data_section"] is False
    assert out["secrets"] == []
    assert out["total"] == 0


def test_wasm_client_secrets_not_a_module_is_invalid_params(tmp_path: Path) -> None:
    from headless_re_mcp.backends.jsre.client import JsReError

    p = tmp_path / "notwasm.bin"
    p.write_bytes(b"MZ\x90\x00 this is not a wasm module at all")
    with pytest.raises(JsReError) as info:
        WasmClient().secrets(p)
    assert info.value.code == "invalid_params"


def test_wasm_client_secrets_missing_file_is_not_found(tmp_path: Path) -> None:
    from headless_re_mcp.backends.jsre.client import JsReError

    with pytest.raises(JsReError) as info:
        WasmClient().secrets(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_wasm_client_secrets_page_limit_is_capped(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_SECRETS_PAGE", 2)
    parts = [f"{_JWT}{i:02d}\x00".encode() for i in range(6)]
    out = WasmClient().secrets(
        _write(tmp_path, _module_with_data(b"".join(parts))), limit=1000
    )
    assert out["count"] == 2
    assert out["total"] == 6
    assert out["has_more"] is True


def test_service_wasm_secrets_routes_to_the_client(tmp_path: Path) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        payload = f"a={_AWS}\x00s={_STRIPE}\x00".encode()
        p = _write(tmp_path, _module_with_data(payload))
        result = service.wasm_secrets(str(p), name_filter="stripe")
        assert result.ok and result.data is not None
        assert [r["detector"] for r in result.data["secrets"]] == ["stripe_secret_key"]
        assert result.data["total"] == 1
    finally:
        service.close_all()


def test_wasm_secrets_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("wasm.secrets").split())
    assert "detector" in doc
    assert "has_data_section" in doc
    assert "include_generic" in doc
    assert "name_filter" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "wasm.secrets" in _READ_ONLY_NAMES
