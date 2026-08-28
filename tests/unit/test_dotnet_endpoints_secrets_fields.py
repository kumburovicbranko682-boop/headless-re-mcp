"""dotnet.endpoints / dotnet.secrets scan the #US ldstr literals.

These complete the .NET static triad (dotnet.strings -> endpoints -> secrets),
running the shared endpoint_scan.py / secret_scan.py over the same #US
user-string literals. They build a #US heap by hand, drive the extractors
through a fake metadata context, and cover URL/host/path aggregation, the token
pivot each finding carries, occurrence counting and dedup, name_filter and
paging, include_paths / include_generic, the no-#US-heap soft result, a real
session for routing, and the tool docstrings / read-only classification.

Secret-looking test values are assembled from fragments at runtime so the
contiguous string never appears in the committed bytes (GitHub push protection).
"""

from __future__ import annotations

import ast
import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet import metadata_enum
from headless_re_mcp.dotnet.metadata_enum import (
    _MetaCtx,
    extract_user_string_endpoints,
    extract_user_string_secrets,
)
from headless_re_mcp.tools.core import build_dotnet_tools

# Assembled so the whole secret never appears contiguously in this file.
_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_STRIPE = "sk_" + "live_" + "0123456789abcdef0123"


def _tool_docstring(func_name: str) -> str:
    source = Path(build_dotnet_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return ast.get_docstring(node) or ""
    return ""


def _compress(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return bytes([0x80 | (n >> 8), n & 0xFF])
    return bytes([0xC0 | (n >> 24), (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def _us_entry(text: str) -> bytes:
    body = text.encode("utf-16-le")
    terminal = b"\x01" if any(ord(ch) > 0x7F for ch in text) else b"\x00"
    blob = body + terminal
    return _compress(len(blob)) + blob


def _us_heap(*texts: str) -> bytes:
    heap = b"\x00"
    for text in texts:
        heap += _us_entry(text)
    return heap


def _ctx(heap: bytes, *, with_us: bool = True) -> _MetaCtx:
    prefix = b"BSJBpad!"
    meta = prefix + heap
    stream_map = {"#US": (len(prefix), len(heap))} if with_us else {}
    return _MetaCtx(
        path=Path("fake.exe"),
        pe_data=b"",
        layout=None,
        meta=meta,
        stream_map=stream_map,
        tables=b"",
        strings=b"",
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts={},
        table_data_offset=0,
    )


def _endpoints(ctx: _MetaCtx, monkeypatch, **kwargs) -> dict:
    monkeypatch.setattr(metadata_enum, "inspect_dotnet", lambda *a, **k: None)
    monkeypatch.setattr(metadata_enum, "_load_metadata_context", lambda p: ctx)
    return extract_user_string_endpoints("fake.exe", **kwargs)


def _secrets(ctx: _MetaCtx, monkeypatch, **kwargs) -> dict:
    monkeypatch.setattr(metadata_enum, "inspect_dotnet", lambda *a, **k: None)
    monkeypatch.setattr(metadata_enum, "_load_metadata_context", lambda p: ctx)
    return extract_user_string_secrets("fake.exe", **kwargs)


def test_endpoints_urls_hosts_and_paths(monkeypatch) -> None:
    heap = _us_heap(
        "https://api.example.com/v1/users",
        "connect to https://api.example.com/v1/orders now",
        "/api/health",
        "just some text",
    )
    out = _endpoints(_ctx(heap), monkeypatch)
    assert out["has_us_heap"] is True
    by_value = {e["value"]: e for e in out["endpoints"]}
    assert "https://api.example.com/v1/users" in by_value
    assert by_value["https://api.example.com/v1/users"]["kind"] == "url"
    assert by_value["https://api.example.com/v1/users"]["host"] == "api.example.com"
    assert by_value["https://api.example.com/v1/users"]["scheme"] == "https"
    # The whole-string path is surfaced as a path endpoint.
    assert "/api/health" in by_value
    assert by_value["/api/health"]["kind"] == "path"
    # Distinct URL host set summarised.
    assert out["hosts"] == ["api.example.com"]


def test_endpoints_dedup_count_and_token(monkeypatch) -> None:
    # Same URL in two literals -> one row, count 2, token of the first literal.
    heap = _us_heap("go https://x.example/a", "again https://x.example/a")
    out = _endpoints(_ctx(heap), monkeypatch)
    row = next(e for e in out["endpoints"] if e["value"] == "https://x.example/a")
    assert row["count"] == 2
    # token is a #US user-string token (0x70xxxxxx) tying back to the literal.
    assert row["token"] & 0xFF000000 == 0x70000000


def test_endpoints_include_paths_false_drops_paths(monkeypatch) -> None:
    heap = _us_heap("https://h.example/x", "/api/things")
    out = _endpoints(_ctx(heap), monkeypatch, include_paths=False)
    kinds = {e["kind"] for e in out["endpoints"]}
    assert kinds == {"url"}


def test_endpoints_name_filter_and_paging(monkeypatch) -> None:
    heap = _us_heap(
        "https://alpha.example/a",
        "https://beta.example/b",
        "https://alpha.example/c",
    )
    filtered = _endpoints(_ctx(heap), monkeypatch, name_filter="alpha")
    assert filtered["total"] == 2
    assert all("alpha" in e["value"] for e in filtered["endpoints"])
    page = _endpoints(_ctx(heap), monkeypatch, offset=0, limit=1)
    assert page["total"] == 3
    assert len(page["endpoints"]) == 1
    assert page["has_more"] is True


def test_endpoints_no_us_heap_is_soft(monkeypatch) -> None:
    out = _endpoints(_ctx(b"", with_us=False), monkeypatch)
    assert out["has_us_heap"] is False
    assert out["endpoints"] == []
    assert out["total"] == 0
    assert out["kind"] == "endpoints"
    assert out["claims_universal_unpack"] is False


def test_secrets_detects_and_carries_token(monkeypatch) -> None:
    heap = _us_heap(
        f"var k = {_AWS}",
        f"stripe {_STRIPE} key",
        "nothing to see",
    )
    out = _secrets(_ctx(heap), monkeypatch)
    by_detector = {s["detector"]: s for s in out["secrets"]}
    assert by_detector["aws_access_key_id"]["value"] == _AWS
    assert by_detector["stripe_secret_key"]["value"] == _STRIPE
    assert by_detector["aws_access_key_id"]["token"] & 0xFF000000 == 0x70000000
    assert out["detectors"] == ["aws_access_key_id", "stripe_secret_key"]


def test_secrets_dedup_counts_occurrences(monkeypatch) -> None:
    heap = _us_heap(f"a {_AWS}", f"b {_AWS}")
    out = _secrets(_ctx(heap), monkeypatch)
    row = next(s for s in out["secrets"] if s["detector"] == "aws_access_key_id")
    assert row["count"] == 2


def test_secrets_generic_gated_by_include_generic(monkeypatch) -> None:
    token = "aB3xK9pQ7wZ2mN5vR8tY1cF4gH6jL0dS"  # high entropy, no specific match
    heap = _us_heap(token)
    off = _secrets(_ctx(heap), monkeypatch)
    assert off["secrets"] == []
    on = _secrets(_ctx(heap), monkeypatch, include_generic=True)
    assert any(s["detector"] == "generic_high_entropy" for s in on["secrets"])


def test_secrets_name_filter(monkeypatch) -> None:
    heap = _us_heap(f"{_AWS}", f"{_STRIPE}")
    out = _secrets(_ctx(heap), monkeypatch, name_filter="aws")
    assert out["total"] == 1
    assert out["secrets"][0]["detector"] == "aws_access_key_id"


def test_secrets_no_us_heap_is_soft(monkeypatch) -> None:
    out = _secrets(_ctx(b"", with_us=False), monkeypatch)
    assert out["has_us_heap"] is False
    assert out["secrets"] == []
    assert out["kind"] == "secrets"


def _write_minimal_clr(path: Path) -> None:
    image = bytearray(0x800)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)
    path.write_bytes(image)


def test_service_dotnet_endpoints_and_secrets_no_heap(tmp_path: Path) -> None:
    binary = tmp_path / "empty.exe"
    _write_minimal_clr(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        endpoints = service.dotnet_endpoints(session_id, limit=5)
        assert endpoints.ok and endpoints.data is not None
        assert endpoints.data["kind"] == "endpoints"
        assert endpoints.data["has_us_heap"] is False
        assert endpoints.data["endpoints"] == []
        secrets = service.dotnet_secrets(session_id, limit=5)
        assert secrets.ok and secrets.data is not None
        assert secrets.data["kind"] == "secrets"
        assert secrets.data["has_us_heap"] is False
        assert secrets.data["secrets"] == []
    finally:
        service.close_all()


def test_dotnet_endpoints_secrets_docstrings_and_read_only() -> None:
    ep = " ".join(_tool_docstring("dotnet_endpoints").split())
    assert "#US" in ep and "token" in ep and "hosts" in ep
    se = " ".join(_tool_docstring("dotnet_secrets").split())
    assert "#US" in se and "include_generic" in se and "detector" in se
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "dotnet.endpoints" in _READ_ONLY_NAMES
    assert "dotnet.secrets" in _READ_ONLY_NAMES
