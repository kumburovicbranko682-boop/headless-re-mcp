"""r2.endpoints / r2.secrets scan the strings radare2 recovered (izj).

These extend the shared endpoint_scan.py / secret_scan.py to the native-binary
line: the same aggregation js/apk/dotnet use, over r2's string items, with each
finding carrying the string's vaddr/address for an r2.xrefs pivot. They exercise
the pure aggregators directly (URL/host/path, dedup+count, the vaddr/address
carry, name_filter, paging, include_paths / include_generic, scan_capped from
items_truncated), the service routing (izj -> transform, and failure
passthrough), and the tool docstrings / read-only classification.

Secret-looking test values are assembled from fragments at runtime so the
contiguous string never appears in the committed bytes (GitHub push protection).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.r2.mapping import aggregate_r2_endpoints, aggregate_r2_secrets
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_ext
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.r2 import build_r2_tools

_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_STRIPE = "sk_" + "live_" + "0123456789abcdef0123"


def _tool_docstring(func_name: str) -> str:
    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return ast.get_docstring(node) or ""
    return ""


def _str_item(text: str, vaddr: int) -> dict[str, Any]:
    return {
        "string": text,
        "vaddr": vaddr,
        "section": ".rodata",
        "type": "ascii",
        "address": {"va": vaddr, "module": "target.bin"},
    }


def _data(*items: dict[str, Any], truncated: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "items": list(items),
        "module": "target.bin",
        "architecture": "x64",
        "image_base": 0x400000,
    }
    if truncated:
        payload["items_truncated"] = True
    return payload


def test_endpoints_urls_hosts_paths_and_address_carry() -> None:
    data = _data(
        _str_item("https://api.example.com/v1/users", 0x401000),
        _str_item("see https://api.example.com/v1/orders now", 0x401100),
        _str_item("/api/health", 0x401200),
        _str_item("plain text, nothing here", 0x401300),
    )
    out = aggregate_r2_endpoints(data)
    by_value = {e["value"]: e for e in out["endpoints"]}
    users = by_value["https://api.example.com/v1/users"]
    assert users["kind"] == "url"
    assert users["host"] == "api.example.com"
    assert users["scheme"] == "https"
    # The string's location is carried for an r2.xrefs / r2.disasm pivot.
    assert users["vaddr"] == 0x401000
    assert users["address"] == {"va": 0x401000, "module": "target.bin"}
    assert by_value["/api/health"]["kind"] == "path"
    assert out["hosts"] == ["api.example.com"]
    assert out["module"] == "target.bin"
    assert out["architecture"] == "x64"


def test_endpoints_dedup_counts_occurrences() -> None:
    data = _data(
        _str_item("go https://x.example/a", 0x1000),
        _str_item("again https://x.example/a", 0x1100),
    )
    out = aggregate_r2_endpoints(data)
    row = next(e for e in out["endpoints"] if e["value"] == "https://x.example/a")
    assert row["count"] == 2
    # vaddr pins the first containing string.
    assert row["vaddr"] == 0x1000


def test_endpoints_include_paths_false_and_name_filter() -> None:
    data = _data(
        _str_item("https://alpha.example/a", 0x1000),
        _str_item("https://beta.example/b", 0x1100),
        _str_item("/api/things", 0x1200),
    )
    only_urls = aggregate_r2_endpoints(data, include_paths=False)
    assert {e["kind"] for e in only_urls["endpoints"]} == {"url"}
    filtered = aggregate_r2_endpoints(data, name_filter="alpha")
    assert filtered["total"] == 1
    assert filtered["endpoints"][0]["host"] == "alpha.example"


def test_endpoints_paging_and_scan_capped() -> None:
    items = [_str_item(f"https://h{i:02d}.example/x", 0x1000 + i) for i in range(5)]
    data = _data(*items, truncated=True)
    page = aggregate_r2_endpoints(data, offset=0, limit=2)
    assert page["total"] == 5
    assert len(page["endpoints"]) == 2
    assert page["has_more"] is True
    assert page["scan_capped"] is True


def test_secrets_detects_and_carries_address() -> None:
    data = _data(
        _str_item(f"key={_AWS}", 0x2000),
        _str_item(f"stripe {_STRIPE}", 0x2100),
        _str_item("harmless", 0x2200),
    )
    out = aggregate_r2_secrets(data)
    by_detector = {s["detector"]: s for s in out["secrets"]}
    assert by_detector["aws_access_key_id"]["value"] == _AWS
    assert by_detector["aws_access_key_id"]["vaddr"] == 0x2000
    assert by_detector["aws_access_key_id"]["address"] == {"va": 0x2000, "module": "target.bin"}
    assert by_detector["stripe_secret_key"]["value"] == _STRIPE
    assert out["detectors"] == ["aws_access_key_id", "stripe_secret_key"]


def test_secrets_generic_gated_and_name_filter() -> None:
    token = "aB3xK9pQ7wZ2mN5vR8tY1cF4gH6jL0dS"
    data = _data(_str_item(token, 0x3000), _str_item(f"{_AWS}", 0x3100))
    off = aggregate_r2_secrets(data)
    assert not any(s["detector"] == "generic_high_entropy" for s in off["secrets"])
    on = aggregate_r2_secrets(data, include_generic=True)
    assert any(s["detector"] == "generic_high_entropy" for s in on["secrets"])
    filtered = aggregate_r2_secrets(data, name_filter="aws")
    assert filtered["total"] == 1
    assert filtered["secrets"][0]["detector"] == "aws_access_key_id"


def test_secrets_dedup_counts() -> None:
    data = _data(_str_item(f"a {_AWS}", 0x1), _str_item(f"b {_AWS}", 0x2))
    out = aggregate_r2_secrets(data)
    row = next(s for s in out["secrets"] if s["detector"] == "aws_access_key_id")
    assert row["count"] == 2


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


def test_service_r2_endpoints_transforms_izj(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        captured: dict[str, Any] = {}

        def fake_request(svc: Any, session_id: str, commands: list[str], *, timeout: float):
            captured["commands"] = commands
            return _success(
                _data(_str_item("https://api.example.com/v1", 0x401000)),
                session_id=session_id,
                backend="radare2",
            )

        monkeypatch.setattr(service_ext, "_r2_request", fake_request)
        result = service.r2_endpoints("sess", name_filter="api")
        assert captured["commands"] == ["izj"]
        assert result.ok and result.data is not None
        assert result.data["endpoints"][0]["host"] == "api.example.com"
        assert result.data["total"] == 1
    finally:
        service.close_all()


def test_service_r2_secrets_transforms_and_passthrough(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        ok = _success(
            _data(_str_item(f"k {_AWS}", 0x401000)),
            session_id="sess",
            backend="radare2",
        )
        monkeypatch.setattr(
            service_ext, "_r2_request", lambda *a, **k: ok
        )
        result = service.r2_secrets("sess")
        assert result.ok and result.data is not None
        assert result.data["secrets"][0]["detector"] == "aws_access_key_id"

        failure = _failure(RuntimeError("boom"), session_id="sess")
        monkeypatch.setattr(service_ext, "_r2_request", lambda *a, **k: failure)
        passthrough = service.r2_secrets("sess")
        assert passthrough.ok is False
    finally:
        service.close_all()


def test_r2_endpoints_secrets_docstrings_and_read_only() -> None:
    ep = " ".join(_tool_docstring("r2_endpoints").split())
    assert "izj" in ep and "vaddr" in ep and "hosts" in ep
    se = " ".join(_tool_docstring("r2_secrets").split())
    assert "izj" in se and "include_generic" in se and "detector" in se
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "r2.endpoints" in _READ_ONLY_NAMES
    assert "r2.secrets" in _READ_ONLY_NAMES
