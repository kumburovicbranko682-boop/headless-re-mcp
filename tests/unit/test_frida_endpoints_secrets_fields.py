"""frida.endpoints / frida.secrets scan the strings harvested from live memory.

These complete the strings->endpoints->secrets triad on the live-process line:
frida.strings harvests the printable runs, these run the shared endpoint /
secret scanners (finding_aggregate.py, the same the static lines use) over them,
each finding carrying the memory address for a frida.memory.read pivot. They
cover the pair builder (address carried, junk dropped), the service aggregation
(endpoint/host/path extraction, secret detection, address carry, scan_capped
from truncated, scanned_ranges passthrough, include_paths / include_generic,
name_filter, paging), the scan_limit threaded to the harvest, the device path,
failure passthrough, and the docstrings / read-only classification.

Secret-looking values are assembled from fragments at runtime so the contiguous
string never lands in the committed bytes (GitHub push protection).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.core import service_ext
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ext import _frida_string_pairs
from headless_re_mcp.tools.frida import build_frida_tools

_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"


def _tool_docstring(name: str) -> str:
    source = Path(build_frida_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_string_pairs_carry_address_and_drop_junk() -> None:
    data = {
        "strings": [
            {"address": "0x1000", "value": "https://api.example.com/v1"},
            {"address": "", "value": "no address"},
            {"value": "missing address"},
            "not-a-dict",
        ]
    }
    pairs = _frida_string_pairs(data)
    assert ("https://api.example.com/v1", {"address": "0x1000"}) in pairs
    assert ("no address", {}) in pairs
    assert ("missing address", {}) in pairs
    assert all(isinstance(text, str) for text, _ref in pairs)


def _harvest(*items: dict[str, Any], truncated: bool = False, scanned: int = 7) -> dict[str, Any]:
    return {
        "strings": list(items),
        "count": len(items),
        "scanned_ranges": scanned,
        "truncated": truncated,
    }


def _service_with_strings(monkeypatch: Any, captured: dict[str, Any], data: dict[str, Any]):
    class _FakeClient:
        def strings(self, pid: int, **kwargs: Any) -> dict[str, Any]:
            captured["pid"] = pid
            captured["local_kwargs"] = kwargs
            return data

        def strings_device(self, device_id: Any, pid: int, **kwargs: Any) -> dict[str, Any]:
            captured["device_id"] = device_id
            captured["device_pid"] = pid
            captured["device_kwargs"] = kwargs
            return data

    monkeypatch.setattr(service_ext, "FridaClient", lambda: _FakeClient())
    monkeypatch.setattr(service_ext, "_frida_device_target", lambda self, sid: None)
    monkeypatch.setattr(service_ext, "_require_debuggee_pid", lambda self, sid: 4321)


def test_frida_endpoints_extracts_and_carries_address(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}
    data = _harvest(
        {"address": "0x1000", "value": "https://api.example.com/v1/users"},
        {"address": "0x1100", "value": "/api/health"},
        {"address": "0x1200", "value": "nothing here"},
        truncated=True,
        scanned=9,
    )
    _service_with_strings(monkeypatch, captured, data)
    service = AnalysisService()
    try:
        sid = service.registry.create("https://example.invalid").id
        result = service.frida_endpoints(sid, scan_limit=1234)
        assert result.ok and result.data is not None
        by_value = {e["value"]: e for e in result.data["endpoints"]}
        users = by_value["https://api.example.com/v1/users"]
        assert users["host"] == "api.example.com"
        assert users["address"] == "0x1000"
        assert by_value["/api/health"]["kind"] == "path"
        assert result.data["hosts"] == ["api.example.com"]
        assert result.data["scan_capped"] is True
        assert result.data["scanned_ranges"] == 9
        # scan_limit is threaded to the harvest as the string limit.
        assert captured["local_kwargs"]["limit"] == 1234
    finally:
        service.close_all()


def test_frida_endpoints_include_paths_false_and_name_filter(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}
    data = _harvest(
        {"address": "0x1", "value": "https://alpha.example/a"},
        {"address": "0x2", "value": "https://beta.example/b"},
        {"address": "0x3", "value": "/api/things"},
    )
    _service_with_strings(monkeypatch, captured, data)
    service = AnalysisService()
    try:
        sid = service.registry.create("https://example.invalid").id
        only_urls = service.frida_endpoints(sid, include_paths=False)
        assert {e["kind"] for e in only_urls.data["endpoints"]} == {"url"}
        filtered = service.frida_endpoints(sid, name_filter="alpha")
        assert filtered.data["total"] == 1
        assert filtered.data["endpoints"][0]["host"] == "alpha.example"
    finally:
        service.close_all()


def test_frida_secrets_detects_and_carries_address(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}
    data = _harvest(
        {"address": "0x2000", "value": f"key={_AWS}"},
        {"address": "0x2100", "value": "harmless"},
        truncated=False,
        scanned=5,
    )
    _service_with_strings(monkeypatch, captured, data)
    service = AnalysisService()
    try:
        result = service.frida_secrets(service.registry.create("https://example.invalid").id)
        assert result.ok and result.data is not None
        row = result.data["secrets"][0]
        assert row["detector"] == "aws_access_key_id"
        assert row["value"] == _AWS
        assert row["address"] == "0x2000"
        assert result.data["scanned_ranges"] == 5
        assert result.data["detectors"] == ["aws_access_key_id"]
    finally:
        service.close_all()


def test_frida_secrets_generic_gated(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}
    token = "aB3xK9pQ7wZ2mN5vR8tY1cF4gH6jL0dS"
    data = _harvest({"address": "0x1", "value": token})
    _service_with_strings(monkeypatch, captured, data)
    service = AnalysisService()
    try:
        sid = service.registry.create("https://example.invalid").id
        off = service.frida_secrets(sid)
        assert not any(s["detector"] == "generic_high_entropy" for s in off.data["secrets"])
        on = service.frida_secrets(sid, include_generic=True)
        assert any(s["detector"] == "generic_high_entropy" for s in on.data["secrets"])
    finally:
        service.close_all()


def test_frida_endpoints_routes_to_device_when_bound(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}
    data = _harvest({"address": "0x1", "value": "https://c2.example/beacon"})

    class _FakeClient:
        def strings_device(self, device_id: Any, pid: int, **kwargs: Any) -> dict[str, Any]:
            captured["device_id"] = device_id
            captured["device_pid"] = pid
            captured["kwargs"] = kwargs
            return data

    monkeypatch.setattr(service_ext, "FridaClient", lambda: _FakeClient())
    monkeypatch.setattr(
        service_ext, "_frida_device_target", lambda self, sid: ("usb", 4242, [4242])
    )
    service = AnalysisService()
    try:
        result = service.frida_endpoints(
            service.registry.create("https://example.invalid").id, protection="rw-", scan_limit=999
        )
        assert result.ok and result.data is not None
        assert result.data["endpoints"][0]["host"] == "c2.example"
        assert captured["device_id"] == "usb"
        assert captured["device_pid"] == 4242
        assert captured["kwargs"]["protection"] == "rw-"
        assert captured["kwargs"]["limit"] == 999
    finally:
        service.close_all()


def test_frida_secrets_passes_backend_failure_through(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.frida.client import FridaError

    class _FakeClient:
        def strings(self, pid: int, **kwargs: Any) -> dict[str, Any]:
            raise FridaError("capability_unavailable", "frida not installed")

    monkeypatch.setattr(service_ext, "FridaClient", lambda: _FakeClient())
    monkeypatch.setattr(service_ext, "_frida_device_target", lambda self, sid: None)
    monkeypatch.setattr(service_ext, "_require_debuggee_pid", lambda self, sid: 4321)
    service = AnalysisService()
    try:
        result = service.frida_secrets(service.registry.create("https://example.invalid").id)
        assert result.ok is False
    finally:
        service.close_all()


def test_frida_endpoints_secrets_docstrings_and_read_only() -> None:
    ep = " ".join(_tool_docstring("frida.endpoints").split())
    assert "frida.memory.read" in ep and "address" in ep and "hosts" in ep
    se = " ".join(_tool_docstring("frida.secrets").split())
    assert "frida.memory.read" in se and "include_generic" in se and "detector" in se
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "frida.endpoints" in _READ_ONLY_NAMES
    assert "frida.secrets" in _READ_ONLY_NAMES
