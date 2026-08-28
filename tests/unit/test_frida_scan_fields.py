"""frida.memory.scan searches the target's live memory for a byte pattern.

The payoff of frida.memory.ranges: it shows the map, this finds a needle in it --
a runtime-decrypted key or a struct signature that exists only in the running
process becomes an address to hand frida.memory.read. These fake the scan probe
(exports_sync.scan, mirroring the agent: a protection mask, a Frida match
pattern, and the match/range/byte ceilings) and cover the result shape, the
text->hex and hex pattern normalization handed to scanSync, pattern and
protection validation, the truncated signal, limit capping, the device path,
service routing and the read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida import client as frida_client
from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.tools.frida import build_frida_tools


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


class _ScanApi:
    def __init__(self, total: int = 25) -> None:
        self.calls: list[tuple[str, str, int, int, int]] = []
        self.total = total

    def scan(
        self,
        protection: str,
        pattern: str,
        max_matches: int,
        max_ranges: int,
        max_bytes: int,
    ) -> dict[str, Any]:
        self.calls.append((protection, pattern, int(max_matches), int(max_ranges), int(max_bytes)))
        rows = [
            {
                "address": f"0x{(index + 1) * 0x10:x}",
                "size": 4,
                "protection": "rw-",
                "file": "/system/lib/libc.so",
            }
            for index in range(self.total)
        ]
        return {
            "matches": rows[: max(0, int(max_matches))],
            "scanned_ranges": 12,
            "truncated": self.total > int(max_matches),
        }


class _ScanScript:
    def __init__(self, api: _ScanApi) -> None:
        self.exports_sync = api

    def load(self) -> None:
        return None


class _ScanSession:
    def __init__(self, api: _ScanApi) -> None:
        self._api = api

    def create_script(self, source: str) -> _ScanScript:
        del source
        return _ScanScript(self._api)

    def detach(self) -> None:
        return None


def _scan_client(api: _ScanApi) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = lambda pid, **kwargs: _ScanSession(api)  # type: ignore[method-assign]
    return client


def test_frida_scan_returns_matches_with_addresses() -> None:
    """A hit carries the address, size, protection and backing file.

    3 matches, generous limit -> count 3, truncated False, and each row names
    an address a caller can hand to frida.memory.read.
    """
    api = _ScanApi(total=3)
    payload = _scan_client(api).scan(1, allowed_pid=1, pattern="token", limit=64)
    assert payload["count"] == 3
    assert payload["truncated"] is False
    assert payload["scanned_ranges"] == 12
    first = payload["matches"][0]
    assert set(first) == {"address", "size", "protection", "file"}
    assert first["address"] == "0x10"


def test_frida_scan_encodes_text_pattern_to_hex_bytes() -> None:
    """pattern_type text utf-8 encodes the needle before it reaches scanSync."""
    api = _ScanApi(total=1)
    _scan_client(api).scan(1, allowed_pid=1, pattern="AB", pattern_type="text")
    assert api.calls[0][1] == "41 42"


def test_frida_scan_normalizes_a_hex_pattern() -> None:
    """A hex pattern is lowercased, comma/space split, and wildcards kept."""
    api = _ScanApi(total=1)
    _scan_client(api).scan(
        1, allowed_pid=1, pattern="DE,AD ?? EF", pattern_type="hex"
    )
    assert api.calls[0][1] == "de ad ?? ef"


def test_frida_scan_hands_bounds_and_protection_to_the_agent() -> None:
    """The match/range/byte ceilings and the protection mask are passed through."""
    api = _ScanApi(total=1)
    _scan_client(api).scan(1, allowed_pid=1, pattern="x", protection="rw-", limit=50)
    protection, _pattern, max_matches, max_ranges, max_bytes = api.calls[0]
    assert protection == "rw-"
    assert max_matches == 50
    assert max_ranges == frida_client._MAX_SCAN_RANGES
    assert max_bytes == frida_client._MAX_SCAN_BYTES_PER_RANGE


def test_frida_scan_caps_limit_at_the_ceiling() -> None:
    """A caller asking past the hard cap gets the cap, not an unbounded scan."""
    api = _ScanApi(total=1)
    _scan_client(api).scan(1, allowed_pid=1, pattern="x", limit=99999)
    assert api.calls[0][2] == frida_client._MAX_SCAN_MATCHES


def test_frida_scan_reports_truncated_when_the_match_cap_is_hit() -> None:
    """25 hits behind a limit of 10 -> count 10, truncated True."""
    api = _ScanApi(total=25)
    payload = _scan_client(api).scan(1, allowed_pid=1, pattern="x", limit=10)
    assert payload["count"] == 10
    assert payload["truncated"] is True


@pytest.mark.parametrize(
    ("pattern", "pattern_type"),
    [
        ("", "text"),
        ("   ", "text"),
        ("zz", "hex"),
        ("de a", "hex"),
        ("?? ??", "hex"),
        ("dead", "hex"),
        ("de ad", "utf8"),
    ],
)
def test_frida_scan_rejects_a_bad_pattern_before_attach(
    pattern: str, pattern_type: str
) -> None:
    """A malformed/empty/all-wildcard pattern is invalid_params and never attaches."""
    attached = {"count": 0}

    def _attach(pid: int, **kwargs: Any) -> _ScanSession:
        attached["count"] += 1
        return _ScanSession(_ScanApi())

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = _attach  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.scan(1, allowed_pid=1, pattern=pattern, pattern_type=pattern_type)
    assert caught.value.code == "invalid_params"
    assert attached["count"] == 0


def test_frida_scan_rejects_a_bad_protection_before_attach() -> None:
    attached = {"count": 0}

    def _attach(pid: int, **kwargs: Any) -> _ScanSession:
        attached["count"] += 1
        return _ScanSession(_ScanApi())

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = _attach  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.scan(1, allowed_pid=1, pattern="de ad", pattern_type="hex", protection="xyz")
    assert caught.value.code == "invalid_params"
    assert attached["count"] == 0


def test_frida_scan_device_path_scans_on_the_resolved_device() -> None:
    api = _ScanApi(total=3)

    class _ScanDevice:
        def attach(self, pid: int) -> _ScanSession:
            del pid
            return _ScanSession(api)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _ScanDevice()  # type: ignore[method-assign]
    payload = client.scan_device(
        "usb", 4242, allowed_pids={4242}, pattern="AB", protection="rw-", limit=10
    )
    assert payload["count"] == 3
    assert api.calls[0][0] == "rw-"
    assert api.calls[0][1] == "41 42"


def test_service_frida_memory_scan_routes_to_local_debuggee(monkeypatch: Any) -> None:
    """With no device auth, the service targets the local debuggee pid."""
    from headless_re_mcp.core import service_ext
    from headless_re_mcp.core.service import AnalysisService

    captured: dict[str, Any] = {}

    class _FakeClient:
        def scan(self, pid: int, **kwargs: Any) -> dict[str, Any]:
            captured["pid"] = pid
            captured.update(kwargs)
            return {"matches": [], "count": 0, "scanned_ranges": 0, "truncated": False}

    service = AnalysisService()
    try:
        session = service.registry.create("https://example.invalid")
        monkeypatch.setattr(service_ext, "FridaClient", lambda: _FakeClient())
        monkeypatch.setattr(service_ext, "_frida_device_target", lambda self, sid: None)
        monkeypatch.setattr(service_ext, "_require_debuggee_pid", lambda self, sid: 4321)
        result = service.frida_memory_scan(
            session.id, "sk-secret", pattern_type="text", protection="rw-", limit=9
        )
        assert result.ok and result.data is not None
        assert captured["pid"] == 4321
        assert captured["allowed_pid"] == 4321
        assert captured["pattern"] == "sk-secret"
        assert captured["pattern_type"] == "text"
        assert captured["protection"] == "rw-"
        assert captured["limit"] == 9
    finally:
        service.close_all()


def test_frida_scan_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("frida.memory.scan").split())
    assert "matches" in doc
    assert "truncated" in doc
    assert "scanned_ranges" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "frida.memory.scan" in _READ_ONLY_NAMES
