"""frida.memory.ranges lists the target's mapped memory regions.

The map that makes frida.memory.read usable: read needs an address, and this is
how you learn which addresses are mapped, what they permit, and what is backing
them. These fake the enumeration probe (exports_sync.ranges, mirroring the agent:
protection selector first, then a file-path substring filter, then the cap) and
cover paging/has_more, the name_filter reaching past the cap, the protection mask
being handed to the enumerator, protection validation, the device path, service
routing and the read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

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


class _RangeApi:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []

    def ranges(self, protection: str, name_filter: str, limit: int) -> dict[str, Any]:
        self.calls.append((protection, name_filter, int(limit)))
        rows = [
            {
                "base": f"0x{(index + 1) * 0x1000:x}",
                "size": 4096,
                "protection": "rw-",
                "file": f"/system/lib/lib{index}.so",
            }
            for index in range(25)
        ]
        if name_filter:
            rows = [row for row in rows if name_filter in row["file"]]
        return {"ranges": rows[: max(0, int(limit))], "total": len(rows)}


class _RangeScript:
    def __init__(self, api: _RangeApi) -> None:
        self.exports_sync = api

    def load(self) -> None:
        return None


class _RangeSession:
    def __init__(self, api: _RangeApi) -> None:
        self._api = api

    def create_script(self, source: str) -> _RangeScript:
        del source
        return _RangeScript(self._api)

    def detach(self) -> None:
        return None


def _range_client(api: _RangeApi) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = lambda pid, **kwargs: _RangeSession(api)  # type: ignore[method-assign]
    return client


def test_frida_ranges_says_when_the_page_is_not_the_whole_map() -> None:
    """25 ranges behind a page of 10 -> count 10, total 25, has_more True.

    Each row carries base, size, protection and file so a caller can pick a
    region to hand frida.memory.read; a full page read as the whole map would
    miss the rest.
    """
    api = _RangeApi()
    payload = _range_client(api).ranges(1, allowed_pid=1, limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True
    first = payload["ranges"][0]
    assert set(first) == {"base", "size", "protection", "file"}
    assert first["base"] == "0x1000"
    assert first["protection"] == "rw-"


def test_frida_ranges_name_filter_reaches_a_mapping_past_the_page() -> None:
    """No offset, so a specific library's mapping must be reachable by path.

    Filter 'lib2' against the 25-range fake matches lib2 and lib20..lib24 ->
    total 6, drawn only from matches.
    """
    api = _RangeApi()
    payload = _range_client(api).ranges(1, allowed_pid=1, limit=64, name_filter="lib2")
    files = {row["file"] for row in payload["ranges"]}
    assert files == {f"/system/lib/lib{n}.so" for n in ("2", "20", "21", "22", "23", "24")}
    assert payload["total"] == 6
    assert payload["has_more"] is False


def test_frida_ranges_hands_the_protection_mask_to_the_enumerator() -> None:
    """The protection selector is passed through, defaulting to readable regions."""
    api = _RangeApi()
    client = _range_client(api)
    client.ranges(1, allowed_pid=1, limit=5)
    client.ranges(1, allowed_pid=1, limit=5, protection="rw-")
    assert [call[0] for call in api.calls] == ["r--", "rw-"]


@pytest.mark.parametrize("protection", ["rwxr", "abc", "r-", "", "RWX", "r_x"])
def test_frida_ranges_rejects_a_bad_protection_before_attach(protection: str) -> None:
    """A mask off [r-][w-][x-] is invalid_params and never attaches."""
    attached = {"count": 0}

    def _attach(pid: int, **kwargs: Any) -> _RangeSession:
        attached["count"] += 1
        return _RangeSession(_RangeApi())

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = _attach  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.ranges(1, allowed_pid=1, protection=protection)
    assert caught.value.code == "invalid_params"
    assert attached["count"] == 0


def test_frida_ranges_device_path_enumerates_on_the_resolved_device() -> None:
    """The device analogue authorizes the pid, attaches on the device, enumerates."""
    api = _RangeApi()

    class _RangeDevice:
        def attach(self, pid: int) -> _RangeSession:
            del pid
            return _RangeSession(api)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _RangeDevice()  # type: ignore[method-assign]
    payload = client.ranges_device(
        "usb", 4242, allowed_pids={4242}, protection="--x", limit=10
    )
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert api.calls[0][0] == "--x"


def test_service_frida_memory_ranges_routes_to_local_debuggee(monkeypatch: Any) -> None:
    """With no device auth, the service targets the local debuggee pid."""
    from headless_re_mcp.core import service_ext
    from headless_re_mcp.core.service import AnalysisService

    captured: dict[str, Any] = {}

    class _FakeClient:
        def ranges(self, pid: int, **kwargs: Any) -> dict[str, Any]:
            captured["pid"] = pid
            captured.update(kwargs)
            return {"ranges": [], "count": 0, "total": 0, "has_more": False}

    service = AnalysisService()
    try:
        session = service.registry.create("https://example.invalid")
        monkeypatch.setattr(service_ext, "FridaClient", lambda: _FakeClient())
        monkeypatch.setattr(service_ext, "_frida_device_target", lambda self, sid: None)
        monkeypatch.setattr(service_ext, "_require_debuggee_pid", lambda self, sid: 4321)
        result = service.frida_memory_ranges(
            session.id, protection="rw-", limit=7, name_filter="libssl"
        )
        assert result.ok and result.data is not None
        assert captured["pid"] == 4321
        assert captured["allowed_pid"] == 4321
        assert captured["protection"] == "rw-"
        assert captured["limit"] == 7
        assert captured["name_filter"] == "libssl"
    finally:
        service.close_all()


def test_frida_ranges_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("frida.memory.ranges").split())
    assert "protection" in doc
    assert "has_more" in doc
    assert "file" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "frida.memory.ranges" in _READ_ONLY_NAMES
