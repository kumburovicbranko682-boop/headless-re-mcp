"""frida.strings harvests printable strings from a live process's memory.

The runtime counterpart to r2.strings / apk.strings: where those read a file on
disk, this walks the ranges a protection mask selects and pulls every printable
ASCII run out of the running process, reaching strings that only exist decrypted
at runtime. Where frida.memory.scan needs a known needle, this is the discovery
step. These fake the strings probe (exports_sync.strings, mirroring the agent's
protection / min length / match / range / byte / value ceilings and filter) and
cover the result shape (address + value for a frida.memory.read pivot), value
truncation, the bounds/protection/min_length/filter handed to the agent, limit
capping, the truncated signal, min_length and protection validation before
attach, the device path, service routing and the read-only classification.
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


class _StringsApi:
    def __init__(self, total: int = 25) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.total = total

    def strings(
        self,
        protection: str,
        min_len: int,
        max_strings: int,
        max_ranges: int,
        max_bytes: int,
        max_value: int,
        name_filter: str,
    ) -> dict[str, Any]:
        self.calls.append(
            (
                protection,
                int(min_len),
                int(max_strings),
                int(max_ranges),
                int(max_bytes),
                int(max_value),
                name_filter,
            )
        )
        rows = [
            {"address": f"0x{(index + 1) * 0x10:x}", "value": f"str{index}"}
            for index in range(self.total)
        ]
        return {
            "strings": rows[: max(0, int(max_strings))],
            "scanned_ranges": 8,
            "truncated": self.total > int(max_strings),
        }


class _StringsScript:
    def __init__(self, api: _StringsApi) -> None:
        self.exports_sync = api

    def load(self) -> None:
        return None


class _StringsSession:
    def __init__(self, api: _StringsApi) -> None:
        self._api = api

    def create_script(self, source: str) -> _StringsScript:
        del source
        return _StringsScript(self._api)

    def detach(self) -> None:
        return None


def _strings_client(api: _StringsApi) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = lambda pid, **kwargs: _StringsSession(api)  # type: ignore[method-assign]
    return client


def test_frida_strings_returns_address_and_value() -> None:
    api = _StringsApi(total=3)
    payload = _strings_client(api).strings(1, allowed_pid=1, limit=64)
    assert payload["count"] == 3
    assert payload["truncated"] is False
    assert payload["scanned_ranges"] == 8
    first = payload["strings"][0]
    assert set(first) == {"address", "value"}
    assert first["address"] == "0x10"
    assert first["value"] == "str0"


def test_frida_strings_marks_a_long_value_truncated() -> None:
    class _LongApi(_StringsApi):
        def strings(self, *args: Any) -> dict[str, Any]:
            self.calls.append(args)
            long_value = "z" * (frida_client._MAX_STRING_VALUE + 20)
            return {
                "strings": [
                    {"address": "0x10", "value": long_value},
                    {"address": "0x20", "value": "short", "value_truncated": True},
                ],
                "scanned_ranges": 1,
                "truncated": False,
            }

    payload = _strings_client(_LongApi()).strings(1, allowed_pid=1)
    clipped = payload["strings"][0]
    assert len(clipped["value"]) == frida_client._MAX_STRING_VALUE
    assert clipped["value_truncated"] is True
    # The agent may also flag a run it clipped even when the shaper did not cut.
    assert payload["strings"][1]["value_truncated"] is True


def test_frida_strings_hands_bounds_protection_min_len_and_filter() -> None:
    api = _StringsApi(total=1)
    _strings_client(api).strings(
        1, allowed_pid=1, protection="rw-", min_length=6, limit=50, name_filter="http"
    )
    prot, min_len, max_strings, max_ranges, max_bytes, max_value, name_filter = api.calls[0]
    assert prot == "rw-"
    assert min_len == 6
    assert max_strings == 50
    assert max_ranges == frida_client._MAX_SCAN_RANGES
    assert max_bytes == frida_client._MAX_SCAN_BYTES_PER_RANGE
    assert max_value == frida_client._MAX_STRING_VALUE
    assert name_filter == "http"


def test_frida_strings_caps_limit_at_the_ceiling() -> None:
    api = _StringsApi(total=1)
    _strings_client(api).strings(1, allowed_pid=1, limit=999999)
    assert api.calls[0][2] == frida_client._MAX_STRINGS


def test_frida_strings_reports_truncated_when_the_cap_is_hit() -> None:
    api = _StringsApi(total=25)
    payload = _strings_client(api).strings(1, allowed_pid=1, limit=10)
    assert payload["count"] == 10
    assert payload["truncated"] is True


@pytest.mark.parametrize("min_length", [0, 65, 4.0, True, -1])
def test_frida_strings_rejects_a_bad_min_length_before_attach(min_length: Any) -> None:
    attached = {"count": 0}

    def _attach(pid: int, **kwargs: Any) -> _StringsSession:
        attached["count"] += 1
        return _StringsSession(_StringsApi())

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = _attach  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.strings(1, allowed_pid=1, min_length=min_length)
    assert caught.value.code == "invalid_params"
    assert attached["count"] == 0


def test_frida_strings_rejects_a_bad_protection_before_attach() -> None:
    attached = {"count": 0}

    def _attach(pid: int, **kwargs: Any) -> _StringsSession:
        attached["count"] += 1
        return _StringsSession(_StringsApi())

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = _attach  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.strings(1, allowed_pid=1, protection="xyz")
    assert caught.value.code == "invalid_params"
    assert attached["count"] == 0


def test_frida_strings_device_path_harvests_on_the_resolved_device() -> None:
    api = _StringsApi(total=3)

    class _StringsDevice:
        def attach(self, pid: int) -> _StringsSession:
            del pid
            return _StringsSession(api)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _StringsDevice()  # type: ignore[method-assign]
    payload = client.strings_device(
        "usb", 4242, allowed_pids={4242}, protection="rw-", min_length=5, limit=10
    )
    assert payload["count"] == 3
    assert api.calls[0][0] == "rw-"
    assert api.calls[0][1] == 5


def test_service_frida_strings_routes_to_local_debuggee(monkeypatch: Any) -> None:
    from headless_re_mcp.core import service_ext
    from headless_re_mcp.core.service import AnalysisService

    captured: dict[str, Any] = {}

    class _FakeClient:
        def strings(self, pid: int, **kwargs: Any) -> dict[str, Any]:
            captured["pid"] = pid
            captured.update(kwargs)
            return {"strings": [], "count": 0, "scanned_ranges": 0, "truncated": False}

    service = AnalysisService()
    try:
        session = service.registry.create("https://example.invalid")
        monkeypatch.setattr(service_ext, "FridaClient", lambda: _FakeClient())
        monkeypatch.setattr(service_ext, "_frida_device_target", lambda self, sid: None)
        monkeypatch.setattr(service_ext, "_require_debuggee_pid", lambda self, sid: 4321)
        result = service.frida_strings(
            session.id, protection="rw-", min_length=6, limit=9, name_filter="tok"
        )
        assert result.ok and result.data is not None
        assert captured["pid"] == 4321
        assert captured["allowed_pid"] == 4321
        assert captured["protection"] == "rw-"
        assert captured["min_length"] == 6
        assert captured["limit"] == 9
        assert captured["name_filter"] == "tok"
    finally:
        service.close_all()


def test_frida_strings_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("frida.strings").split())
    assert "strings" in doc
    assert "address" in doc
    assert "scanned_ranges" in doc
    assert "min_length" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "frida.strings" in _READ_ONLY_NAMES
