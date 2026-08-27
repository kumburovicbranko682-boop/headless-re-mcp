"""frida outputs must fit the transport budget by their encoded size.

memory_read returns hex (2 chars per byte), and modules/exports/applications/
java enumerations window by row count only, but a module path is unbounded, a
mangled export name or class name is long, and a package id can be 255 chars --
so a full read or page can encode past the 262144-byte result budget and be
discarded whole for a ~16 KiB summary. These tests drive real oversized outputs
through the real budget.
"""

from __future__ import annotations

import json
from typing import Any

from headless_re_mcp.backends.common.json_budget import RESULT_BUDGET_BYTES
from headless_re_mcp.backends.frida.client import FridaClient


def _encoded_size(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


class _ReadApi:
    def read(self, address: int, size: int) -> bytes:
        del address
        return b"\x00" * int(size)


class _ScriptWith:
    def __init__(self, api: Any) -> None:
        self.exports_sync = api

    def load(self) -> None:
        return None


class _SessionWith:
    def __init__(self, api: Any) -> None:
        self._api = api

    def create_script(self, source: str) -> _ScriptWith:
        del source
        return _ScriptWith(self._api)

    def detach(self) -> None:
        return None


class _FridaWith:
    def __init__(self, api: Any) -> None:
        self._api = api

    def attach(self, pid: int) -> _SessionWith:
        del pid
        return _SessionWith(self._api)


def _client_with(api: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = _FridaWith(api)
    return client


def test_memory_read_large_read_is_cut_to_fit_the_budget() -> None:
    # size 200000 -> 400000 hex chars, ~2x the whole budget. The read must come
    # back cut to the bytes whose hex fits, with returned/truncated set so the
    # caller can continue from address+returned.
    client = _client_with(_ReadApi())

    payload = client.memory_read(1, 0, 200_000, allowed_pid=1)

    assert payload["truncated"] is True
    assert payload["size"] == 200_000
    assert 0 < payload["returned"] < 200_000
    assert len(payload["data"]) == payload["returned"] * 2
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_memory_read_small_read_is_returned_whole() -> None:
    client = _client_with(_ReadApi())

    payload = client.memory_read(1, 0, 16, allowed_pid=1)

    assert payload["truncated"] is False
    assert payload["returned"] == 16
    assert len(payload["data"]) == 32
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


class _ModulesApi:
    def modules(self, limit: int = 64) -> list[dict[str, Any]]:
        del limit
        return [
            {"name": f"m{index}", "base": "0x1", "size": 1, "path": "/data/app/" + "p" * 2000}
            for index in range(256)
        ]


def test_modules_page_is_trimmed_to_the_encoded_budget() -> None:
    client = _client_with(_ModulesApi())

    payload = client.modules(1, allowed_pid=1, limit=256)

    assert 0 < payload["count"] < 256
    assert len(payload["modules"]) == payload["count"]
    assert payload["total"] == 256
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


class _ExportsApi:
    def exports(self, name: str, count: int) -> dict[str, Any]:
        del count
        return {
            "found": True,
            "module": name,
            "base": "0x1",
            "exports": [
                {"name": "_Z" + "n" * 1000 + str(index), "address": "0x2", "type": "function"}
                for index in range(512)
            ],
        }


def test_exports_page_is_trimmed_to_the_encoded_budget() -> None:
    # 512 exports with ~1000-char mangled names, limit 512: the row cap is not
    # exceeded (exactly 512), so has_more must come from the size budget.
    client = _client_with(_ExportsApi())

    payload = client.exports(1, "libc.so", allowed_pid=1, limit=512)

    assert 0 < payload["count"] < 512
    assert len(payload["exports"]) == payload["count"]
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


class _JavaApi:
    def classes(self, name_filter: str, count: int) -> list[str]:
        del name_filter, count
        return ["com.example." + "C" * 200 + str(index) for index in range(2000)]

    def methods(self, class_name: str, count: int) -> list[str]:
        del class_name, count
        return ["method" + "M" * 200 + str(index) for index in range(2000)]


class _JavaDevice:
    def __init__(self, api: Any) -> None:
        self._api = api

    def attach(self, pid: int) -> _SessionWith:
        del pid
        return _SessionWith(self._api)


def _java_client(api: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _JavaDevice(api)  # type: ignore[method-assign]
    return client


def test_java_classes_page_is_trimmed_to_the_encoded_budget() -> None:
    client = _java_client(_JavaApi())

    payload = client.java_enumerate(None, 1, allowed_pids={1}, mode="classes", limit=2000)

    assert 0 < payload["count"] < 2000
    assert len(payload["classes"]) == payload["count"]
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_java_methods_page_is_trimmed_to_the_encoded_budget() -> None:
    client = _java_client(_JavaApi())

    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="methods", class_name="Foo", limit=2000
    )

    assert 0 < payload["count"] < 2000
    assert len(payload["methods"]) == payload["count"]
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


class _App:
    def __init__(self, index: int) -> None:
        self.identifier = "com.example." + "a" * 240 + str(index)
        self.name = f"App{index}"
        self.pid = 0


class _AppDevice:
    def enumerate_applications(self) -> list[_App]:
        return [_App(index) for index in range(1000)]


def test_applications_page_is_trimmed_to_the_encoded_budget() -> None:
    client = FridaClient()
    client._resolve_device = lambda device_id: _AppDevice()  # type: ignore[method-assign]

    payload = client.applications("usb", limit=1000)

    assert 0 < payload["count"] < 1000
    assert len(payload["applications"]) == payload["count"]
    assert payload["total"] == 1000
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES
