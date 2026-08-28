"""frida.java.static_fields reads a class's static fields without an instance.

The instance-free companion to frida.java.instances: instances needs a live
object on the heap, this reflects static fields off the Class itself
(f.get(null)), reaching the static final constants (hardcoded keys, base URLs)
in a utility/config class that never gets instantiated. These cover the per-field
shaper (value truncation, is_final passthrough, junk dropped), the client
"statics" mode (payload shape, agent call args, has_more from asking one past the
cap, class_name required), the service routing, and the docstring / read-only
classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import (
    _MAX_JAVA_FIELD_VALUE,
    FridaClient,
    FridaError,
    _shape_java_field,
)
from headless_re_mcp.core.service_frida import FridaDeviceMixin
from headless_re_mcp.core.session import SessionRegistry
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


def test_shape_field_truncates_and_carries_is_final() -> None:
    long_value = "k" * (_MAX_JAVA_FIELD_VALUE + 10)
    row = _shape_java_field(
        {"name": "API_KEY", "type": "java.lang.String", "value": long_value, "is_final": True}
    )
    assert row is not None
    assert row["name"] == "API_KEY"
    assert len(row["value"]) == _MAX_JAVA_FIELD_VALUE
    assert row["value_truncated"] is True
    assert row["is_final"] is True


def test_shape_field_omits_is_final_when_absent_and_drops_non_dict() -> None:
    row = _shape_java_field({"name": "x", "type": "int", "value": "1"})
    assert row is not None
    assert "is_final" not in row
    assert _shape_java_field("nope") is None


class _StaticsApi:
    """Agent stub: honour the requested count, record how it was called."""

    def __init__(self, pool: int) -> None:
        self.pool = pool
        self.calls: list[tuple[Any, ...]] = []

    def statics(
        self, class_name: str, limit: int, name_filter: str, max_value: int
    ) -> list[dict[str, Any]]:
        self.calls.append((class_name, limit, name_filter, max_value))
        rows = []
        for index in range(min(self.pool, int(limit))):
            rows.append(
                {
                    "name": f"KEY{index}",
                    "type": "java.lang.String",
                    "value": f"v{index}",
                    "is_final": True,
                }
            )
        return rows


class _StaticsScript:
    def __init__(self, api: _StaticsApi) -> None:
        self.exports_sync = api

    def load(self) -> None:
        return None


class _StaticsSession:
    def __init__(self, api: _StaticsApi) -> None:
        self._api = api

    def create_script(self, source: str) -> _StaticsScript:
        del source
        return _StaticsScript(self._api)

    def detach(self) -> None:
        return None


class _StaticsDevice:
    def __init__(self, api: _StaticsApi, attached: list[int]) -> None:
        self._api = api
        self._attached = attached

    def attach(self, pid: int) -> _StaticsSession:
        self._attached.append(pid)
        return _StaticsSession(self._api)


def _client(api: _StaticsApi, attached: list[int]) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _StaticsDevice(api, attached)  # type: ignore[method-assign]
    return client


def test_statics_mode_shapes_payload_and_pages() -> None:
    api = _StaticsApi(pool=5)
    attached: list[int] = []
    payload = _client(api, attached).java_enumerate(
        None,
        4242,
        allowed_pids={4242},
        mode="statics",
        class_name="com.example.Config",
        name_filter="KEY",
        limit=3,
    )
    assert payload["class_name"] == "com.example.Config"
    assert "instances" not in payload
    assert payload["count"] == 3
    assert payload["has_more"] is True
    assert attached == [4242]
    first = payload["fields"][0]
    assert first["name"] == "KEY0"
    assert first["is_final"] is True
    # The agent is asked for one past the page, with the filter/value cap threaded.
    assert api.calls == [("com.example.Config", 4, "KEY", _MAX_JAVA_FIELD_VALUE)]


def test_statics_mode_has_more_false_when_pool_fits() -> None:
    api = _StaticsApi(pool=2)
    payload = _client(api, []).java_enumerate(
        None, 4242, allowed_pids={4242}, mode="statics", class_name="Foo", limit=10
    )
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_statics_mode_requires_class_name() -> None:
    with pytest.raises(FridaError) as info:
        _client(_StaticsApi(pool=1), []).java_enumerate(
            None, 4242, allowed_pids={4242}, mode="statics", class_name="", limit=1
        )
    assert info.value.code == "invalid_params"


class _Repo:
    def record_backend(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def append_timeline(self, *args: object, **kwargs: object) -> None:
        del args, kwargs


class _Service(FridaDeviceMixin):
    def __init__(self) -> None:
        self.registry = SessionRegistry()
        self.repository = _Repo()


def test_service_frida_java_static_fields_threads_class_and_filter(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    class _FakeClient:
        def java_enumerate(self, device_id: Any, pid: int, **kwargs: Any) -> dict[str, Any]:
            captured["pid"] = pid
            captured["kwargs"] = kwargs
            return {
                "class_name": kwargs["class_name"],
                "fields": [
                    {
                        "name": "BASE_URL",
                        "type": "java.lang.String",
                        "value": "https://api.example.com",
                        "is_final": True,
                    }
                ],
                "count": 1,
                "has_more": False,
            }

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _FakeClient()
    )
    service = _Service()
    session = service.registry.create("https://example.invalid")
    service.registry.update_metadata(
        session.id,
        {"frida_authorized": {"device_id": "usb", "pids": [4242], "packages": []}},
    )

    result = service.frida_java_static_fields(
        session.id, "com.example.Config", name_filter="URL"
    )
    assert result.ok and result.data is not None
    assert result.data["fields"][0]["name"] == "BASE_URL"
    assert captured["pid"] == 4242
    assert captured["kwargs"]["mode"] == "statics"
    assert captured["kwargs"]["class_name"] == "com.example.Config"
    assert captured["kwargs"]["name_filter"] == "URL"


def test_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("frida.java.static_fields").split())
    assert "f.get(null)" in doc
    assert "is_final" in doc
    assert "name_filter" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "frida.java.static_fields" in _READ_ONLY_NAMES
