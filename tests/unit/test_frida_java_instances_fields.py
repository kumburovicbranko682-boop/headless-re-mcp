"""frida.java.instances snapshots live heap objects via Java.choose.

The third leg of the Java surface after classes/methods: those enumerate what is
loaded and declared, this reflects the fields of the instances that exist right
now, so a runtime config/session/crypto object's values are readable. These
cover the record shaper (value truncation, junk dropped, field_count fallback),
the client "instances" mode (payload shape, the agent call args, has_more from
asking one past the cap, class_name required), the service routing (auth pid +
class_name + max_fields threaded through), and the tool docstring / read-only
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
    _shape_java_instance,
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


def test_shape_truncates_value_and_keeps_field_count() -> None:
    long_value = "x" * (_MAX_JAVA_FIELD_VALUE + 88)
    shaped = _shape_java_instance(
        {
            "fields": [
                {"name": "baseUrl", "type": "java.lang.String", "value": "https://api.x/"},
                {"name": "blob", "type": "java.lang.String", "value": long_value},
            ],
            "field_count": 7,
            "fields_truncated": True,
        },
        max_fields=64,
    )
    assert shaped["field_count"] == 7
    assert shaped["fields_truncated"] is True
    blob = shaped["fields"][1]
    assert len(blob["value"]) == _MAX_JAVA_FIELD_VALUE
    assert blob["value_truncated"] is True
    assert "value_truncated" not in shaped["fields"][0]


def test_shape_drops_junk_and_falls_back_to_len_for_field_count() -> None:
    shaped = _shape_java_instance(
        {"fields": [{"name": "a", "type": "int", "value": "1"}, "not-a-dict", 5]},
        max_fields=64,
    )
    # Only the well-formed row survives; field_count falls back to that length.
    assert [f["name"] for f in shaped["fields"]] == ["a"]
    assert shaped["field_count"] == 1
    assert shaped["fields_truncated"] is False


def test_shape_handles_a_non_dict_record() -> None:
    assert _shape_java_instance("nope", max_fields=8) == {
        "fields": [],
        "field_count": 0,
        "fields_truncated": False,
    }


class _InstancesApi:
    """Agent stub: honour the requested count, record how it was called."""

    def __init__(self, pool: int) -> None:
        self.pool = pool
        self.calls: list[tuple[Any, ...]] = []

    def instances(
        self, class_name: str, limit: int, max_fields: int, name_filter: str, max_value: int
    ) -> list[dict[str, Any]]:
        self.calls.append((class_name, limit, max_fields, name_filter, max_value))
        records = []
        for index in range(min(self.pool, int(limit))):
            records.append(
                {
                    "fields": [
                        {"name": "token", "type": "java.lang.String", "value": f"t{index}"},
                    ],
                    "field_count": 1,
                    "fields_truncated": False,
                }
            )
        return records


class _InstancesScript:
    def __init__(self, api: _InstancesApi) -> None:
        self.exports_sync = api

    def load(self) -> None:
        return None


class _InstancesSession:
    def __init__(self, api: _InstancesApi) -> None:
        self._api = api

    def create_script(self, source: str) -> _InstancesScript:
        del source
        return _InstancesScript(self._api)

    def detach(self) -> None:
        return None


class _InstancesDevice:
    def __init__(self, api: _InstancesApi, attached: list[int]) -> None:
        self._api = api
        self._attached = attached

    def attach(self, pid: int) -> _InstancesSession:
        self._attached.append(pid)
        return _InstancesSession(self._api)


def _client(api: _InstancesApi, attached: list[int]) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _InstancesDevice(api, attached)  # type: ignore[method-assign]
    return client


def test_instances_mode_shapes_payload_and_pages() -> None:
    api = _InstancesApi(pool=5)
    attached: list[int] = []
    payload = _client(api, attached).java_enumerate(
        None,
        4242,
        allowed_pids={4242},
        mode="instances",
        class_name="com.example.Config",
        name_filter="tok",
        limit=3,
        max_fields=16,
    )
    assert payload["class_name"] == "com.example.Config"
    assert payload["count"] == 3
    assert payload["has_more"] is True
    assert attached == [4242]
    first = payload["instances"][0]
    assert first["fields"][0]["name"] == "token"
    assert first["field_count"] == 1
    # The agent is asked for one past the page, with the caps/filter threaded in.
    assert api.calls == [("com.example.Config", 4, 16, "tok", _MAX_JAVA_FIELD_VALUE)]


def test_instances_mode_has_more_false_when_pool_fits() -> None:
    api = _InstancesApi(pool=2)
    payload = _client(api, []).java_enumerate(
        None, 4242, allowed_pids={4242}, mode="instances", class_name="Foo", limit=10
    )
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_instances_mode_requires_class_name() -> None:
    with pytest.raises(FridaError) as info:
        _client(_InstancesApi(pool=1), []).java_enumerate(
            None, 4242, allowed_pids={4242}, mode="instances", class_name="", limit=1
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


def test_service_frida_java_instances_threads_class_and_max_fields(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    class _FakeClient:
        def java_enumerate(self, device_id: Any, pid: int, **kwargs: Any) -> dict[str, Any]:
            captured["pid"] = pid
            captured["kwargs"] = kwargs
            return {
                "class_name": kwargs["class_name"],
                "instances": [
                    {
                        "fields": [
                            {"name": "apiKey", "type": "java.lang.String", "value": "secret"}
                        ],
                        "field_count": 1,
                        "fields_truncated": False,
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

    result = service.frida_java_instances(
        session.id, "com.example.Session", name_filter="Key", max_fields=8
    )
    assert result.ok and result.data is not None
    assert result.data["instances"][0]["fields"][0]["name"] == "apiKey"
    # The authorized pid is used, and the class/filter/caps are threaded through.
    assert captured["pid"] == 4242
    assert captured["kwargs"]["mode"] == "instances"
    assert captured["kwargs"]["class_name"] == "com.example.Session"
    assert captured["kwargs"]["name_filter"] == "Key"
    assert captured["kwargs"]["max_fields"] == 8


def test_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("frida.java.instances").split())
    assert "Java.choose" in doc
    assert "instances" in doc
    assert "field_count" in doc
    assert "name_filter" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "frida.java.instances" in _READ_ONLY_NAMES
