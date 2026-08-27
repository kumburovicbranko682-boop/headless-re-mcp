"""frida.java.classes / frida.java.methods must bound their string inputs.

Every other string that crosses a backend boundary in this codebase is guarded
in the backend -- ADB serials and package names, the web selector, frida's
module_name -- but ``java_enumerate`` used to pass ``class_name`` and
``name_filter`` straight across the Frida RPC to the device with no type check
and no length ceiling, while the tool layer bounds only ``limit``. They are
marshalled as RPC data (never interpolated into the fixed script), so this is a
resource/marshalling bound rather than an injection guard: the point is that a
caller cannot ship a megabyte string to the device on every call, and that a
malformed input fails *before* any device is resolved or attached, the same
fail-fast ordering ``install``/``push`` use for their cheap local checks.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.backends.frida.client import (
    _MAX_JAVA_NAME_BYTES,
    FridaClient,
    FridaError,
)
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.frida import build_frida_tools


def _tool_schema(name: str) -> dict[str, Any]:
    """The JSON input schema for the tool declared with @tools.tool(name=...).

    Built with a dummy analysis: the handlers close over it only when called,
    and input_schema_for reads the signature only, so no live service is needed
    to see the parameter bounds the schema advertises to a client.
    """
    for bound in build_frida_tools(cast(Any, object())):
        if bound.name == name:
            return input_schema_for(bound.handler)
    raise AssertionError(f"no such frida tool: {name}")


def _tool_docstring(name: str) -> str:
    """The docstring of the tool declared with @tools.tool(name=...).

    Read from source via AST rather than importing the closure, matching how
    test_frida_fields.py inspects these -- the tool functions are defined
    inside build_frida_tools and are not otherwise reachable.
    """
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


class _RecordingApi:
    """A java RPC surface that records exactly what reached the script."""

    def __init__(self) -> None:
        self.classes_args: list[tuple[str, int]] = []
        self.methods_args: list[tuple[str, int]] = []

    def classes(self, name_filter: str, count: int) -> list[str]:
        self.classes_args.append((name_filter, int(count)))
        return [f"c{index}" for index in range(int(count))]

    def methods(self, class_name: str, count: int) -> dict[str, Any]:
        self.methods_args.append((class_name, int(count)))
        return {"found": True, "methods": [f"m{index}" for index in range(int(count))]}


def _client(api: _RecordingApi) -> tuple[FridaClient, list[str], list[int]]:
    """A client whose device resolution and attach are both observable.

    ``resolved`` and ``attached`` stay empty when a guard refuses the input
    before any device work -- that is the fail-fast property under test.
    """
    resolved: list[str] = []
    attached: list[int] = []

    script = type("_S", (), {"exports_sync": api, "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, source: script, "detach": lambda self: None},
    )()

    class _Device:
        def attach(self, pid: int) -> object:
            attached.append(pid)
            return session

    def _resolve(device_id: str | None) -> _Device:
        resolved.append(str(device_id))
        return _Device()

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = _resolve  # type: ignore[method-assign]
    return client, resolved, attached


def test_class_name_is_required_and_the_device_is_never_touched_when_missing() -> None:
    client, resolved, attached = _client(_RecordingApi())
    for bad in ("", "   ", "\t\n"):
        with pytest.raises(FridaError) as caught:
            client.java_enumerate(None, 1, allowed_pids={1}, mode="methods", class_name=bad)
        assert caught.value.code == "invalid_params"
    assert resolved == []
    assert attached == []


def test_class_name_over_the_cap_fails_before_any_device_work() -> None:
    client, resolved, attached = _client(_RecordingApi())
    over = "x" * (_MAX_JAVA_NAME_BYTES + 1)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="methods", class_name=over)
    assert caught.value.code == "invalid_params"
    assert caught.value.details.get("limit") == _MAX_JAVA_NAME_BYTES
    # The guard runs before _resolve_device, so a hostile length never reaches
    # a device attach -- it is refused as the cheap local fact it is.
    assert resolved == []
    assert attached == []


def test_class_name_at_the_cap_is_accepted_and_reaches_the_script() -> None:
    api = _RecordingApi()
    client, resolved, attached = _client(api)
    at_cap = "a" * _MAX_JAVA_NAME_BYTES
    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="methods", class_name=at_cap, limit=5
    )
    assert payload["class_name"] == at_cap
    assert payload["found"] is True
    assert resolved == ["None"]
    assert attached == [1]
    assert api.methods_args and api.methods_args[0][0] == at_cap


def test_class_name_with_a_nul_byte_is_refused() -> None:
    client, resolved, attached = _client(_RecordingApi())
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(
            None, 1, allowed_pids={1}, mode="methods", class_name="com.x\x00.Y"
        )
    assert caught.value.code == "invalid_params"
    assert resolved == []
    assert attached == []


def test_a_non_string_class_name_is_refused_before_any_device_work() -> None:
    """The MCP schema types class_name as a string, but the agent and OpenAI
    transports call the backend directly and skip that validation. The backend
    must therefore reject a non-string itself -- as invalid_params, before any
    device is resolved -- rather than marshalling an int across the RPC."""
    client, resolved, attached = _client(_RecordingApi())
    for bad in (123, ["Foo"], object()):
        with pytest.raises(FridaError) as caught:
            client.java_enumerate(
                None, 1, allowed_pids={1}, mode="methods", class_name=bad
            )
        assert caught.value.code == "invalid_params"
        assert "class_name must be a string" in caught.value.message
    assert resolved == []
    assert attached == []


def test_class_name_is_stripped_before_it_reaches_the_device() -> None:
    api = _RecordingApi()
    client, _resolved, _attached = _client(api)
    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="methods", class_name="  com.example.Foo  ", limit=3
    )
    assert payload["class_name"] == "com.example.Foo"
    assert api.methods_args[0][0] == "com.example.Foo"


def test_name_filter_over_the_cap_fails_before_any_device_work() -> None:
    client, resolved, attached = _client(_RecordingApi())
    over = "y" * (_MAX_JAVA_NAME_BYTES + 1)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes", name_filter=over)
    assert caught.value.code == "invalid_params"
    assert caught.value.details.get("limit") == _MAX_JAVA_NAME_BYTES
    assert resolved == []
    assert attached == []


def test_name_filter_with_a_nul_byte_is_refused() -> None:
    client, resolved, attached = _client(_RecordingApi())
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(
            None, 1, allowed_pids={1}, mode="classes", name_filter="com\x00"
        )
    assert caught.value.code == "invalid_params"
    assert resolved == []
    assert attached == []


def test_a_non_string_name_filter_is_refused_before_any_device_work() -> None:
    """Like class_name, a name_filter that bypasses the schema as a non-string
    (None is the only non-string accepted, meaning 'no filter') is refused up
    front rather than shipped to the device as a malformed RPC argument."""
    client, resolved, attached = _client(_RecordingApi())
    for bad in (123, ["x"], object()):
        with pytest.raises(FridaError) as caught:
            client.java_enumerate(
                None, 1, allowed_pids={1}, mode="classes", name_filter=bad
            )
        assert caught.value.code == "invalid_params"
        assert "name_filter must be a string" in caught.value.message
    assert resolved == []
    assert attached == []


def test_name_filter_is_optional_and_empty_reaches_the_script_unchanged() -> None:
    api = _RecordingApi()
    client, resolved, attached = _client(api)
    # Neither passing a filter nor passing None should be refused; both mean
    # "no filter" and the script receives the empty string.
    for value in (None, ""):
        payload = client.java_enumerate(
            None, 1, allowed_pids={1}, mode="classes", name_filter=value, limit=4
        )
        assert payload["count"] == 4
    assert api.classes_args and all(args[0] == "" for args in api.classes_args)
    assert resolved == ["None", "None"]
    assert attached == [1, 1]


def test_a_normal_filter_is_passed_through_verbatim() -> None:
    api = _RecordingApi()
    client, _resolved, _attached = _client(api)
    client.java_enumerate(
        None, 1, allowed_pids={1}, mode="classes", name_filter="javax.crypto", limit=2
    )
    assert api.classes_args[0][0] == "javax.crypto"


def test_an_unknown_mode_is_refused_before_any_device_work() -> None:
    client, resolved, attached = _client(_RecordingApi())
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="fields")
    assert caught.value.code == "invalid_params"
    assert caught.value.details.get("mode") == "fields"
    assert resolved == []
    assert attached == []


def test_the_tool_docstrings_publish_the_input_bound() -> None:
    """The bound is only useful if an agent can learn it from the tool schema.

    This codebase treats tool docstrings as the published contract, so the
    guard added in the backend must also be named where a caller reads it --
    otherwise the first sign of the 512-byte / NUL rule is an invalid_params
    the agent could not have anticipated.
    """
    classes_doc = _tool_docstring("frida.java.classes")
    assert "name_filter" in classes_doc
    assert "512" in classes_doc
    assert "invalid_params" in classes_doc

    methods_doc = _tool_docstring("frida.java.methods")
    assert "class_name is required" in methods_doc
    assert "512" in methods_doc
    assert "invalid_params" in methods_doc


@pytest.mark.parametrize("tool", ["frida.java.classes", "frida.java.methods"])
def test_the_tool_pid_is_bounded_non_negative_at_the_schema(tool: str) -> None:
    """pid is an OS process id: its only sentinel is 0 (most recent spawn), and a
    negative value is never a pid. The sibling PE tool dynamic.attach already
    bounds its pid in the schema; these device tools used to take a bare int, so
    a negative pid slipped past the schema and was only caught later by the
    device authorization check as permission_denied -- the wrong taxonomy for
    malformed input. The bound now makes the framework reject it up front, and
    advertises the valid range to a client reading the schema.
    """
    schema = _tool_schema(tool)
    pid = schema["properties"]["pid"]
    assert pid["minimum"] == 0
    assert pid["maximum"] == 0xFFFFFFFF
    # 0 stays a valid default (the "last spawned pid" sentinel), so the lower
    # bound admits the sentinel rather than forcing an explicit pid.
    assert schema["properties"]["pid"].get("default") == 0


def test_the_tool_docstrings_publish_the_pid_contract() -> None:
    """The pid contract -- 0 means the last spawned pid, a specific pid must be
    one frida.spawn authorized -- must be readable from the tool schema, the same
    way the name_filter / class_name bounds are, so a caller is not surprised by
    an invalid_params or a permission_denied it could not have anticipated."""
    for name in ("frida.java.classes", "frida.java.methods"):
        doc = _tool_docstring(name)
        assert "pid" in doc
        assert "frida.spawn" in doc
        assert "non-negative" in doc


def test_the_authorization_boundary_still_precedes_input_validation() -> None:
    """An unauthorized pid is refused even with otherwise valid input.

    The pid allow-set is the session's security boundary; the string bounds are
    a resource guard. The security check must not be reachable-around by a
    malformed class_name, so authorization is asserted to win first.
    """
    client, resolved, attached = _client(_RecordingApi())
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 999, allowed_pids={1}, mode="methods", class_name="Foo")
    assert caught.value.code == "permission_denied"
    assert resolved == []
    assert attached == []
