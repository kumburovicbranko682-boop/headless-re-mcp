"""frida.exports must bound its ``module_name`` before it crosses the RPC.

``exports`` marshals ``module_name`` straight across the Frida RPC to the device
as the argument to the export-enumeration script (``exports_sync.exports(name,
...)``). That is the same resource/marshalling exposure ``java_enumerate``'s
``class_name`` / ``name_filter`` have, and the backend comment on
``_MAX_RPC_NAME_BYTES`` -- and the sibling bounds test's own docstring -- both
list ``module_name`` as already following the 512-byte / NUL-refusing
discipline. It did not: ``exports`` only stripped and checked non-empty, so a
caller (or a transport that skips the pydantic schema, as the agent and
OpenAI-bridge paths do) could ship a megabyte name to the device on every call,
or a NUL that truncates it mid-marshal.

These pin the fix the same way the Java bounds are pinned: an over-long name, a
NUL, a non-string and an empty name are each refused as ``invalid_params``
*before* the probe attaches (so a hostile length never reaches a device), while
a name at the cap is accepted and reaches the enumeration script verbatim.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import (
    _MAX_RPC_NAME_BYTES,
    FridaClient,
    FridaError,
)


class _RecordingExports:
    """The export RPC surface, recording exactly what reached the script."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def exports(self, name: str, count: int) -> dict[str, Any]:
        self.calls.append((name, int(count)))
        return {
            "found": True,
            "module": name,
            "base": "0x1000",
            "exports": [{"name": "malloc", "address": "0x2000", "type": "function"}],
        }


def _client(api: _RecordingExports) -> tuple[FridaClient, list[int]]:
    """A client whose local attach is observable.

    ``attached`` stays empty when a guard refuses the input before any attach --
    that is the fail-fast property under test.
    """
    attached: list[int] = []

    script = type("_S", (), {"exports_sync": api, "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, source: script, "detach": lambda self: None},
    )()

    class _Frida:
        def attach(self, pid: int) -> object:
            attached.append(pid)
            return session

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    return client, attached


def test_module_name_over_the_cap_fails_before_any_attach() -> None:
    api = _RecordingExports()
    client, attached = _client(api)
    over = "x" * (_MAX_RPC_NAME_BYTES + 1)
    with pytest.raises(FridaError) as caught:
        client.exports(1, over, allowed_pid=1)
    assert caught.value.code == "invalid_params"
    assert caught.value.details.get("limit") == _MAX_RPC_NAME_BYTES
    # The guard runs before the probe attaches, so a hostile length never
    # reaches a device attach or the export RPC.
    assert attached == []
    assert api.calls == []


def test_module_name_with_a_nul_byte_is_refused() -> None:
    api = _RecordingExports()
    client, attached = _client(api)
    with pytest.raises(FridaError) as caught:
        client.exports(1, "libc\x00.so", allowed_pid=1)
    assert caught.value.code == "invalid_params"
    assert attached == []
    assert api.calls == []


def test_a_non_string_module_name_is_refused_before_any_attach() -> None:
    """The MCP schema types module_name as a string, but the agent and OpenAI
    transports call the backend directly and skip that validation, so the
    backend must reject a non-string itself rather than marshalling it."""
    api = _RecordingExports()
    client, attached = _client(api)
    for bad in (123, ["libc.so"], object()):
        with pytest.raises(FridaError) as caught:
            client.exports(1, bad, allowed_pid=1)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"
        assert "module_name must be a string" in caught.value.message
    assert attached == []
    assert api.calls == []


def test_an_empty_module_name_is_required_and_never_attaches() -> None:
    api = _RecordingExports()
    client, attached = _client(api)
    for bad in ("", "   ", "\t\n"):
        with pytest.raises(FridaError) as caught:
            client.exports(1, bad, allowed_pid=1)
        assert caught.value.code == "invalid_params"
        assert "module_name is required" in caught.value.message
    assert attached == []
    assert api.calls == []


def test_module_name_at_the_cap_is_accepted_and_reaches_the_script_stripped() -> None:
    api = _RecordingExports()
    client, attached = _client(api)
    at_cap = "a" * _MAX_RPC_NAME_BYTES
    payload = client.exports(1, f"  {at_cap}  ", allowed_pid=1, limit=5)
    assert payload["found"] is True
    assert payload["module"] == at_cap
    assert attached == [1]
    # The stripped name -- not the padded input -- is what crossed the RPC.
    assert api.calls and api.calls[0][0] == at_cap


def test_the_authorization_boundary_still_precedes_module_name_validation() -> None:
    """An unauthorized pid is refused even with an otherwise valid module_name.

    The pid allow-set is the session's security boundary; the length bound is a
    resource guard. The security check must not be reachable-around by a
    malformed module_name, so authorization is asserted to win first.
    """
    api = _RecordingExports()
    client, attached = _client(api)
    with pytest.raises(FridaError) as caught:
        client.exports(999, "x" * (_MAX_RPC_NAME_BYTES + 1), allowed_pid=1)
    assert caught.value.code == "permission_denied"
    assert attached == []
    assert api.calls == []
