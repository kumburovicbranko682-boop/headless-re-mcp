"""Listing and removing single adb forwards (device.forwards / forward_remove).

Before this, an adb forward could be created (device.forward) but only ever
released all at once at close_all: a long-lived agent that forwarded frida or a
debug port for several apps could fill the 32-slot table with no way to see what
was held or reclaim one slot short of tearing every session down. These cover the
backend list_forwards/remove_forward, the freed-slot behaviour, the idempotent
no-op, and the service + tool surface that expose them.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adb_client
from headless_re_mcp.backends.adb.client import _MAX_FORWARDS, AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_device_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _Dev:
    """A device whose forward/forward_remove just record what they were asked."""

    def __init__(self, removed: list[str] | None = None) -> None:
        self._removed = removed if removed is not None else []

    def forward(self, local: str, remote: str) -> None:
        del local, remote

    def forward_remove(self, local: str) -> None:
        self._removed.append(local)


def test_list_forwards_reports_the_held_triples() -> None:
    """device.forwards shows the serial/local/remote of each occupied slot."""
    backend = AdbBackend()
    backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
    backend.forward("emulator-5554", "tcp:27042", "tcp:27042")
    backend.forward("emulator-5554", "localabstract:frida", "tcp:1337")

    payload = backend.list_forwards()

    assert payload["count"] == 2
    assert payload["cap"] == _MAX_FORWARDS
    triples = {(f["serial"], f["local"], f["remote"]) for f in payload["forwards"]}
    assert triples == {
        ("emulator-5554", "tcp:27042", "tcp:27042"),
        ("emulator-5554", "localabstract:frida", "tcp:1337"),
    }


def test_list_forwards_is_empty_and_needs_no_device_when_nothing_is_held() -> None:
    """Reading the table is in-memory: it must not touch a device."""
    backend = AdbBackend()

    def boom(serial: str) -> Any:  # pragma: no cover - must never be called
        del serial
        raise AssertionError("list_forwards must not resolve a device")

    backend._device = boom  # type: ignore[method-assign]
    payload = backend.list_forwards()
    assert payload == {"forwards": [], "count": 0, "cap": _MAX_FORWARDS}


def test_remove_forward_drops_a_tracked_forward_and_frees_the_slot(
    monkeypatch: Any,
) -> None:
    """The whole point: reclaim one slot after the table filled."""
    monkeypatch.setattr(adb_client, "_MAX_FORWARDS", 1)
    removed: list[str] = []
    backend = adb_client.AdbBackend()
    backend._device = lambda serial: _Dev(removed)  # type: ignore[method-assign]

    backend.forward("emu", "tcp:1", "tcp:1")
    with pytest.raises(adb_client.AdbError) as caught:
        backend.forward("emu", "tcp:2", "tcp:2")
    assert caught.value.code == "invalid_state"

    out = backend.remove_forward("emu", "tcp:1")
    assert out == {"serial": "emu", "local": "tcp:1", "removed": True}
    assert removed == ["tcp:1"]
    assert backend._forwards == {}

    # The freed slot is usable again -- the forward that was just refused fits.
    backend.forward("emu", "tcp:2", "tcp:2")
    assert backend._forwards == {("emu", "tcp:2"): "tcp:2"}


def test_remove_forward_on_an_untracked_forward_is_an_idempotent_no_op() -> None:
    """Removing what we never created still asks adb but reports removed False."""
    removed: list[str] = []
    backend = AdbBackend()
    backend._device = lambda serial: _Dev(removed)  # type: ignore[method-assign]

    out = backend.remove_forward("emulator-5554", "tcp:9")
    assert out == {"serial": "emulator-5554", "local": "tcp:9", "removed": False}
    assert removed == ["tcp:9"]
    assert backend._forwards == {}


def test_remove_forward_swallows_an_adb_error_when_it_was_not_tracked() -> None:
    """A 'listener not found' on a forward we do not hold is not our failure."""

    class _Dev404:
        def forward_remove(self, local: str) -> None:
            raise RuntimeError(f"listener '{local}' not found")

    backend = AdbBackend()
    backend._device = lambda serial: _Dev404()  # type: ignore[method-assign]
    out = backend.remove_forward("emulator-5554", "tcp:9")
    assert out["removed"] is False


def test_remove_forward_keeps_a_tracked_forward_when_adb_removal_fails() -> None:
    """A failed removal of a forward we hold must not leak the slot silently.

    adb still has the forward, so the entry stays for the next close_all to
    retry -- the same resilience release_forwards has -- and the caller is told
    with backend_error rather than a false 'removed'.
    """

    class _DevBoom:
        def forward(self, local: str, remote: str) -> None:
            del local, remote

        def forward_remove(self, local: str) -> None:
            raise RuntimeError(f"device offline ({local})")

    backend = AdbBackend()
    backend._device = lambda serial: _DevBoom()  # type: ignore[method-assign]
    backend.forward("emulator-5554", "tcp:1", "tcp:1")

    with pytest.raises(AdbError) as caught:
        backend.remove_forward("emulator-5554", "tcp:1")
    assert caught.value.code == "backend_error"
    assert backend._forwards == {("emulator-5554", "tcp:1"): "tcp:1"}


def test_remove_forward_rejects_a_bad_local_spec_before_touching_a_device() -> None:
    """A malformed local endpoint is invalid_params, not a device round trip."""

    def boom(serial: str) -> Any:  # pragma: no cover - must never be called
        del serial
        raise AssertionError("a bad local spec must be refused before _device")

    backend = AdbBackend()
    backend._device = boom  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend.remove_forward("emulator-5554", "tcp:1; rm -rf /")
    assert caught.value.code == "invalid_params"


# --------------------------------------------------------------------------
# Service + tool surface: the tools route through and are shaped/classified.
# --------------------------------------------------------------------------


def test_service_device_forwards_and_remove_route_to_the_owned_backend() -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        listed: list[bool] = []
        removed_calls: list[tuple[str, str]] = []
        service._adb_backend.list_forwards = (  # type: ignore[method-assign]
            lambda: listed.append(True)
            or {"forwards": [], "count": 0, "cap": _MAX_FORWARDS}
        )
        service._adb_backend.remove_forward = (  # type: ignore[method-assign]
            lambda serial, local: removed_calls.append((serial, local))
            or {"serial": serial, "local": local, "removed": True}
        )

        listing = service.device_forwards()
        assert listing.ok and listing.data is not None
        assert listing.data["cap"] == _MAX_FORWARDS
        assert listed == [True]

        dropped = service.device_forward_remove("emulator-5554", "tcp:27042")
        assert dropped.ok and dropped.data is not None
        assert dropped.data["removed"] is True
        assert removed_calls == [("emulator-5554", "tcp:27042")]
    finally:
        service.close_all()


def test_forward_tool_docstrings_name_the_new_reclaim_path() -> None:
    forwards_doc = " ".join(_tool_docstring("device.forwards").split())
    assert "forwards (each {serial, local, remote})" in forwards_doc
    assert "cap" in forwards_doc
    assert "device.forward_remove" in forwards_doc

    remove_doc = " ".join(_tool_docstring("device.forward_remove").split())
    assert "removed is true" in remove_doc
    assert "idempotent no-op" in remove_doc

    forward_doc = " ".join(_tool_docstring("device.forward").split())
    assert "device.forward_remove" in forward_doc


def test_new_forward_tools_are_classified_read_and_write() -> None:
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES, _STATE_CHANGE_NAMES

    assert "device.forwards" in _READ_ONLY_NAMES
    assert "device.forward_remove" in _STATE_CHANGE_NAMES
