"""adb reverse (device->host): device.reverse / reverses / reverse_remove.

device.forward tunnels host->device; this is its mirror, the piece that routes an
on-device app's traffic into a host-run proxy (proxy.start, then device.reverse
tcp:8080 tcp:8080, then point the app at 127.0.0.1:8080). adb takes the
device-side spec first, so the argument order is (remote, local) -- the opposite
of forward -- and these cover that ordering, the reservation table and cap, the
in-memory listing, the freed-slot reclaim, the idempotent no-op, the
keep-on-failure resilience, spec validation, the service + tool surface, and the
read/write classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adb_client
from headless_re_mcp.backends.adb.client import _MAX_REVERSES, AdbBackend, AdbError
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
    """A device whose reverse/reverse_remove record exactly what they were asked."""

    def __init__(
        self,
        created: list[tuple[str, str]] | None = None,
        removed: list[str] | None = None,
    ) -> None:
        self._created = created if created is not None else []
        self._removed = removed if removed is not None else []

    def reverse(self, remote: str, local: str, norebind: bool = False) -> None:
        del norebind
        self._created.append((remote, local))

    def reverse_remove(self, remote: str) -> None:
        self._removed.append(remote)


def test_reverse_passes_remote_local_order_and_lists_triples() -> None:
    """adb reverse takes the device-side spec first; the table shows the triple."""
    created: list[tuple[str, str]] = []
    backend = AdbBackend()
    backend._device = lambda serial: _Dev(created)  # type: ignore[method-assign]

    out = backend.reverse("emulator-5554", "tcp:8080", "tcp:9090")
    assert out == {"remote": "tcp:8080", "local": "tcp:9090"}
    # The device saw (remote, local), not forward's (local, remote).
    assert created == [("tcp:8080", "tcp:9090")]

    backend.reverse("emulator-5554", "localabstract:mitm", "tcp:8080")
    payload = backend.list_reverses()
    assert payload["count"] == 2
    assert payload["cap"] == _MAX_REVERSES
    triples = {(r["serial"], r["remote"], r["local"]) for r in payload["reverses"]}
    assert triples == {
        ("emulator-5554", "tcp:8080", "tcp:9090"),
        ("emulator-5554", "localabstract:mitm", "tcp:8080"),
    }


def test_list_reverses_is_empty_and_needs_no_device_when_nothing_is_held() -> None:
    backend = AdbBackend()

    def boom(serial: str) -> Any:  # pragma: no cover - must never be called
        del serial
        raise AssertionError("list_reverses must not resolve a device")

    backend._device = boom  # type: ignore[method-assign]
    payload = backend.list_reverses()
    assert payload == {"reverses": [], "count": 0, "cap": _MAX_REVERSES}


def test_reverse_cap_is_enforced_and_a_removed_slot_is_reusable(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(adb_client, "_MAX_REVERSES", 1)
    removed: list[str] = []
    backend = adb_client.AdbBackend()
    backend._device = lambda serial: _Dev(removed=removed)  # type: ignore[method-assign]

    backend.reverse("emu", "tcp:1", "tcp:1")
    with pytest.raises(adb_client.AdbError) as caught:
        backend.reverse("emu", "tcp:2", "tcp:2")
    assert caught.value.code == "invalid_state"

    out = backend.remove_reverse("emu", "tcp:1")
    assert out == {"serial": "emu", "remote": "tcp:1", "removed": True}
    assert removed == ["tcp:1"]
    assert backend._reverses == {}

    backend.reverse("emu", "tcp:2", "tcp:2")
    assert backend._reverses == {("emu", "tcp:2"): "tcp:2"}


def test_remove_reverse_on_an_untracked_reverse_is_an_idempotent_no_op() -> None:
    removed: list[str] = []
    backend = AdbBackend()
    backend._device = lambda serial: _Dev(removed=removed)  # type: ignore[method-assign]

    out = backend.remove_reverse("emulator-5554", "tcp:9")
    assert out == {"serial": "emulator-5554", "remote": "tcp:9", "removed": False}
    assert removed == ["tcp:9"]
    assert backend._reverses == {}


def test_remove_reverse_swallows_an_adb_error_when_it_was_not_tracked() -> None:
    class _Dev404:
        def reverse_remove(self, remote: str) -> None:
            raise RuntimeError(f"listener '{remote}' not found")

    backend = AdbBackend()
    backend._device = lambda serial: _Dev404()  # type: ignore[method-assign]
    out = backend.remove_reverse("emulator-5554", "tcp:9")
    assert out["removed"] is False


def test_remove_reverse_keeps_a_tracked_reverse_when_adb_removal_fails() -> None:
    class _DevBoom:
        def reverse(self, remote: str, local: str, norebind: bool = False) -> None:
            del remote, local, norebind

        def reverse_remove(self, remote: str) -> None:
            raise RuntimeError(f"device offline ({remote})")

    backend = AdbBackend()
    backend._device = lambda serial: _DevBoom()  # type: ignore[method-assign]
    backend.reverse("emulator-5554", "tcp:1", "tcp:1")

    with pytest.raises(AdbError) as caught:
        backend.remove_reverse("emulator-5554", "tcp:1")
    assert caught.value.code == "backend_error"
    assert backend._reverses == {("emulator-5554", "tcp:1"): "tcp:1"}


@pytest.mark.parametrize(
    ("remote", "local"),
    [
        ("tcp:8080; rm -rf /", "tcp:8080"),
        ("tcp:8080", "tcp:8080; reboot"),
        ("jdwp:1", "tcp:8080"),
        ("", "tcp:8080"),
    ],
)
def test_reverse_rejects_a_bad_spec_before_touching_a_device(
    remote: str, local: str
) -> None:
    def boom(serial: str) -> Any:  # pragma: no cover - must never be called
        del serial
        raise AssertionError("a bad reverse spec must be refused before _device")

    backend = AdbBackend()
    backend._device = boom  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend.reverse("emulator-5554", remote, local)
    assert caught.value.code == "invalid_params"


def test_remove_reverse_rejects_a_bad_remote_before_touching_a_device() -> None:
    def boom(serial: str) -> Any:  # pragma: no cover - must never be called
        del serial
        raise AssertionError("a bad remote spec must be refused before _device")

    backend = AdbBackend()
    backend._device = boom  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend.remove_reverse("emulator-5554", "tcp:1; rm -rf /")
    assert caught.value.code == "invalid_params"


def test_release_reverses_drops_every_held_reverse() -> None:
    removed: list[str] = []
    backend = AdbBackend()
    backend._device = lambda serial: _Dev(removed=removed)  # type: ignore[method-assign]
    backend.reverse("emu", "tcp:1", "tcp:1")
    backend.reverse("emu", "tcp:2", "tcp:2")

    out = backend.release_reverses()
    assert out["count"] == 2
    assert sorted(removed) == ["tcp:1", "tcp:2"]
    assert backend._reverses == {}


# --------------------------------------------------------------------------
# Service + tool surface: the tools route through and are shaped/classified.
# --------------------------------------------------------------------------


def test_service_device_reverse_routes_to_the_owned_backend() -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        created: list[tuple[str, str, str]] = []
        listed: list[bool] = []
        removed_calls: list[tuple[str, str]] = []
        service._adb_backend.reverse = (  # type: ignore[method-assign]
            lambda serial, remote, local: created.append((serial, remote, local))
            or {"remote": remote, "local": local}
        )
        service._adb_backend.list_reverses = (  # type: ignore[method-assign]
            lambda: listed.append(True)
            or {"reverses": [], "count": 0, "cap": _MAX_REVERSES}
        )
        service._adb_backend.remove_reverse = (  # type: ignore[method-assign]
            lambda serial, remote: removed_calls.append((serial, remote))
            or {"serial": serial, "remote": remote, "removed": True}
        )

        made = service.device_reverse("emulator-5554", "tcp:8080", "tcp:8080")
        assert made.ok and made.data is not None
        assert made.data == {"remote": "tcp:8080", "local": "tcp:8080"}
        assert created == [("emulator-5554", "tcp:8080", "tcp:8080")]

        listing = service.device_reverses()
        assert listing.ok and listing.data is not None
        assert listing.data["cap"] == _MAX_REVERSES
        assert listed == [True]

        dropped = service.device_reverse_remove("emulator-5554", "tcp:8080")
        assert dropped.ok and dropped.data is not None
        assert dropped.data["removed"] is True
        assert removed_calls == [("emulator-5554", "tcp:8080")]
    finally:
        service.close_all()


def test_reverse_tool_docstrings_explain_the_mirror_and_ordering() -> None:
    reverse_doc = " ".join(_tool_docstring("device.reverse").split())
    assert "(remote, local)" in reverse_doc
    assert "127.0.0.1" in reverse_doc
    assert "device.reverse_remove" in reverse_doc

    reverses_doc = " ".join(_tool_docstring("device.reverses").split())
    assert "reverses (each {serial, remote, local})" in reverses_doc
    assert "cap" in reverses_doc

    remove_doc = " ".join(_tool_docstring("device.reverse_remove").split())
    assert "removed is true" in remove_doc
    assert "idempotent no-op" in remove_doc


def test_reverse_tools_are_classified_read_and_write() -> None:
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES, _STATE_CHANGE_NAMES

    assert "device.reverses" in _READ_ONLY_NAMES
    assert "device.reverse" in _STATE_CHANGE_NAMES
    assert "device.reverse_remove" in _STATE_CHANGE_NAMES
