"""IDA name set used to call a no-op a successful rename."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from headless_re_mcp.backends.ida.worker import WorkerRequestError, _name_set


def _install(monkeypatch: pytest.MonkeyPatch, *, after: str) -> None:
    ida_ida = ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]

    idc = ModuleType("idc")
    idc.get_name = lambda ea: after  # type: ignore[attr-defined]

    ida_name = ModuleType("ida_name")
    ida_name.SN_FORCE = 1  # type: ignore[attr-defined]
    ida_name.set_name = lambda ea, name, flags: True  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    monkeypatch.setitem(sys.modules, "idc", idc)
    monkeypatch.setitem(sys.modules, "ida_name", ida_name)


class TestNameSetDoesNotCallNoOpSuccess:
    """set_name True plus an unchanged readback used to look renamed.

    Measured: set_name returned True, get_name still returned the old
    name, ok=true -- so a caller treats a no-op as the requested name.
    """

    def test_an_unchanged_name_is_not_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(monkeypatch, after="old")
        with pytest.raises(WorkerRequestError) as info:
            _name_set({"address": 0x1000, "name": "new"})
        assert info.value.code == "write_failed"

    def test_a_changed_name_is_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch, after="new")
        result = _name_set({"address": 0x1000, "name": "new"})
        assert result["ok"] is True
        assert result["name"] == "new"
