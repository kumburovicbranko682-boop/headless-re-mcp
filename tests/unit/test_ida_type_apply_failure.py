"""IDA type apply used to call a no-op a successful write."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from headless_re_mcp.backends.ida.worker import WorkerRequestError, _type_apply


def _install(monkeypatch: pytest.MonkeyPatch, *, after: str) -> None:
    ida_ida = ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]

    idc = ModuleType("idc")
    idc.get_type = lambda ea: after  # type: ignore[attr-defined]
    idc.SetType = lambda ea, type_str: True  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    monkeypatch.setitem(sys.modules, "idc", idc)


class TestTypeApplyDoesNotCallNoOpSuccess:
    """SetType True plus an unchanged readback used to look applied.

    Measured: SetType returned True, get_type still returned the old
    type, ok=true -- so a caller treats a no-op as the requested type.
    """

    def test_an_unchanged_type_is_not_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(monkeypatch, after="int")
        with pytest.raises(WorkerRequestError) as info:
            _type_apply({"address": 0x1000, "type": "void *"})
        assert info.value.code == "write_failed"

    def test_a_changed_type_is_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch, after="void *")
        result = _type_apply({"address": 0x1000, "type": "void *"})
        assert result["ok"] is True
        assert result["type"] == "void *"
