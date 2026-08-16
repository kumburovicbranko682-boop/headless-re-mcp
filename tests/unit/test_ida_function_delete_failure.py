"""IDA function delete used to call a leftover function gone."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from headless_re_mcp.backends.ida.worker import WorkerRequestError, _function_delete


class _Fn:
    def __init__(self, start: int = 0x1000, end: int = 0x1100) -> None:
        self.start_ea = start
        self.end_ea = end


def _install(monkeypatch: pytest.MonkeyPatch, *, leftover: bool) -> None:
    class _Funcs:
        @staticmethod
        def get_func(ea: int) -> _Fn | None:
            if leftover:
                return _Fn()
            return None if getattr(_Funcs, "_deleted", False) else _Fn()

        @staticmethod
        def del_func(start: int) -> bool:
            del start
            _Funcs._deleted = True
            return True

    ida_funcs = ModuleType("ida_funcs")
    ida_funcs.get_func = _Funcs.get_func  # type: ignore[attr-defined]
    ida_funcs.del_func = _Funcs.del_func  # type: ignore[attr-defined]

    ida_ida = ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)


class TestFunctionDeleteDoesNotCallLeftoverSuccess:
    """del_func True plus a leftover function used to look deleted.

    Measured: del_func returned True, get_func still found the function,
    deleted=true -- so a caller treats a no-op as a removed function.
    """

    def test_a_leftover_function_is_not_deleted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(monkeypatch, leftover=True)
        with pytest.raises(WorkerRequestError) as info:
            _function_delete({"address": 0x1000})
        assert info.value.code == "write_failed"

    def test_a_gone_function_is_deleted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch, leftover=False)
        result = _function_delete({"address": 0x1000})
        assert result["deleted"] is True
        assert result["ok"] is True
