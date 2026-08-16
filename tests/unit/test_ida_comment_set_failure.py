"""IDA comment set used to call a no-op a successful write."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from headless_re_mcp.backends.ida.worker import WorkerRequestError, _comment_set


def _install(monkeypatch: pytest.MonkeyPatch, *, after: str) -> None:
    ida_ida = ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]

    ida_bytes = ModuleType("ida_bytes")
    ida_bytes.get_cmt = lambda ea, repeatable: after  # type: ignore[attr-defined]
    ida_bytes.set_cmt = lambda ea, comment, repeatable: True  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)


class TestCommentSetDoesNotCallNoOpSuccess:
    """set_cmt True plus an unchanged readback used to look written.

    Measured: set_cmt returned True, get_cmt still returned the old
    comment, ok=true -- so a caller treats a no-op as the requested text.
    """

    def test_an_unchanged_comment_is_not_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(monkeypatch, after="oldc")
        with pytest.raises(WorkerRequestError) as info:
            _comment_set({"address": 0x1000, "comment": "newc"})
        assert info.value.code == "write_failed"

    def test_a_changed_comment_is_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch, after="newc")
        result = _comment_set({"address": 0x1000, "comment": "newc"})
        assert result["ok"] is True
        assert result["comment"] == "newc"
