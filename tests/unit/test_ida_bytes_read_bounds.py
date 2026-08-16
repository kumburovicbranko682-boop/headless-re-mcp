"""IDA bytes.read used to call a short read complete."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from headless_re_mcp.backends.ida.worker import _bytes_read


def _install_ida(monkeypatch: pytest.MonkeyPatch, blob: bytes) -> None:
    ida_bytes = ModuleType("ida_bytes")
    ida_bytes.is_loaded = lambda ea: True  # type: ignore[attr-defined]
    ida_bytes.get_bytes = lambda ea, size: blob  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)


class TestIdaBytesReadSaysWhenItStopped:
    """A short read used to look like the whole requested range.

    Measured: asked 64, got 10, truncated=false -- so a caller that trusts
    the flag treats the slice as every byte it asked for.
    """

    def test_a_short_read_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_ida(monkeypatch, b"AB" * 5)
        result = _bytes_read({"address": 0x1000, "size": 64})
        assert result["size"] == 10
        assert result["truncated"] is True

    def test_a_full_read_is_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_ida(monkeypatch, b"A" * 64)
        result = _bytes_read({"address": 0x1000, "size": 64})
        assert result["size"] == 64
        assert result["truncated"] is False
