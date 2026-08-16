"""IDA linear disassembly used to cut a long line without saying so."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from headless_re_mcp.backends.ida.worker import _disassemble


def _install_ida(monkeypatch: pytest.MonkeyPatch, line: str) -> None:
    ida_bytes = ModuleType("ida_bytes")
    ida_bytes.is_loaded = lambda ea: True  # type: ignore[attr-defined]

    class _Insn:
        pass

    ida_ua = ModuleType("ida_ua")
    ida_ua.insn_t = _Insn  # type: ignore[attr-defined]
    ida_ua.decode_insn = lambda insn, ea: 4  # type: ignore[attr-defined]

    idc = ModuleType("idc")
    idc.generate_disasm_line = lambda ea, flags: line  # type: ignore[attr-defined]

    for name, module in {
        "ida_bytes": ida_bytes,
        "ida_ua": ida_ua,
        "idc": idc,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)


class TestIdaDisasmSaysWhenALineStopped:
    """A disasm line that hit 512 chars used to look complete.

    Measured: 1000-char line, text length 512, no truncated -- so a caller
    that only looks at instructions[].text thinks the mnemonic ended.
    """

    def test_hitting_the_cap_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_ida(monkeypatch, "X" * 1000)
        result = _disassemble({"address": 0x1000, "count": 1})
        insn = result["instructions"][0]
        assert len(insn["text"]) == 512
        assert insn["truncated"] is True
        assert result["truncated"] is True

    def test_a_short_line_is_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_ida(monkeypatch, "nop")
        result = _disassemble({"address": 0x1000, "count": 1})
        insn = result["instructions"][0]
        assert insn["text"] == "nop"
        assert "truncated" not in insn
        assert "truncated" not in result
