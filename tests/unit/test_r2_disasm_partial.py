"""r2.disasm must report what r2 decoded, not the count that was requested.

pdj disassembles linearly from an address; it returns fewer instructions than
asked when it runs into unmapped or undecodable bytes, and nothing parseable
when the address holds no code. disasm used to overwrite the decoded count with
the requested count, so a listing that stopped after 3 instructions -- or none
-- reported the full request, and a caller read the request size as the result
size. It now keeps the decoded count, carries the request as requested, and
flags a short listing as partial.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.r2.client import R2Client


def _client(monkeypatch: Any, raw: str) -> R2Client:
    client = R2Client(executable=Path("/nonexistent-r2"))

    def fake_run(binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        del binary, timeout
        return {"raw": raw, "commands": commands}

    monkeypatch.setattr(client, "run", fake_run)
    return client


def _pdj(n: int, base: int = 0x1000) -> str:
    return json.dumps([{"offset": base + i, "opcode": "nop"} for i in range(n)])


def test_disasm_flags_a_short_listing_as_partial(monkeypatch: Any, tmp_path: Path) -> None:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00")
    payload = _client(monkeypatch, _pdj(10)).disasm(binary, 0x1000, count=32)
    assert payload["count"] == 10
    assert payload["requested"] == 32
    assert payload["partial"] is True
    assert len(payload["items"]) == 10


def test_disasm_full_listing_is_not_partial(monkeypatch: Any, tmp_path: Path) -> None:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00")
    payload = _client(monkeypatch, _pdj(8)).disasm(binary, 0x1000, count=8)
    assert payload["count"] == 8
    assert payload["requested"] == 8
    assert "partial" not in payload


def test_disasm_reports_zero_when_nothing_decoded(monkeypatch: Any, tmp_path: Path) -> None:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00")
    payload = _client(monkeypatch, "").disasm(binary, 0x1000, count=16)
    assert payload["count"] == 0
    assert payload["requested"] == 16
    assert payload["partial"] is True
    assert payload.get("parsed") is False
    assert "items" not in payload
