"""r2.disasm / r2.xrefs enrich the payload once, not twice.

Both used to call ``run`` (which enriches) and then ``enrich_r2_payload`` again
on that already-enriched result -- a second PE-header read and JSON re-parse for
an identical payload. The refactor routes them through ``_run_raw`` so enrich is
paid once; this pins that so the redundancy cannot creep back, and confirms the
returned payload is unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client


def _pe64(tmp_path: Path) -> Path:
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = (0x140000000).to_bytes(8, "little")
    pe = tmp_path / "demo64.exe"
    pe.write_bytes(bytes(image))
    return pe


def _client(tmp_path: Path) -> R2Client:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    return R2Client(executable)


def _count_enrich(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls = [0]
    real = r2_module.enrich_r2_payload

    def spy(data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        calls[0] += 1
        return real(data, **kwargs)

    monkeypatch.setattr(r2_module, "enrich_r2_payload", spy)
    return calls


def test_disasm_enriches_once_and_maps_the_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pe = _pe64(tmp_path)
    client = _client(tmp_path)
    pdj = json.dumps([{"offset": 0x140001000, "opcode": "nop"}])

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(0, pdj.encode(), b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    calls = _count_enrich(monkeypatch)

    result = client.disasm(pe, 0x140001000, count=4, timeout=30.0)

    assert calls[0] == 1
    assert result["address"] == {
        "module": "demo64.exe",
        "rva": 0x1000,
        "va": 0x140001000,
        "architecture": "x64",
    }
    assert result["address_va"] == 0x140001000
    assert result["parsed"] is True
    assert result["count"] == len(result["items"]) == 1


def test_xrefs_enriches_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pe = _pe64(tmp_path)
    client = _client(tmp_path)
    axj = json.dumps([{"from": 0x140001100, "to": 0x140001000, "type": "CALL"}])

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(0, axj.encode(), b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    calls = _count_enrich(monkeypatch)

    result = client.xrefs(pe, 0x140001000, timeout=30.0)

    assert calls[0] == 1
    assert result["address"]["va"] == 0x140001000
    assert result["parsed"] is True
    assert result["items"][0]["from_address"]["va"] == 0x140001100


def test_run_still_enriches_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pe = _pe64(tmp_path)
    client = _client(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    calls = _count_enrich(monkeypatch)

    result = client.run(pe, ["aa", "aflj"], timeout=30.0)

    assert calls[0] == 1
    assert result["commands"] == ["aa", "aflj"]
    assert result["parsed"] is True
