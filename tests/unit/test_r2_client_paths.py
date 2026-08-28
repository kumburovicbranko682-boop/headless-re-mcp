"""Direct coverage for the R2Client method bodies.

The existing r2 suite exercises enrich_r2_payload and the tool layer, but the
client's own validation guards, capability/not-found checks, disasm/xrefs
enrichment bodies, and executable discovery were never driven directly. These
tests do that without a real radare2: the happy paths stub ``run`` and the
guards need no subprocess at all.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2 import client as r2client
from headless_re_mcp.backends.r2.client import R2Client, R2Error


def _pe64(path: Path, *, image_base: int = 0x140000000) -> Path:
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = image_base.to_bytes(8, "little")
    path.write_bytes(bytes(image))
    return path


def _exe(tmp_path: Path) -> Path:
    exe = tmp_path / "r2"
    exe.write_bytes(b"#!/bin/sh\n")
    return exe


def test_open_rejects_missing_binary(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.open(tmp_path / "absent.exe")
    assert caught.value.code == "not_found"


def test_disasm_rejects_bad_address(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    binary = _pe64(tmp_path / "s.exe")
    with pytest.raises(R2Error) as neg:
        client.disasm(binary, -1)
    assert neg.value.code == "invalid_params"
    with pytest.raises(R2Error):
        client.disasm(binary, True)  # bool is not an int here


def test_disasm_rejects_out_of_range_count(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    binary = _pe64(tmp_path / "s.exe")
    with pytest.raises(R2Error, match="count must be"):
        client.disasm(binary, 0x1000, count=0)
    with pytest.raises(R2Error, match="count must be"):
        client.disasm(binary, 0x1000, count=513)


def test_disasm_enriches_run_payload(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    binary = _pe64(tmp_path / "s.exe")

    def _fake_run(_binary: Path, commands: list[str], *, timeout: float) -> dict[str, Any]:
        assert commands == ["aa", "pdj 1 @ 4096"]
        return {"raw": json.dumps([{"offset": 0x140001000}]), "commands": commands}

    client.run = _fake_run  # type: ignore[assignment]
    out = client.disasm(binary, 0x1000, count=1)
    assert out["address_va"] == 0x1000
    assert out["count"] == 1
    assert out["items"][0]["address"]["va"] == 0x140001000


def test_xrefs_rejects_bad_address(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    binary = _pe64(tmp_path / "s.exe")
    with pytest.raises(R2Error, match="non-negative"):
        client.xrefs(binary, -5)


def test_xrefs_enriches_run_payload(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    binary = _pe64(tmp_path / "s.exe")

    def _fake_run(_binary: Path, commands: list[str], *, timeout: float) -> dict[str, Any]:
        assert commands == ["aa", "axj @ 8192"]
        return {"raw": json.dumps([{"from": 0x140002000}]), "commands": commands}

    client.run = _fake_run  # type: ignore[assignment]
    out = client.xrefs(binary, 0x2000)
    assert out["address_va"] == 0x2000
    assert out["items"][0]["from_address"]["va"] == 0x140002000


def test_run_reports_capability_unavailable_without_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Force discovery to find nothing so the unavailable arm runs whether or not
    # radare2/rizin happens to be on PATH in this environment.
    monkeypatch.setattr(r2client, "_discover", lambda: None)
    client = R2Client(executable=None)
    assert client.available is False
    with pytest.raises(R2Error) as caught:
        client.run(tmp_path / "any.exe", ["i"])
    assert caught.value.code == "capability_unavailable"


def test_run_rejects_missing_binary_when_available(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    assert client.available is True
    with pytest.raises(R2Error) as caught:
        client.run(tmp_path / "gone.exe", ["i"])
    assert caught.value.code == "not_found"


def test_discover_prefers_r2_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.r2.client.shutil.which",
        lambda name: "/usr/bin/r2" if name == "r2" else None,
    )
    assert r2client._discover() == Path("/usr/bin/r2")


def test_discover_returns_none_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.r2.client.shutil.which", lambda name: None)
    assert r2client._discover() is None
