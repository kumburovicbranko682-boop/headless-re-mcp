"""Input-validation and degradation guards of the radare2/rizin client.

``run`` itself is exercised elsewhere; this pins the thin wrappers around it --
``disasm``/``xrefs`` argument validation and command shaping, ``open`` on a
missing file, and the three ways ``run`` refuses before spawning anything (a
non-positive deadline, a missing tool, a missing target) -- so each is a
structured ``R2Error`` the tool layer can turn into an envelope, not a bare
exception or a silent launch.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2 import client as r2_client
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _discover


def _stub_client(tmp_path: Path) -> R2Client:
    """A client whose executable exists on disk (so ``available`` is True) but
    is never launched because ``run`` is stubbed."""
    stub = tmp_path / "r2"
    stub.write_bytes(b"")
    return R2Client(stub)


def test_open_reports_a_missing_binary_as_not_found(tmp_path: Path) -> None:
    client = _stub_client(tmp_path)
    with pytest.raises(R2Error) as caught:
        client.open(tmp_path / "absent.exe")
    assert caught.value.code == "not_found"


def test_disasm_rejects_a_bad_address_and_count(tmp_path: Path) -> None:
    client = _stub_client(tmp_path)
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"MZ")
    for address in (-1, "0x10"):
        with pytest.raises(R2Error) as caught:
            client.disasm(binary, address)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"
    for count in (0, 513, 4.0):
        with pytest.raises(R2Error) as caught:
            client.disasm(binary, 0x1000, count=count)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"


def test_disasm_shapes_the_pdj_command_and_threads_the_address(tmp_path: Path) -> None:
    client = _stub_client(tmp_path)
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"not a pe")
    captured: dict[str, Any] = {}

    def fake_run(target: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        captured["commands"] = commands
        return {"raw": json.dumps([{"offset": 0x1000, "opcode": "nop"}]), "commands": commands}

    client.run = fake_run  # type: ignore[method-assign]
    payload = client.disasm(binary, 0x1000, count=4)
    assert captured["commands"] == ["aa", "pdj 4 @ 4096"]
    assert payload["address_va"] == 0x1000
    assert payload["count"] == 1


def test_xrefs_rejects_a_bad_address(tmp_path: Path) -> None:
    client = _stub_client(tmp_path)
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"MZ")
    with pytest.raises(R2Error) as caught:
        client.xrefs(binary, -5)
    assert caught.value.code == "invalid_params"


def test_xrefs_shapes_the_axj_command_and_threads_the_address(tmp_path: Path) -> None:
    client = _stub_client(tmp_path)
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"not a pe")
    captured: dict[str, Any] = {}

    def fake_run(target: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        captured["commands"] = commands
        return {"raw": json.dumps([{"from": 0x2000, "to": 0x1000}]), "commands": commands}

    client.run = fake_run  # type: ignore[method-assign]
    payload = client.xrefs(binary, 0x1000)
    assert captured["commands"] == ["aa", "axj @ 4096"]
    assert payload["address_va"] == 0x1000


def test_run_without_a_tool_is_capability_unavailable(tmp_path: Path) -> None:
    client = R2Client(None)
    assert client.available is False
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"MZ")
    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"])
    assert caught.value.code == "capability_unavailable"


def test_run_with_a_missing_binary_is_not_found(tmp_path: Path) -> None:
    client = _stub_client(tmp_path)
    with pytest.raises(R2Error) as caught:
        client.run(tmp_path / "gone.bin", ["i"])
    assert caught.value.code == "not_found"


def test_run_rejects_a_non_positive_timeout(tmp_path: Path) -> None:
    client = _stub_client(tmp_path)
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"MZ")
    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"], timeout=0)
    assert caught.value.code == "invalid_params"


def test_discover_returns_the_first_tool_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake_which(name: str) -> str | None:
        seen.append(name)
        return "/usr/bin/rizin" if name == "rizin" else None

    monkeypatch.setattr(r2_client.shutil, "which", fake_which)
    found = _discover()
    assert found == Path("/usr/bin/rizin")
    # r2 is probed first, then rizin; the search stops at the first hit.
    assert seen[:2] == ["r2", "rizin"]


def test_discover_returns_none_when_no_tool_is_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(r2_client.shutil, "which", lambda name: None)
    assert _discover() is None
