"""Device-free coverage for the radare2/rizin client's guards and discovery.

The command allowlist (test_r2_command_whitelist) and the run boundary --
timeout, launch failure, truncation (test_r2_info_truncated,
test_run_bounded_launch_failure) -- are pinned elsewhere. What was not: the
per-method input guards that refuse a bad address or count *before* r2 is
spawned, run's own capability/not-found gates, and the PATH discovery that
decides which of r2/rizin/radare2 the client binds to.

The address guards are a small but load-bearing contract on this line: every
address-taking tool checks ``type(address) is not int``, which also rejects a
bool (``type(True) is int`` is False), so a stray True/False can never be
formatted into an ``@ <addr>`` command. These pin that without a binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2 import client as r2_client
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _discover


def _fake_exe(tmp_path: Path) -> Path:
    exe = tmp_path / "r2"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    return exe


# --- _discover --------------------------------------------------------------


def test_discover_prefers_r2_then_rizin_then_radare2(monkeypatch: pytest.MonkeyPatch) -> None:
    def only(*present: str):
        return lambda name: f"/usr/bin/{name}" if name in present else None

    monkeypatch.setattr(r2_client.shutil, "which", only("r2", "rizin", "radare2"))
    assert _discover() == Path("/usr/bin/r2")

    # r2 absent: rizin is next in preference order.
    monkeypatch.setattr(r2_client.shutil, "which", only("rizin", "radare2"))
    assert _discover() == Path("/usr/bin/rizin")

    monkeypatch.setattr(r2_client.shutil, "which", only("radare2"))
    assert _discover() == Path("/usr/bin/radare2")


def test_discover_returns_none_when_nothing_is_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r2_client.shutil, "which", lambda _name: None)
    assert _discover() is None


def test_available_is_false_without_an_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r2_client.shutil, "which", lambda _name: None)
    assert R2Client().available is False


def test_available_is_false_when_the_path_is_not_a_file(tmp_path: Path) -> None:
    assert R2Client(tmp_path / "does-not-exist").available is False


# --- open -------------------------------------------------------------------


def test_open_reports_not_found_for_a_missing_binary(tmp_path: Path) -> None:
    client = R2Client(_fake_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.open(tmp_path / "gone.bin")
    assert caught.value.code == "not_found"


# --- disasm guards ----------------------------------------------------------


def test_disasm_rejects_a_negative_address(tmp_path: Path) -> None:
    client = R2Client(_fake_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.disasm(tmp_path / "a.bin", -1)
    assert caught.value.code == "invalid_params"


def test_disasm_rejects_a_boolean_address(tmp_path: Path) -> None:
    # bool is an int subclass, but type(...) is int is False for a bool, so a
    # stray True never reaches the "@ 1" command shape.
    client = R2Client(_fake_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.disasm(tmp_path / "a.bin", True)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("count", [0, 513, -5])
def test_disasm_bounds_the_instruction_count(tmp_path: Path, count: int) -> None:
    client = R2Client(_fake_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.disasm(tmp_path / "a.bin", 0x1000, count=count)
    assert caught.value.code == "invalid_params"
    assert "count" in caught.value.message


# --- xrefs family guards ----------------------------------------------------


@pytest.mark.parametrize("method", ["xrefs", "xrefs_to", "xrefs_from"])
def test_xrefs_family_rejects_a_negative_address(tmp_path: Path, method: str) -> None:
    client = R2Client(_fake_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        getattr(client, method)(tmp_path / "a.bin", -1)
    assert caught.value.code == "invalid_params"


# --- run gates --------------------------------------------------------------


def test_run_degrades_without_an_executable(tmp_path: Path) -> None:
    client = R2Client(_fake_exe(tmp_path))
    client.executable = None  # simulate discovery finding nothing
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"\x7fELF")
    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"])
    assert caught.value.code == "capability_unavailable"


def test_run_reports_not_found_for_a_missing_binary(tmp_path: Path) -> None:
    client = R2Client(_fake_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.run(tmp_path / "gone.bin", ["i"])
    assert caught.value.code == "not_found"
