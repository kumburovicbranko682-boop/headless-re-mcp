"""Guard and parameter branches of the radare2/rizin client wrapper.

The existing r2 tests pin the whitelist, the field mapping and the truncation
contracts, driving `run` with a fake so the JSON shaping is covered. This file
fills in the branches those step over: the one-shot `open` validation, the
`disasm` / `xrefs` argument checks and command shaping, the availability and
missing-binary guards on `run`, and executable discovery. Each test pins one
branch and needs no radare2 on PATH -- the one call that would spawn it is
stubbed at the seam.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2 import client as r2mod
from headless_re_mcp.backends.r2.client import R2Client, R2Error


def _fake_exe(tmp_path: Path) -> Path:
    exe = tmp_path / "r2"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    return exe


# ---------------------------------------------------------------------------
# open.
# ---------------------------------------------------------------------------
def test_open_reports_a_missing_binary(tmp_path: Path) -> None:
    client = R2Client(executable=None)
    with pytest.raises(R2Error) as caught:
        client.open(tmp_path / "absent.bin")
    assert caught.value.code == "not_found"


def test_open_validates_and_summarizes(tmp_path: Path) -> None:
    """open is one-shot: it runs `i`, returns a bounded info blurb and a note."""
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00\x01")
    client = R2Client(executable=None)
    client.run = lambda *a, **k: {"raw": "R2 INFO"}  # type: ignore[method-assign]
    payload = client.open(binary)
    assert payload["opened"] is True
    assert payload["binary"] == str(binary)
    assert payload["info"] == "R2 INFO"
    assert "one-shot" in payload["note"]


# ---------------------------------------------------------------------------
# disasm.
# ---------------------------------------------------------------------------
def test_disasm_rejects_a_bad_address() -> None:
    client = R2Client(executable=None)
    for bad in (-1, "0x10", 1.5):
        with pytest.raises(R2Error) as caught:
            client.disasm(Path("x"), bad)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"


def test_disasm_rejects_a_bad_count() -> None:
    client = R2Client(executable=None)
    for bad in (0, 513, 2.0):
        with pytest.raises(R2Error) as caught:
            client.disasm(Path("x"), 0x1000, count=bad)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"


def test_disasm_builds_the_command_and_enriches(tmp_path: Path) -> None:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00\x01")
    client = R2Client(executable=None)
    captured: dict[str, Any] = {}

    def fake_run(b: Path, cmds: list[str], *, timeout: float) -> dict[str, Any]:
        captured["cmds"] = cmds
        return {"raw": "[]", "commands": cmds}

    client.run = fake_run  # type: ignore[method-assign]
    payload = client.disasm(binary, 0x1000, count=4)
    assert captured["cmds"] == ["aa", "pdj 4 @ 4096"]
    assert payload["address_va"] == 0x1000
    assert payload["parsed"] is True


# ---------------------------------------------------------------------------
# xrefs.
# ---------------------------------------------------------------------------
def test_xrefs_rejects_a_bad_address() -> None:
    client = R2Client(executable=None)
    for bad in (-1, "0x10"):
        with pytest.raises(R2Error) as caught:
            client.xrefs(Path("x"), bad)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"


def test_xrefs_builds_the_command_and_enriches(tmp_path: Path) -> None:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00\x01")
    client = R2Client(executable=None)
    captured: dict[str, Any] = {}

    def fake_run(b: Path, cmds: list[str], *, timeout: float) -> dict[str, Any]:
        captured["cmds"] = cmds
        return {"raw": "[]", "commands": cmds}

    client.run = fake_run  # type: ignore[method-assign]
    payload = client.xrefs(binary, 0x2000)
    assert captured["cmds"] == ["aa", "axj @ 8192"]
    assert payload["address_va"] == 0x2000


# ---------------------------------------------------------------------------
# run guards.
# ---------------------------------------------------------------------------
def test_run_without_r2_reports_capability_unavailable(tmp_path: Path) -> None:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00")
    client = R2Client(executable=None)
    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"])
    assert caught.value.code == "capability_unavailable"


def test_run_rejects_a_non_positive_timeout(tmp_path: Path) -> None:
    client = R2Client(executable=_fake_exe(tmp_path))
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00")
    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"], timeout=0)
    assert caught.value.code == "invalid_params"


def test_run_reports_a_missing_binary(tmp_path: Path) -> None:
    client = R2Client(executable=_fake_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.run(tmp_path / "absent.bin", ["i"])
    assert caught.value.code == "not_found"


# ---------------------------------------------------------------------------
# available / _discover.
# ---------------------------------------------------------------------------
def test_available_tracks_the_executable(tmp_path: Path) -> None:
    assert R2Client(executable=None).available is False
    assert R2Client(executable=tmp_path / "absent").available is False
    assert R2Client(executable=_fake_exe(tmp_path)).available is True


def test_discover_returns_the_first_tool_on_path(monkeypatch: Any) -> None:
    seen: list[str] = []

    def which(name: str) -> str | None:
        seen.append(name)
        return "/usr/bin/rizin" if name == "rizin" else None

    monkeypatch.setattr(r2mod.shutil, "which", which)
    assert r2mod._discover() == Path("/usr/bin/rizin")
    assert seen[:2] == ["r2", "rizin"]


def test_discover_returns_none_when_no_tool_is_found(monkeypatch: Any) -> None:
    monkeypatch.setattr(r2mod.shutil, "which", lambda name: None)
    assert r2mod._discover() is None
