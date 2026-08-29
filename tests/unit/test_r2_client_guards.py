"""R2Client argument guards, availability refusal, and executable discovery.

The whitelist and timeout bounds are pinned elsewhere; these cover the
client-side contracts around them -- disasm and xrefs refuse addresses and
counts that would build a command outside the whitelist, a missing install
or binary is a named refusal rather than a launch failure, and discovery
returns the first radare2 flavour found on PATH.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import R2Client, R2Error, _discover

JsonObject = dict[str, Any]


def _client_with_fake_run(tmp_path: Path) -> tuple[R2Client, list[tuple[Any, ...]]]:
    client = R2Client(executable=tmp_path / "r2")
    calls: list[tuple[Any, ...]] = []

    def _fake_run(binary: Path, commands: list[str], *, timeout: float = 30.0) -> JsonObject:
        calls.append((binary, commands, timeout))
        return {"raw": "[]", "commands": commands}

    client.run = _fake_run  # type: ignore[method-assign]
    return client, calls


def test_open_names_a_missing_binary(tmp_path: Path) -> None:
    client = R2Client(executable=tmp_path / "r2")
    with pytest.raises(R2Error) as info:
        client.open(tmp_path / "gone.exe")
    assert info.value.code == "not_found"
    assert str(info.value.details["path"]).endswith("gone.exe")


def test_disasm_builds_the_whitelisted_command_and_echoes_the_request(
    tmp_path: Path,
) -> None:
    client, calls = _client_with_fake_run(tmp_path)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x90" * 16)
    data = client.disasm(binary, 0x401000, count=7, timeout=12.0)
    assert calls == [(binary, ["aa", "pdj 7 @ 4198400"], 12.0)]
    # Enrichment turns the flat int into the unified Address shape, echoes
    # the raw request in address_va, and repoints count at the parsed items.
    assert data["address"] == {"va": 0x401000}
    assert data["address_va"] == 0x401000
    assert data["count"] == 0
    assert data["items"] == []
    assert data["module"] == "sample.bin"


def test_disasm_refuses_addresses_and_counts_outside_the_whitelist(
    tmp_path: Path,
) -> None:
    """A bool address or a count of 0 would build a pdj line the whitelist
    regex rejects; refusing here names the actual parameter instead."""
    client, calls = _client_with_fake_run(tmp_path)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x90" * 16)
    for bad_address in (-1, True, "0x401000"):
        with pytest.raises(R2Error) as info:
            client.disasm(binary, bad_address)  # type: ignore[arg-type]
        assert info.value.code == "invalid_params"
        assert "address" in info.value.message
    for bad_count in (0, 513, True, 2.5):
        with pytest.raises(R2Error) as info:
            client.disasm(binary, 0x1000, count=bad_count)  # type: ignore[arg-type]
        assert info.value.code == "invalid_params"
        assert "count" in info.value.message
    assert calls == []


def test_xrefs_builds_the_whitelisted_commands_and_refuses_bad_addresses(
    tmp_path: Path,
) -> None:
    client, calls = _client_with_fake_run(tmp_path)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x90" * 16)
    data = client.xrefs(binary, 4096, timeout=8.0)
    # One spawn, both scoped listings: axtj (refs to the address) and axfj
    # (refs from it). Bare "axj @ addr" is gone -- the seek never filtered it,
    # so it answered every address with the binary's whole xref database.
    assert calls == [(binary, ["aa", "axtj @ 4096", "axfj @ 4096"], 8.0)]
    assert data["address"] == {"va": 4096}

    for bad_address in (-5, False):
        with pytest.raises(R2Error) as info:
            client.xrefs(binary, bad_address)
        assert info.value.code == "invalid_params"
    assert len(calls) == 1


def test_run_refuses_before_launching_when_r2_or_the_binary_is_missing(
    tmp_path: Path,
) -> None:
    missing_install = R2Client(executable=tmp_path / "not-installed")
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x90" * 16)
    with pytest.raises(R2Error) as info:
        missing_install.run(binary, ["i"])
    assert info.value.code == "capability_unavailable"

    executable = tmp_path / "r2"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    installed = R2Client(executable=executable)
    with pytest.raises(R2Error) as info:
        installed.run(tmp_path / "gone.exe", ["i"])
    assert info.value.code == "not_found"


def test_discover_returns_the_first_flavour_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "rizin"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")

    def _which(name: str) -> str | None:
        return str(fake) if name == "rizin" else None

    monkeypatch.setattr(shutil, "which", _which)
    assert _discover() == fake
    # And a machine with none of the three flavours yields an unavailable client.
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert _discover() is None
    assert R2Client().available is False
