"""Unit tests for r2 Address mapping (no live r2 required)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_client
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.mapping import (
    address_dict,
    enrich_r2_payload,
    parse_r2_json,
    pe_preferred_base,
)
from headless_re_mcp.core.models import Architecture


def _minimal_pe(tmp_path: Path, *, x64: bool = True) -> Path:
    # Tiny fake PE with MZ + PE + optional header image base.
    path = tmp_path / ("demo64.exe" if x64 else "demo32.exe")
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    # SizeOfOptionalHeader
    optional_size = 0xF0 if x64 else 0xE0
    data[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    optional_off = pe_offset + 24
    if x64:
        data[optional_off : optional_off + 2] = (0x20B).to_bytes(2, "little")
        image_base = 0x140000000
        data[optional_off + 24 : optional_off + 32] = image_base.to_bytes(8, "little")
    else:
        data[optional_off : optional_off + 2] = (0x10B).to_bytes(2, "little")
        image_base = 0x400000
        data[optional_off + 28 : optional_off + 32] = image_base.to_bytes(4, "little")
    # SizeOfImage
    data[optional_off + 56 : optional_off + 60] = (0x10000).to_bytes(4, "little")
    path.write_bytes(bytes(data))
    return path


def _stub_executable(tmp_path: Path) -> Path:
    """A file that exists, so the client considers r2 available without one."""
    path = tmp_path / "r2"
    path.write_bytes(b"")
    return path


def test_output_cut_at_the_buffer_says_it_was_cut(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A listing that stopped at the cap looks like a listing that ended.

    ``raw`` is the analysis text a caller reads to decide where a function
    finishes, and it was trimmed at a megabyte with nothing to say so. The
    sibling backends in this package all flag their own truncation.
    """
    binary = _minimal_pe(tmp_path)
    monkeypatch.setattr(r2_client, "_MAX_OUTPUT", 64)

    def huge(*args: Any, **kwargs: Any) -> Completed:
        return Completed(returncode=0, stdout=b"A" * 500, stderr=b"")

    monkeypatch.setattr(r2_client, "run_bounded", huge)
    client = r2_client.R2Client(_stub_executable(tmp_path))

    payload = client.run(binary, ["aa"])

    assert payload["truncated"] is True, "a cut listing must not read as a complete one"
    assert payload["output_bytes"] == 500
    assert payload["returned_bytes"] == 64
    assert len(str(payload["raw"])) == 64


def test_output_that_fits_is_not_labelled_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The flag has to mean something, so it stays off when nothing was cut."""
    binary = _minimal_pe(tmp_path)

    def small(*args: Any, **kwargs: Any) -> Completed:
        return Completed(returncode=0, stdout=b"[]", stderr=b"")

    monkeypatch.setattr(r2_client, "run_bounded", small)
    client = r2_client.R2Client(_stub_executable(tmp_path))

    payload = client.run(binary, ["aa"])

    assert "truncated" not in payload
    assert payload["raw"] == "[]"


def test_a_cut_function_array_is_not_the_last_function(tmp_path: Path) -> None:
    """A truncated aflj used to parse as one complete function.

    Measured: 50 rows with the closing ] removed became
    info={last function}, parsed=True, no items.
    """
    items = [{"name": f"fcn.{index}", "offset": index, "size": 16} for index in range(50)]
    cut = json.dumps(items)[:-1]
    assert parse_r2_json(cut) is None
    binary = _minimal_pe(tmp_path)
    enriched = enrich_r2_payload(
        {"raw": cut, "commands": ["aa", "aflj"], "truncated": True},
        binary=binary,
    )
    assert enriched["parsed"] is False
    assert "info" not in enriched
    assert "items" not in enriched


def test_parse_r2_json_trailing_array() -> None:
    raw = "warning stuff\n" + json.dumps([{"offset": 0x140001000, "name": "entry0", "size": 16}])
    parsed = parse_r2_json(raw)
    assert isinstance(parsed, list)
    assert parsed[0]["name"] == "entry0"


def test_address_dict_with_rva() -> None:
    mapped = address_dict(
        0x140001000,
        module="demo64.exe",
        image_base=0x140000000,
        architecture=Architecture.X64,
    )
    assert mapped == {
        "module": "demo64.exe",
        "rva": 0x1000,
        "va": 0x140001000,
        "architecture": "x64",
    }


def test_enrich_functions_payload(tmp_path: Path) -> None:
    binary = _minimal_pe(tmp_path, x64=True)
    arch, base = pe_preferred_base(binary)
    assert arch is Architecture.X64
    assert base == 0x140000000
    raw = json.dumps(
        [
            {"offset": 0x140001000, "name": "entry0", "size": 32},
            {"offset": 0x140002000, "name": "f1", "size": 8},
        ]
    )
    enriched = enrich_r2_payload(
        {"raw": raw, "commands": ["aa", "aflj"]},
        binary=binary,
        architecture=Architecture.X64,
    )
    assert enriched["parsed"] is True
    assert enriched["count"] == 2
    assert enriched["items"][0]["address"]["rva"] == 0x1000
    assert enriched["items"][0]["address"]["module"] == "demo64.exe"
    assert enriched["items"][1]["address"]["va"] == 0x140002000


def test_enrich_disasm_request_address(tmp_path: Path) -> None:
    binary = _minimal_pe(tmp_path, x64=True)
    raw = json.dumps([{"offset": 0x140001000, "opcode": "nop"}])
    enriched = enrich_r2_payload(
        {"raw": raw, "commands": ["pdj"], "address": 0x140001000, "count": 1},
        binary=binary,
    )
    assert enriched["address"]["rva"] == 0x1000
    assert enriched["address_va"] == 0x140001000
    assert enriched["items"][0]["address"]["module"] == binary.name


def test_a_timeout_kills_what_the_r2_launcher_started(tmp_path: Path) -> None:
    """r2 used subprocess.run, which kills the launcher and leaves the tool.

    Measured the same shape as isolation: a wrapper that starts a sleeper
    returns a timeout while the sleeper is reparented to pid 1. r2 is
    invoked on every listing, so that orphan holds the sample open.
    """
    pid_path = tmp_path / "child.pid"
    launcher = tmp_path / "fake-r2"
    launcher.write_text(
        "#!/usr/bin/env python3\n"
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        f"open({str(pid_path)!r}, 'w').write(str(child.pid))\n"
        "while True: time.sleep(0.2)\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    binary = _minimal_pe(tmp_path)
    client = r2_client.R2Client(launcher)

    started = time.monotonic()
    with pytest.raises(r2_client.R2Error) as caught:
        client.run(binary, ["i"], timeout=0.8)
    elapsed = time.monotonic() - started

    assert caught.value.code == "timeout"
    assert elapsed < 5.0
    assert pid_path.is_file()
    child = int(pid_path.read_text())
    deadline = time.monotonic() + 2.0
    alive = True
    while time.monotonic() < deadline:
        try:
            os.kill(child, 0)
        except OSError:
            alive = False
            break
        time.sleep(0.05)
    assert alive is False, "the process r2 started outlived the timeout"
    assert child in list(caught.value.details.get("killed") or [])
