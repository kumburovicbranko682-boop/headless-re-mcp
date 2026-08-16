"""Unit tests for r2 Address mapping (no live r2 required)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_client
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

    def huge(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"A" * 500, stderr=b"")

    monkeypatch.setattr(r2_client.subprocess, "run", huge)
    client = r2_client.R2Client(_stub_executable(tmp_path))

    payload = client.run(binary, ["aa"])

    assert payload["truncated"] is True, "a cut listing must not read as a complete one"
    assert payload["output_bytes"] == 500
    assert payload["returned_bytes"] == 64
    assert len(str(payload["raw"])) == 64


def test_open_cut_info_says_it_was_cut(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """r2.open used to slice info at 8000 characters with no truncated.

    Measured: 20_000 characters of ``i`` still answered
    ``{'opened': True, 'info': <8000 chars>}`` and no truncated. An
    unattended agent then treats the fragment as the binary identity.
    """
    binary = _minimal_pe(tmp_path)

    def huge(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"I" * 20_000, stderr=b"")

    monkeypatch.setattr(r2_client.subprocess, "run", huge)
    client = r2_client.R2Client(_stub_executable(tmp_path))
    payload = client.open(binary)

    assert payload["opened"] is True
    assert len(payload["info"]) == 8000
    assert payload["truncated"] is True
    assert payload["output_chars"] == 20_000
    assert payload["returned_chars"] == 8000


def test_open_info_that_fits_is_not_labelled_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = _minimal_pe(tmp_path)

    def small(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"arch x86", stderr=b"")

    monkeypatch.setattr(r2_client.subprocess, "run", small)
    client = r2_client.R2Client(_stub_executable(tmp_path))
    payload = client.open(binary)

    assert payload["info"] == "arch x86"
    assert "truncated" not in payload


def test_open_tool_description_says_to_read_truncated() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "src" / "headless_re_mcp" / "tools" / "r2.py"
    ).read_text(encoding="utf-8")
    block = source.split("def r2_open(")[1].split("def r2_functions(")[0]
    assert "truncated" in block


def test_open_tool_description_does_not_claim_an_analysis_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The tool text used to say analysis ran and later tools reuse it.

    Measured: r2.open invoked ``-c i\\nq`` (info only) and the client note
    says subsequent tools reopen the binary, while the description said
    ``run its own analysis pass`` and ``the other r2 tools read what this
    produced``. An unattended agent then skips ``aa`` and treats later
    listings as already analysed.
    """
    seen: list[list[str]] = []

    def capture(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        seen.append(list(argv))
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"arch", stderr=b"")

    monkeypatch.setattr(r2_client.subprocess, "run", capture)
    client = r2_client.R2Client(_stub_executable(tmp_path))
    client.open(_minimal_pe(tmp_path))
    assert seen, "open must invoke r2"
    script = seen[0][seen[0].index("-c") + 1]
    assert script.split()[0] == "i"
    assert "aa" not in script

    source = (
        Path(__file__).resolve().parents[2] / "src" / "headless_re_mcp" / "tools" / "r2.py"
    ).read_text(encoding="utf-8")
    block = source.split("def r2_open(")[1].split("def r2_functions(")[0]
    assert "analysis pass" not in block
    assert "read what this produced" not in block
    assert "reopen" in block


def test_output_that_fits_is_not_labelled_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The flag has to mean something, so it stays off when nothing was cut."""
    binary = _minimal_pe(tmp_path)

    def small(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"[]", stderr=b"")

    monkeypatch.setattr(r2_client.subprocess, "run", small)
    client = r2_client.R2Client(_stub_executable(tmp_path))

    payload = client.run(binary, ["aa"])

    assert "truncated" not in payload
    assert payload["raw"] == "[]"


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


def test_a_cut_function_list_is_marked(tmp_path: Path) -> None:
    """A function list that hit the item cap used to look complete if unread.

    Measured: 4146 functions came back as count=4096, items_truncated=True,
    while the tool text omitted items_truncated. An unattended agent that
    trusted the description treated the page as every function.
    """
    from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS

    binary = _minimal_pe(tmp_path, x64=True)
    raw = json.dumps(
        [{"offset": 0x140001000 + index, "name": f"f{index}"} for index in range(4146)]
    )
    enriched = enrich_r2_payload({"raw": raw, "commands": ["aa", "aflj"]}, binary=binary)
    assert enriched["count"] == _MAX_ITEMS
    assert enriched["items_truncated"] is True
    assert enriched["items_total"] == 4146


def test_a_cut_string_list_is_marked(tmp_path: Path) -> None:
    """A string list that hit the item cap used to look complete if unread.

    Measured: 4146 strings came back as count=4096, items_truncated=True,
    while the tool text omitted items_truncated. An unattended agent that
    trusted the description treated the page as every string.
    """
    from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS

    binary = _minimal_pe(tmp_path, x64=True)
    raw = json.dumps(
        [{"vaddr": 0x140001000 + index, "string": f"s{index}"} for index in range(4146)]
    )
    enriched = enrich_r2_payload({"raw": raw, "commands": ["izj"]}, binary=binary)
    assert enriched["count"] == _MAX_ITEMS
    assert enriched["items_truncated"] is True
    assert enriched["items_total"] == 4146


def test_a_cut_import_list_is_marked(tmp_path: Path) -> None:
    """An import list that hit the item cap used to look complete if unread.

    Measured: 4146 imports came back as count=4096, items_truncated=True,
    while the tool text omitted items_truncated. An unattended agent that
    trusted the description treated the page as every import.
    """
    from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS

    binary = _minimal_pe(tmp_path, x64=True)
    raw = json.dumps(
        [{"plt": 0x140001000 + index, "name": f"imp{index}"} for index in range(4146)]
    )
    enriched = enrich_r2_payload({"raw": raw, "commands": ["iij"]}, binary=binary)
    assert enriched["count"] == _MAX_ITEMS
    assert enriched["items_truncated"] is True
    assert enriched["items_total"] == 4146


def test_a_cut_export_list_is_marked(tmp_path: Path) -> None:
    """An export list that hit the item cap used to look complete if unread.

    Measured: 4146 exports came back as count=4096, items_truncated=True,
    while the tool text omitted items_truncated. An unattended agent that
    trusted the description treated the page as every export.
    """
    from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS

    binary = _minimal_pe(tmp_path, x64=True)
    raw = json.dumps(
        [{"vaddr": 0x140001000 + index, "name": f"exp{index}"} for index in range(4146)]
    )
    enriched = enrich_r2_payload({"raw": raw, "commands": ["iEj"]}, binary=binary)
    assert enriched["count"] == _MAX_ITEMS
    assert enriched["items_truncated"] is True
    assert enriched["items_total"] == 4146


def test_exports_tool_description_says_to_read_items_truncated() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "src" / "headless_re_mcp" / "tools" / "r2.py"
    ).read_text(encoding="utf-8")
    block = source.split("def r2_exports(")[1].split("def r2_disasm(")[0]
    assert "items_truncated" in block


def test_imports_tool_description_says_to_read_items_truncated() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "src" / "headless_re_mcp" / "tools" / "r2.py"
    ).read_text(encoding="utf-8")
    block = source.split("def r2_imports(")[1].split("def r2_exports(")[0]
    assert "items_truncated" in block


def test_strings_tool_description_says_to_read_items_truncated() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "src" / "headless_re_mcp" / "tools" / "r2.py"
    ).read_text(encoding="utf-8")
    block = source.split("def r2_strings(")[1].split("def r2_imports(")[0]
    assert "items_truncated" in block


def test_functions_tool_description_says_to_read_items_truncated() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "src" / "headless_re_mcp" / "tools" / "r2.py"
    ).read_text(encoding="utf-8")
    block = source.split("def r2_functions(")[1].split("def r2_strings(")[0]
    assert "items_truncated" in block


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
