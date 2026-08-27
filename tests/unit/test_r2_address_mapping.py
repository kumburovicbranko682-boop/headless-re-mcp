"""Unit tests for r2 Address mapping (no live r2 required)."""

from __future__ import annotations

import ast
import json
import os
import sys
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


def test_parse_r2_json_trailing_array() -> None:
    raw = "warning stuff\n" + json.dumps([{"offset": 0x140001000, "name": "entry0", "size": 16}])
    parsed = parse_r2_json(raw)
    assert isinstance(parsed, list)
    assert parsed[0]["name"] == "entry0"


def test_parse_r2_json_keeps_the_whole_list_when_opcodes_contain_brackets() -> None:
    """pdj emits ``mov eax, dword [rbp+0x10]``. rfind('[') used to slice there."""
    raw = json.dumps(
        [
            {"offset": 0x140001000, "opcode": "mov eax, dword [rbp+0x10]"},
            {"offset": 0x140001007, "opcode": "ret"},
        ]
    )
    parsed = parse_r2_json("Cannot find function\n" + raw)
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert parsed[0]["opcode"].endswith("[rbp+0x10]")
    assert parsed[1]["opcode"] == "ret"


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


def test_address_dict_below_image_base_stays_va_only() -> None:
    """An address below the load base has no rva: va-only, no module, and never
    a fabricated (would-be-negative) rva.

    This is the r2 twin of the Ghidra EXTERNAL-space degradation pinned in
    test_ghidra_address_mapping.py. In a coordinate-agreement line the one thing
    worse than "no rva" is a wrong rva, so the guard that keeps va < image_base
    out of the subtraction must be asserted directly, not just implied by the
    happy path.
    """
    below = address_dict(
        0x1000,
        module="demo64.exe",
        image_base=0x140000000,
        architecture=Architecture.X64,
    )
    assert below == {"va": 0x1000, "architecture": "x64"}

    # The lower bound is inclusive: va == image_base is rva 0, still enriched.
    at_base = address_dict(
        0x140000000,
        module="demo64.exe",
        image_base=0x140000000,
        architecture=Architecture.X64,
    )
    assert at_base == {
        "module": "demo64.exe",
        "rva": 0,
        "va": 0x140000000,
        "architecture": "x64",
    }


def test_enrich_r2_item_below_image_base_is_va_only(tmp_path: Path) -> None:
    """An r2 item whose va is below the image base degrades to va-only.

    r2 can report addresses outside the mapped image; enrich_r2_payload must
    carry them as va-only (arch still known from the binary) rather than
    subtracting past the base into a bogus rva. Same contract the Ghidra
    enrichment holds for EXTERNAL-space symbols, now pinned on the r2 side.
    """
    binary = _minimal_pe(tmp_path, x64=True)  # image_base 0x140000000
    raw = json.dumps(
        [
            {"offset": 0x140001000, "name": "entry0"},
            {"offset": 0x1000, "name": "below_base"},
        ]
    )
    enriched = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=binary)
    in_image, below = enriched["items"]
    assert in_image["address"] == {
        "module": "demo64.exe",
        "rva": 0x1000,
        "va": 0x140001000,
        "architecture": "x64",
    }
    assert below["address"] == {"va": 0x1000, "architecture": "x64"}


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


def test_r2_open_only_asks_for_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The catalog called this an analysis pass. It is not.

    Measured: the argv script is ``i`` then ``q``. ``aa`` is what functions
    and disasm run later, each against a fresh process, so giving open a
    longer timeout does not buy analysis for anyone else.
    """
    recorded: list[list[str]] = []

    def capture(cmd: list[str], **kwargs: Any) -> Completed:
        recorded.append(list(cmd))
        return Completed(returncode=0, stdout=b"format pe", stderr=b"")

    monkeypatch.setattr(r2_client, "run_bounded", capture)
    client = r2_client.R2Client(_stub_executable(tmp_path))
    payload = client.open(_minimal_pe(tmp_path))

    assert len(recorded) == 1
    argv = recorded[0]
    script = argv[argv.index("-c") + 1]
    commands = [line for line in script.splitlines() if line and line != "q"]
    assert commands == ["i"], commands
    assert "aa" not in script
    assert "one-shot" in payload["note"]
    assert "reopen" in payload["note"]


def test_r2_open_description_does_not_claim_an_analysis_pass() -> None:
    """A caller that believes open analysed the file will skip r2.functions.

    The live description said it runs an analysis pass and the other r2 tools
    read what this produced. The process it starts only prints identity and
    exits.
    """
    source = Path(r2_client.__file__).resolve().parents[2] / "tools" / "r2.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    described = ""
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == "r2.open"
                ):
                    described = ast.get_docstring(node) or ""
    assert described, "r2.open must describe itself"
    lowered = described.casefold()
    assert "one-shot" in lowered
    assert "reopen" in lowered
    assert "run its own analysis pass" not in lowered
    assert "read what this produced" not in lowered


def _pid_alive(pid: int) -> bool:
    import ctypes

    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def test_r2_timeout_kills_the_process_the_launcher_started(
    tmp_path: Path,
) -> None:
    """subprocess.run returned the timeout while the child kept the core.

    Measured on this machine: r2.cmd that starts a sleeper and holds the pipes
    did not return 8s after a 0.8s deadline, and the sleeper was still alive.
    r2 on PATH is often a script. CREATE_NO_WINDOW is already set so this
    does not pop a console.
    """
    if os.name != "nt":
        pytest.skip("descendant kill here is Win32 (skip != pass)")

    binary = _minimal_pe(tmp_path)
    stub = tmp_path / "r2_stub.py"
    stub.write_text(
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        "print(child.pid, flush=True)\n"
        "while True: time.sleep(0.2)\n",
        encoding="utf-8",
    )
    wrapper = tmp_path / "r2.cmd"
    wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{stub}"\r\n', encoding="utf-8")
    client = r2_client.R2Client(wrapper)

    import time

    started = time.monotonic()
    with pytest.raises(r2_client.R2Error) as caught:
        client.run(binary, ["i"], timeout=0.8)
    elapsed = time.monotonic() - started

    assert caught.value.code == "timeout"
    assert elapsed < 10.0, f"deadline 0.8s, caller waited {elapsed:.1f}s"
    killed = list(caught.value.details.get("killed_pids") or [])
    assert len(killed) >= 2, f"launcher and child, got {killed}"
    for pid in killed:
        assert _pid_alive(int(pid)) is False


def test_function_list_is_items_not_functions(tmp_path: Path) -> None:
    """The catalog said functions with address/size/name; the list is items.

    Measured a typical aflj payload: no functions field, two rows under items,
    each with offset/name/size and address as {va,rva,module}. Looking for
    functions after a successful call reads as radare2 finding none.
    """
    import ast

    from headless_re_mcp.tools.r2 import build_r2_tools

    binary = _minimal_pe(tmp_path, x64=True)
    raw = json.dumps(
        [
            {"offset": 0x140001000, "name": "entry0", "size": 32},
            {"offset": 0x140002000, "name": "f1", "size": 8},
        ]
    )
    payload = enrich_r2_payload(
        {"raw": raw, "commands": ["aa", "aflj"]},
        binary=binary,
        architecture=Architecture.X64,
    )
    assert "functions" not in payload
    assert payload["count"] == 2
    assert payload["items"][0]["name"] == "entry0"
    assert payload["items"][0]["address"]["rva"] == 0x1000

    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    described = ""
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != "r2_functions":
            continue
        described = ast.get_docstring(node) or ""
    assert "Answers with items" in described
    assert "no functions field" in described


def test_r2_functions_docstring_names_the_top_level_coordinate_frame(tmp_path: Path) -> None:
    """r2 and Ghidra now report the same top-level coordinate frame; ghidra.functions
    documents module/image_base/architecture, so r2.functions must too, or the parity
    the coords gate proves is invisible on the r2 side. The wording is checked against
    the keys enrich_r2_payload actually emits so the doc cannot drift from the mapper.
    """
    import ast

    from headless_re_mcp.tools.r2 import build_r2_tools

    binary = _minimal_pe(tmp_path, x64=True)
    payload = enrich_r2_payload(
        {
            "raw": json.dumps([{"offset": 0x140001000, "name": "entry0", "size": 32}]),
            "commands": ["aa", "aflj"],
        },
        binary=binary,
        architecture=Architecture.X64,
    )
    # The frame the docstring promises is really at the top level of the payload.
    assert payload["module"] == "demo64.exe"
    assert payload["image_base"] == 0x140000000
    assert payload["architecture"] == "x64"

    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
    described = ""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef) and node.name == "r2_functions":
            described = ast.get_docstring(node) or ""
    for key in ("module", "image_base", "architecture"):
        assert key in described, key
    assert "top level" in described


def test_r2_info_puts_identity_in_raw_not_arch_bits_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The catalog named format/arch/bits/endianness/entry; none of those exist.

    Measured an ``i`` listing: parsed is false, the text is in raw, and
    architecture is the PE header (x64) rather than r2's arch line. Looking
    for bits after a successful call reads as radare2 returning no identity.
    """
    import ast

    from headless_re_mcp.tools.r2 import build_r2_tools

    binary = _minimal_pe(tmp_path)
    text = b"arch     x86\nbits     64\nos       windows\nendian   little\n"

    def fake(*args: Any, **kwargs: Any) -> Completed:
        return Completed(returncode=0, stdout=text, stderr=b"")

    monkeypatch.setattr(r2_client, "run_bounded", fake)
    payload = r2_client.R2Client(_stub_executable(tmp_path)).run(binary, ["i"])

    assert payload["raw"] == text.decode()
    assert payload["parsed"] is False
    for missing in ("format", "arch", "bits", "endianness", "entry"):
        assert missing not in payload, missing

    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    described = ""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "r2_info":
            described = ast.get_docstring(node) or ""
    assert "Answers with raw" in described
    assert "no format, arch, bits" in described
