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


def test_parse_r2_json_skips_a_bracketed_banner_before_the_array() -> None:
    """r2 -q0 leads its output with brackets that are not the payload.

    The scan tries json.raw_decode at *every* '[' or '{', not just the first,
    because r2 prints its interactive prompt '[0x00000000]>' and log tags like
    '[WARN]' ahead of the JSON. A first-bracket parse would start inside the
    prompt, fail, and (with rfind or a give-up) miss the real array. The decode
    at those leading brackets must fail quietly and the scan continue to the
    root list -- the opcode-bracket test above never exercises that skip, because
    there the very first bracket is already the valid array.
    """
    array = json.dumps([{"offset": 0x401000, "name": "main"}])
    raw = "[0x00000000]> \n[WARN] partial analysis\n" + array
    parsed = parse_r2_json(raw)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["name"] == "main"


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


def test_enrich_surfaces_a_json_object_as_info(tmp_path: Path) -> None:
    """Some r2 commands (ij, iSj) answer with an object, not an array.

    The list branch fills items/count; an object has no rows to map, so it is
    carried verbatim under 'info' with parsed True and no items. A caller must
    not read count/items for such a payload, and a break that dropped the dict
    branch would report parsed False for a perfectly good answer.
    """
    binary = _minimal_pe(tmp_path, x64=True)
    info = {"core": {"type": "PE32+"}, "bin": {"arch": "x86", "bits": 64}}
    enriched = enrich_r2_payload({"raw": json.dumps(info), "commands": ["ij"]}, binary=binary)
    assert enriched["parsed"] is True
    assert enriched["info"] == info
    assert "items" not in enriched
    assert "count" not in enriched


def test_enrich_maps_addresses_given_as_hex_strings(tmp_path: Path) -> None:
    """r2 emits some address fields as strings ('0x401000'), not integers.

    _item_va takes an int directly and parses a string with int(x, 0), so a
    hex-string offset still maps to an Address. A key whose string is not a
    number is skipped so a later, valid key can still supply the address --
    without that, one unparsable field would drop the whole row's address.
    """
    binary = _minimal_pe(tmp_path, x64=True)
    raw = json.dumps(
        [
            {"offset": "0x140001000", "name": "hex-offset"},
            {"offset": "n/a", "vaddr": 0x140002000, "name": "fallback-key"},
        ]
    )
    enriched = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=binary)
    items = enriched["items"]
    assert items[0]["address"]["va"] == 0x140001000
    assert items[0]["address"]["rva"] == 0x1000
    # 'offset' was unparsable ('n/a'), so the address came from the next key.
    assert items[1]["address"]["va"] == 0x140002000
    assert items[1]["address"]["rva"] == 0x2000


def test_enrich_drops_non_dict_rows_and_keeps_rows_without_an_address(tmp_path: Path) -> None:
    """A parsed array can carry noise and rows with no recognised address.

    A non-dict element is dropped entirely; a dict with no address key is kept
    as an item but without an 'address' field, because losing the row would hide
    data the caller can still read by name. count reflects the surviving dicts.
    """
    binary = _minimal_pe(tmp_path, x64=True)
    raw = json.dumps(
        [
            "a bare string",
            42,
            {"name": "no-address-here", "size": 8},
            {"offset": 0x140001000, "name": "has-address"},
        ]
    )
    enriched = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=binary)
    items = enriched["items"]
    assert enriched["count"] == 2
    assert [it["name"] for it in items] == ["no-address-here", "has-address"]
    assert "address" not in items[0]
    assert items[1]["address"]["va"] == 0x140001000


def test_enrich_flags_when_the_item_list_is_capped(tmp_path: Path) -> None:
    """A list cut at the item cap must say so, like the raw-output cut does.

    enrich keeps at most _MAX_ITEMS rows; past that a caller enumerating xrefs
    or functions would read a capped list as a complete one and conclude 'these
    are all of them'. The payload flags items_truncated with the true total and
    the limit, mirroring the raw truncation flag the sibling path already sets --
    and count/len stay pinned to the cap so the flag cannot drift from reality.
    """
    from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS

    binary = _minimal_pe(tmp_path, x64=True)
    total = _MAX_ITEMS + 5
    raw = json.dumps([{"offset": 0x140000000 + index * 4} for index in range(total)])
    enriched = enrich_r2_payload({"raw": raw, "commands": ["axtj"]}, binary=binary)
    assert enriched["count"] == _MAX_ITEMS
    assert len(enriched["items"]) == _MAX_ITEMS
    assert enriched["items_truncated"] is True
    assert enriched["items_total"] == total
    assert enriched["items_limit"] == _MAX_ITEMS


def test_pe_preferred_base_degrades_on_a_malformed_or_unknown_header(tmp_path: Path) -> None:
    """pe_preferred_base runs for every r2 payload, including non-PE targets.

    r2 on Linux analyses ELF and raw blobs too, so this parser must never raise
    or misreport on a header it does not recognise. Each case degrades to a
    documented fallback rather than a guess: an unknown optional-header magic, a
    truncated optional header, and a wrong PE signature yield no architecture
    and no base, while a valid magic whose ImageBase is zero still names the
    architecture but reports no base (there is no positive load address to map
    RVAs against).
    """

    def _pe(
        *,
        magic: int = 0x20B,
        image_base: int = 0x140000000,
        optional_size: int = 0xF0,
        pe_sig: bytes = b"PE\0\0",
    ) -> Path:
        data = bytearray(0x200)
        data[0:2] = b"MZ"
        po = 0x80
        data[0x3C:0x40] = po.to_bytes(4, "little")
        data[po : po + 4] = pe_sig
        data[po + 20 : po + 22] = optional_size.to_bytes(2, "little")
        oo = po + 24
        data[oo : oo + 2] = magic.to_bytes(2, "little")
        if magic == 0x20B:
            data[oo + 24 : oo + 32] = image_base.to_bytes(8, "little")
        else:
            data[oo + 28 : oo + 32] = (image_base & 0xFFFFFFFF).to_bytes(4, "little")
        out = tmp_path / f"pe-{magic:x}-{image_base:x}-{optional_size:x}-{pe_sig.hex()}.bin"
        out.write_bytes(bytes(data))
        return out

    # A sane header still parses, so the negative cases below are meaningful.
    assert pe_preferred_base(_pe()) == (Architecture.X64, 0x140000000)
    # Unknown optional-header magic: no architecture, no base.
    assert pe_preferred_base(_pe(magic=0x999)) == (None, None)
    # Optional header too short to hold the ImageBase field.
    assert pe_preferred_base(_pe(optional_size=32)) == (None, None)
    # MZ present but the PE signature is wrong -- not a PE after all.
    assert pe_preferred_base(_pe(pe_sig=b"XX\0\0")) == (None, None)
    # Valid magic, but ImageBase is zero: architecture known, base unknown.
    assert pe_preferred_base(_pe(image_base=0)) == (Architecture.X64, None)


def test_pe_preferred_base_reads_a_32_bit_image_base_from_its_own_offset(tmp_path: Path) -> None:
    """A PE32 (magic 0x10B) carries ImageBase at optional[28:32], not [24:32].

    Every other mapping test builds an x64 image (0x20B, an 8-byte base at
    [24:32]); the 32-bit path reads a 4-byte base from a different offset and a
    different architecture, and 32-bit PEs are the bulk of what r2 sees for
    legacy and packed samples. A regression that reused the x64 offset -- or
    mislabelled the architecture -- would shift every RVA this backend maps for a
    32-bit target, so the x86 branch is pinned as its own case rather than left
    to the x64 fixture the rest of the file uses.
    """
    binary = _minimal_pe(tmp_path, x64=False)
    assert pe_preferred_base(binary) == (Architecture.X86, 0x400000)


def test_pe_preferred_base_rereads_when_the_header_straddles_the_first_window(
    tmp_path: Path,
) -> None:
    """A header ending past the 64 KiB probe window is re-read, not dropped.

    pe_preferred_base first reads only a 64 KiB window -- slurping a 200 MB
    target to read one field cost 200 MB of RSS per call. When the PE signature
    sits inside that window but the optional header runs past it, the first slice
    is too short to hold the ImageBase, and the parser must seek back and read
    the whole header. Placing the signature just below 64 KiB forces exactly that
    second pass; without it this binary -- a real shape for a bloated or oddly
    linked image -- would silently report no base instead of its true one.
    """
    from headless_re_mcp.backends.r2.mapping import _HEADER_WINDOW

    pe_offset = _HEADER_WINDOW - 8  # signature readable in pass one; optional header is not
    optional_size = 0xF0
    optional_off = pe_offset + 24
    data = bytearray(optional_off + optional_size)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    data[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    data[optional_off : optional_off + 2] = (0x20B).to_bytes(2, "little")
    data[optional_off + 24 : optional_off + 32] = (0x140000000).to_bytes(8, "little")
    binary = tmp_path / "straddle.exe"
    binary.write_bytes(bytes(data))

    assert pe_preferred_base(binary) == (Architecture.X64, 0x140000000)


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


def test_disasm_disassembles_at_the_request_address_with_the_request_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """disasm runs ``pdj <count> @ <address>`` and maps the request address back.

    The requested count is what pdj is told to fetch (an off-by-one on the
    address or count disassembles the wrong bytes), while the reply reports the
    instructions that actually came back and maps each to its module address.
    The request address is carried back mapped to {va, rva} so a caller knows
    which address the disassembly belongs to, not just anonymous opcode text.
    """
    recorded: list[list[str]] = []
    rows = [
        {"offset": 0x140001000, "opcode": "nop"},
        {"offset": 0x140001001, "opcode": "ret"},
    ]

    def capture(cmd: list[str], **kwargs: Any) -> Completed:
        recorded.append(list(cmd))
        return Completed(returncode=0, stdout=json.dumps(rows).encode(), stderr=b"")

    monkeypatch.setattr(r2_client, "run_bounded", capture)
    client = r2_client.R2Client(_stub_executable(tmp_path))
    payload = client.disasm(_minimal_pe(tmp_path), 0x140001000, count=4)

    assert payload["address"]["rva"] == 0x1000
    assert payload["address_va"] == 0x140001000
    assert payload["count"] == 2
    assert payload["items"][0]["address"]["rva"] == 0x1000
    argv = recorded[0]
    script = argv[argv.index("-c") + 1]
    assert f"pdj 4 @ {0x140001000}" in script
    assert "aa" in script.splitlines()


def test_xrefs_asks_for_axtj_at_the_request_address_and_echoes_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """xrefs must query axtj (references to) at the asked address and echo it.

    The reply lists references to one address; without echoing which address was
    queried the list is unanchored, so the payload has to carry it alongside the
    ``axtj @ <address>`` command that produced it. axtj -- not the whole-program
    ``axj`` -- is what scopes the result to this address and stays parseable
    across r2 versions (it returns [] rather than empty for no references).
    """
    recorded: list[list[str]] = []

    def capture(cmd: list[str], **kwargs: Any) -> Completed:
        recorded.append(list(cmd))
        return Completed(returncode=0, stdout=b"[]", stderr=b"")

    monkeypatch.setattr(r2_client, "run_bounded", capture)
    client = r2_client.R2Client(_stub_executable(tmp_path))
    payload = client.xrefs(_minimal_pe(tmp_path), 0x140002000)

    assert payload["address"]["rva"] == 0x2000
    assert payload["address_va"] == 0x140002000
    argv = recorded[0]
    script = argv[argv.index("-c") + 1]
    assert f"axtj @ {0x140002000}" in script
    # The dead whole-program command must not be what we send.
    assert "axj @" not in script


def test_xrefs_of_a_referent_free_address_is_parsed_with_zero_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An address nothing references answers parsed True, count 0 -- not an error.

    This is the contract the switch to axtj restored. The first function r2 lists
    is usually the entry point, which nothing calls, so xrefs at it is the common
    case, not an edge one. axtj answers ``[]`` there; the old whole-program
    ``axj`` answered with empty output on radare2 6.x, which parse_r2_json read as
    a parse failure (parsed False) -- an agent then could not tell "no callers"
    from "the query broke". Pinning [] -> parsed True, count 0, items [] keeps
    that distinction honest without needing r2 on the box.
    """

    def empty_list(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(returncode=0, stdout=b"[]\n", stderr=b"")

    monkeypatch.setattr(r2_client, "run_bounded", empty_list)
    client = r2_client.R2Client(_stub_executable(tmp_path))
    payload = client.xrefs(_minimal_pe(tmp_path), 0x140001000)

    assert payload["parsed"] is True
    assert payload["count"] == 0
    assert payload["items"] == []
    assert payload["address_va"] == 0x140001000
    assert "items_truncated" not in payload


def test_open_reports_a_missing_binary_as_not_found(tmp_path: Path) -> None:
    """open refuses a nonexistent binary before spawning r2.

    The guard names the missing path so the caller sees a bad input, not an r2
    that failed to open a file it was never given.
    """
    client = r2_client.R2Client(_stub_executable(tmp_path))
    missing = tmp_path / "nope.exe"
    with pytest.raises(r2_client.R2Error) as caught:
        client.open(missing)
    assert caught.value.code == "not_found"
    assert caught.value.details.get("path") == str(missing)


def test_run_reports_a_missing_binary_as_not_found(tmp_path: Path) -> None:
    """run refuses a nonexistent binary even when r2 itself is configured.

    Availability is checked first, so a configured r2 pointed at a missing file
    still answers not_found rather than launching r2 on a path that is not there.
    """
    client = r2_client.R2Client(_stub_executable(tmp_path))
    assert client.available is True
    missing = tmp_path / "gone.bin"
    with pytest.raises(r2_client.R2Error) as caught:
        client.run(missing, ["i"])
    assert caught.value.code == "not_found"
    assert caught.value.details.get("path") == str(missing)


def test_discover_returns_the_first_tool_found_on_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_discover prefers r2, then rizin, then radare2, and resolves the found one.

    The client falls back to PATH discovery when no executable is configured, so
    the first name that resolves must come back as a Path -- a discovery that
    answered None with r2 on PATH would report the backend unavailable when it
    is installed.
    """
    def only_rizin(name: str) -> str | None:
        return "/opt/bin/rizin" if name == "rizin" else None

    monkeypatch.setattr(r2_client.shutil, "which", only_rizin)
    assert r2_client._discover() == Path("/opt/bin/rizin")
