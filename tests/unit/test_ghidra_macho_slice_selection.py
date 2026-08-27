"""Fat Mach-O slice selection for Ghidra: carve the slice, import the carve.

Ghidra's headless importer offers no load spec for a fat/universal Mach-O, and
``-processor`` merely forces a language onto whatever loads (verified: every
slice then imports wrong), so directing Ghidra at a slice means carving that
slice -- a complete thin Mach-O, since fat table offsets/sizes span whole slice
files -- and importing the carved file. Coordinates still come from the
original fat via the ``select``-aware base derivation, so the frame matches
what r2 reports for the same ``slice_arch``. These tests pin the carve
primitive and the client behaviour with hand-built fats and a stubbed
analyzeHeadless launch, so they need no Ghidra.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.ghidra.client import GhidraClient, GhidraError
from headless_re_mcp.backends.r2.mapping import macho_slice_span
from headless_re_mcp.core.models import Architecture

_LE64 = b"\xcf\xfa\xed\xfe"


def _thin_with_text(cputype: int, text_vmaddr: int) -> bytes:
    """A thin 64-bit Mach-O carrying __PAGEZERO + __TEXT (fileoff 0)."""
    order = "<"

    def seg(name: str, vmaddr: int, fileoff: int, filesize: int) -> bytes:
        body = struct.pack(order + "II", 0x19, 72) + name.encode().ljust(16, b"\x00")
        body += struct.pack(order + "QQQQ", vmaddr, 0x1000, fileoff, filesize)
        body += struct.pack(order + "IIII", 0, 5, 0, 0)
        return body

    cmds = seg("__PAGEZERO", 0, 0, 0) + seg("__TEXT", text_vmaddr, 0, 0x1000)
    header = _LE64 + struct.pack(order + "IIIII", cputype, 3, 2, 2, len(cmds))
    header += struct.pack(order + "II", 0, 0)
    return header + cmds


def _write_fat(
    path: Path,
    slices: tuple[tuple[int, int], ...],
    *,
    is64: bool = False,
) -> tuple[Path, dict[int, bytes]]:
    """Wrap (cputype, text_vmaddr) slices in a fat header; return slice bytes."""
    blobs = [(cputype, _thin_with_text(cputype, vmaddr)) for cputype, vmaddr in slices]
    entry_size = 32 if is64 else 20
    cursor = (8 + entry_size * len(blobs) + 0xFFF) & ~0xFFF
    placed: list[tuple[int, int, bytes]] = []
    for cputype, blob in blobs:
        placed.append((cputype, cursor, blob))
        cursor += (len(blob) + 0xFFF) & ~0xFFF
    header = (b"\xca\xfe\xba\xbf" if is64 else b"\xca\xfe\xba\xbe") + struct.pack(">I", len(blobs))
    for cputype, offset, blob in placed:
        if is64:
            header += struct.pack(">IIQQII", cputype, 3, offset, len(blob), 12, 0)
        else:
            header += struct.pack(">IIIII", cputype, 3, offset, len(blob), 12)
    image = bytearray(header)
    for _cputype, offset, blob in placed:
        image = image.ljust(offset, b"\x00") + blob
    path.write_bytes(bytes(image))
    return path, {cputype: blob for cputype, blob in blobs}


_X64_ARM64 = ((0x01000007, 0x100000000), (0x0100000C, 0x140000000))


# --- the carve primitive -----------------------------------------------------


def test_slice_span_of_a_thin_binary_is_none(tmp_path: Path) -> None:
    thin = tmp_path / "thin"
    thin.write_bytes(_thin_with_text(0x01000007, 0x100000000))
    assert macho_slice_span(thin, Architecture.X64) is None


def test_slice_span_of_a_missing_file_is_none(tmp_path: Path) -> None:
    assert macho_slice_span(tmp_path / "absent", Architecture.X64) is None


@pytest.mark.parametrize("is64", [False, True], ids=["fat32", "fat64"])
def test_slice_span_names_each_slices_bytes(tmp_path: Path, is64: bool) -> None:
    fat, blobs = _write_fat(tmp_path / "u", _X64_ARM64, is64=is64)
    data = fat.read_bytes()
    for select, cputype in ((Architecture.X64, 0x01000007), (Architecture.ARM64, 0x0100000C)):
        span = macho_slice_span(fat, select)
        assert span is not None
        offset, size = span
        assert data[offset : offset + size] == blobs[cputype]


def test_slice_span_of_an_absent_architecture_is_none(tmp_path: Path) -> None:
    fat, _ = _write_fat(tmp_path / "u", _X64_ARM64)
    assert macho_slice_span(fat, Architecture.ARM) is None


def test_slice_span_of_a_truncated_table_is_none(tmp_path: Path) -> None:
    # nfat says two entries but the file ends inside the table.
    stub = tmp_path / "u"
    stub.write_bytes(b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\x00" * 8)
    assert macho_slice_span(stub, Architecture.X64) is None


# --- the client: what gets imported, what the payload says -------------------


def _client(tmp_path: Path) -> GhidraClient:
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    (home / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    client = GhidraClient(home=home)
    client.java = tmp_path / "java"
    client.java.write_bytes(b"")
    return client


def _capture_run(monkeypatch: pytest.MonkeyPatch, payload: str) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        argv = [str(part) for part in cmd]
        calls.append(argv)
        for arg in argv:
            if arg.endswith(".json"):
                Path(arg).write_text(payload, encoding="utf-8")
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    return calls


def _imported(argv: list[str]) -> str:
    return argv[argv.index("-import") + 1]


def test_slice_arch_imports_the_carved_slice_and_maps_its_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path)
    fat, blobs = _write_fat(tmp_path / "universal", _X64_ARM64)
    calls = _capture_run(
        monkeypatch, '{"mode": "functions", "items": [{"name": "entry", "entry": "100000400"}]}'
    )
    project = tmp_path / "project"

    payload = client.functions(fat, project, slice_arch=Architecture.X64)

    # analyzeHeadless received the carved thin slice, byte-identical to the
    # fat table's x86_64 entry, not the fat itself.
    carved = Path(_imported(calls[0]))
    assert carved != fat
    assert carved.name == fat.name, "carve keeps the original file name"
    assert carved.read_bytes() == blobs[0x01000007]

    # The payload frame and item coordinates come from the selected slice's
    # own header, in the fat's module -- the frame r2 reports for -a/-b x64.
    assert payload["module"] == fat.name
    assert payload["image_base"] == 0x100000000
    assert payload["architecture"] == "x64"
    assert payload["items"][0]["entry_address"] == {
        "module": fat.name,
        "rva": 0x400,
        "va": 0x100000400,
        "architecture": "x64",
    }


def test_no_slice_arch_imports_the_original_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path)
    fat, _ = _write_fat(tmp_path / "universal", _X64_ARM64)
    calls = _capture_run(monkeypatch, '{"mode": "functions", "items": []}')

    client.functions(fat, tmp_path / "project")

    assert _imported(calls[0]) == str(fat)


def test_an_absent_slice_is_rejected_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path)
    fat, _ = _write_fat(tmp_path / "universal", _X64_ARM64)
    calls = _capture_run(monkeypatch, '{"mode": "functions", "items": []}')

    with pytest.raises(GhidraError) as excinfo:
        client.functions(fat, tmp_path / "project", slice_arch=Architecture.ARM)
    assert excinfo.value.code == "invalid_params"
    assert calls == [], "no headless run was spawned for a slice that does not exist"


def test_a_thin_binary_with_slice_arch_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path)
    thin = tmp_path / "thin"
    thin.write_bytes(_thin_with_text(0x01000007, 0x100000000))
    calls = _capture_run(monkeypatch, '{"mode": "functions", "items": []}')

    with pytest.raises(GhidraError) as excinfo:
        client.functions(thin, tmp_path / "project", slice_arch=Architecture.X64)
    assert excinfo.value.code == "invalid_params"
    assert calls == []


def test_a_table_pointing_past_eof_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A well-formed table whose size field overruns the file: the carve must
    # fail loudly rather than hand Ghidra a silently truncated slice.
    stub = tmp_path / "u"
    stub.write_bytes(
        b"\xca\xfe\xba\xbe"
        + struct.pack(">I", 1)
        + struct.pack(">IIIII", 0x01000007, 3, 0x40, 0x10000, 12)
    )
    client = _client(tmp_path)
    calls = _capture_run(monkeypatch, '{"mode": "functions", "items": []}')

    with pytest.raises(GhidraError) as excinfo:
        client.functions(stub, tmp_path / "project", slice_arch=Architecture.X64)
    assert excinfo.value.code == "invalid_params"
    assert "end of the file" in excinfo.value.message
    assert calls == []


def test_analyze_binary_imports_the_carved_slice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path)
    fat, blobs = _write_fat(tmp_path / "universal", _X64_ARM64)
    calls = _capture_run(monkeypatch, '{"mode": "functions", "items": []}')

    client.analyze_binary(fat, tmp_path / "project", slice_arch=Architecture.ARM64)

    carved = Path(_imported(calls[0]))
    assert carved != fat
    assert carved.read_bytes() == blobs[0x0100000C]
