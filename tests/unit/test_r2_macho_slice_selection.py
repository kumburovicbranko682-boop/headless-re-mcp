"""Fat Mach-O slice selection: aim r2 at one slice, derive that slice's base.

A universal binary has no single base until an architecture is picked, and which
slice radare2 picks by default is host-dependent, so an unselected fat stays
va-only. When the caller directs r2 at a slice (``slice_arch``), R2Client passes
r2's ``-a``/``-b`` and the mapping layer parses the *selected* slice's own thin
header for its base and arch -- verified in development to equal the ``baddr``
r2 reports for the same selection. These tests pin that path with hand-built
fats and a stubbed r2 launch, so they need no radare2.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.r2 import client as r2client
from headless_re_mcp.backends.r2.client import _SLICE_FLAGS, R2Client
from headless_re_mcp.backends.r2.mapping import (
    enrich_r2_payload,
    macho_preferred_base,
    preferred_base,
)
from headless_re_mcp.core.models import Architecture

_LE64 = b"\xcf\xfa\xed\xfe"


def _thin_with_text(cputype: int, text_vmaddr: int) -> bytes:
    """A thin 64-bit Mach-O carrying __PAGEZERO + __TEXT (fileoff 0).

    Enough for macho_preferred_base to read the load base off __TEXT's vmaddr,
    the way it does for a whole thin file -- here the header sits at a slice
    offset inside a fat instead of at 0.
    """
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
    magic: bytes = b"\xca\xfe\xba\xbe",
    is64: bool = False,
) -> Path:
    """Wrap (cputype, text_vmaddr) slices in a big-endian fat/universal header."""
    blobs = [(cputype, _thin_with_text(cputype, vmaddr)) for cputype, vmaddr in slices]
    entry_size = 32 if is64 else 20
    cursor = (8 + entry_size * len(blobs) + 0xFFF) & ~0xFFF
    placed: list[tuple[int, int, bytes]] = []
    for cputype, blob in blobs:
        placed.append((cputype, cursor, blob))
        cursor += (len(blob) + 0xFFF) & ~0xFFF
    header = magic + struct.pack(">I", len(blobs))
    for cputype, offset, blob in placed:
        if is64:
            header += struct.pack(">IIQQII", cputype, 3, offset, len(blob), 12, 0)
        else:
            header += struct.pack(">IIIII", cputype, 3, offset, len(blob), 12)
    image = bytearray(header)
    for _cputype, offset, blob in placed:
        image = image.ljust(offset, b"\x00") + blob
    path.write_bytes(bytes(image))
    return path


_X64_ARM64 = ((0x01000007, 0x100000000), (0x0100000C, 0x140000000))


def test_unselected_fat_stays_va_only(tmp_path: Path) -> None:
    fat = _write_fat(tmp_path / "u", _X64_ARM64)
    assert macho_preferred_base(fat) == (None, None)
    assert preferred_base(fat) == (None, None)


@pytest.mark.parametrize(
    ("select", "arch", "base"),
    [
        (Architecture.X64, Architecture.X64, 0x100000000),
        (Architecture.ARM64, Architecture.ARM64, 0x140000000),
    ],
)
def test_selected_slice_yields_that_slices_base(
    tmp_path: Path, select: Architecture, arch: Architecture, base: int
) -> None:
    fat = _write_fat(tmp_path / "u", _X64_ARM64)
    assert macho_preferred_base(fat, select=select) == (arch, base)
    # preferred_base chains through to the same answer once PE/ELF decline.
    assert preferred_base(fat, select=select) == (arch, base)


def test_selecting_an_absent_slice_stays_va_only(tmp_path: Path) -> None:
    # This fat has x86_64 + arm64, no 32-bit arm slice: the scan finds nothing
    # and the addresses stay va-only rather than borrowing another slice's base.
    fat = _write_fat(tmp_path / "u", _X64_ARM64)
    assert macho_preferred_base(fat, select=Architecture.ARM) == (None, None)


def test_fat_magic_64_offsets_are_followed(tmp_path: Path) -> None:
    fat = _write_fat(tmp_path / "u64", _X64_ARM64, magic=b"\xca\xfe\xba\xbf", is64=True)
    assert macho_preferred_base(fat, select=Architecture.ARM64) == (
        Architecture.ARM64,
        0x140000000,
    )


def test_selected_slice_ignored_for_a_thin_binary(tmp_path: Path) -> None:
    # A thin file has one architecture; select cannot override it, so the base
    # is the thin file's own regardless of what was asked.
    thin = tmp_path / "thin"
    thin.write_bytes(_thin_with_text(0x01000007, 0x100000000))
    assert macho_preferred_base(thin, select=Architecture.ARM64) == (
        Architecture.X64,
        0x100000000,
    )


def test_enrich_maps_item_to_selected_slice_base(tmp_path: Path) -> None:
    fat = _write_fat(tmp_path / "u", _X64_ARM64)
    raw = json.dumps([{"offset": 0x140001000, "name": "start", "size": 8}])
    payload = enrich_r2_payload(
        {"raw": raw, "commands": ["aa", "aflj"]},
        binary=fat,
        slice_arch=Architecture.ARM64,
    )
    assert payload["image_base"] == 0x140000000
    assert payload["architecture"] == "arm64"
    assert payload["items"][0]["address"] == {
        "module": "u",
        "rva": 0x1000,
        "va": 0x140001000,
        "architecture": "arm64",
    }


def _stub_launch(monkeypatch: Any) -> list[list[str]]:
    """Capture the argv R2Client hands run_bounded, without launching r2."""
    calls: list[list[str]] = []

    def fake_run_bounded(argv: list[str], **_kwargs: Any) -> Any:
        calls.append(list(argv))
        return SimpleNamespace(stdout=b"[]", stderr=b"", returncode=0)

    monkeypatch.setattr(r2client, "run_bounded", fake_run_bounded)
    return calls


def test_slice_arch_adds_r2_arch_bits_flags(tmp_path: Path, monkeypatch: Any) -> None:
    calls = _stub_launch(monkeypatch)
    binary = _write_fat(tmp_path / "u", _X64_ARM64)
    client = R2Client(Path("/usr/bin/true"))
    client.run(binary, ["aflj"], slice_arch=Architecture.ARM64)
    argv = calls[-1]
    assert argv[:2] == [str(client.executable), "-q0"]
    assert "-a" in argv and argv[argv.index("-a") + 1] == "arm"
    assert "-b" in argv and argv[argv.index("-b") + 1] == "64"


def test_no_slice_arch_leaves_argv_flag_free(tmp_path: Path, monkeypatch: Any) -> None:
    calls = _stub_launch(monkeypatch)
    binary = _write_fat(tmp_path / "u", _X64_ARM64)
    client = R2Client(Path("/usr/bin/true"))
    client.run(binary, ["aflj"])
    assert "-a" not in calls[-1] and "-b" not in calls[-1]


def test_slice_flag_table_covers_every_architecture() -> None:
    # Every Architecture the enum can name maps to an (arch, bits) pair, so a
    # slice_arch the service accepts can always be handed to r2.
    assert set(_SLICE_FLAGS) == set(Architecture)
    assert _SLICE_FLAGS[Architecture.X64] == ("x86", "64")
    assert _SLICE_FLAGS[Architecture.ARM64] == ("arm", "64")
    assert _SLICE_FLAGS[Architecture.X86] == ("x86", "32")
    assert _SLICE_FLAGS[Architecture.ARM] == ("arm", "32")
