"""The .NET reader walks more attacker-controlled arithmetic than the PE one.

Stream headers, table row counts and heap offsets all come out of a file nobody
trusts. Getting a report back from a mangled assembly is fine; getting one that
looks like a good assembly is not, because the tools downstream act on it.
"""

from __future__ import annotations

import dataclasses
import struct
import time
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError, inspect_dotnet

# A real de4dot build is the richest thing to mutate when a dev has one, but it
# is never in CI, so this hardening used to skip there entirely -- "skip != pass"
# on the exact fail-closed paths that matter most. The committed minimal
# assembly is a genuine managed image too, so fall back to it: the mutations
# below are structural (break the metadata pointer, expect an unverified
# downgrade) and hold for any valid CLR image regardless of size.
_DE4DOT = (
    Path(__file__).resolve().parents[2]
    / "artifacts" / "tools" / "de4dotEx-3.2.4-net48" / "AssemblyData.dll"
)
_FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
)
MANAGED = _DE4DOT if _DE4DOT.is_file() else _FIXTURE

pytestmark = pytest.mark.skipif(
    not MANAGED.is_file(), reason="no managed assembly available to mutate"
)


def _cli_header_offset(raw: bytes) -> int:
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    optional = e_lfanew + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    directories = optional + (112 if magic == 0x20B else 96)
    cli_rva = struct.unpack_from("<I", raw, directories + 14 * 8)[0]
    coff = e_lfanew + 4
    sections = struct.unpack_from("<H", raw, coff + 2)[0]
    table = coff + 20 + struct.unpack_from("<H", raw, coff + 16)[0]
    for index in range(sections):
        base = table + index * 40
        virtual_address = struct.unpack_from("<I", raw, base + 12)[0]
        raw_size, raw_pointer = struct.unpack_from("<II", raw, base + 16)
        if virtual_address <= cli_rva < virtual_address + max(raw_size, 1):
            return raw_pointer + (cli_rva - virtual_address)
    raise AssertionError("could not locate the CLI header in the fixture")


def _with(offset: int, packed: bytes) -> bytes:
    raw = bytearray(MANAGED.read_bytes())
    raw[offset : offset + len(packed)] = packed
    return bytes(raw)


def _report(path: Path) -> dict[str, object]:
    value = inspect_dotnet(path)
    return dataclasses.asdict(value) if dataclasses.is_dataclass(value) else dict(vars(value))


@pytest.mark.parametrize(
    "field",
    ["metadata rva", "metadata size", "zero metadata size"],
)
def test_unreadable_metadata_is_reported_as_unverified(field: str, tmp_path: Path) -> None:
    """A pointer that leads nowhere must not produce a confident report.

    verified_clr going false is what stops the external .NET tools from running
    against metadata that was never read, and kind drops to clr_directory_hint
    so a caller can see the difference from a real managed image.
    """
    raw = MANAGED.read_bytes()
    cli = _cli_header_offset(raw)
    offset, value = {
        "metadata rva": (cli + 8, 0x7FFFFFFF),
        "metadata size": (cli + 12, 0x7FFFFFFF),
        "zero metadata size": (cli + 12, 0),
    }[field]
    path = tmp_path / "mangled.dll"
    path.write_bytes(_with(offset, struct.pack("<I", value)))

    report = _report(path)

    assert report["verified_clr"] is False, f"{field} still reported a verified CLR"
    assert report["kind"] == "clr_directory_hint"
    assert not report["streams"], "no stream can have been read"
    assert report.get("note"), "and the caller has to be told why"


def test_the_intact_assembly_is_still_recognised(tmp_path: Path) -> None:
    """The downgrade has to mean something."""
    report = _report(MANAGED)

    assert report["is_dotnet"] is True
    assert report["verified_clr"] is True
    assert report["kind"] == "pure_managed"
    assert "#~" in report["streams"]


def test_external_tools_are_refused_on_metadata_that_was_never_read(tmp_path: Path) -> None:
    """require_verified is the gate the unpackers and deobfuscators sit behind."""
    raw = MANAGED.read_bytes()
    path = tmp_path / "mangled.dll"
    path.write_bytes(_with(_cli_header_offset(raw) + 8, struct.pack("<I", 0x7FFFFFFF)))

    with pytest.raises(DotnetInspectError) as caught:
        inspect_dotnet(path, require_verified=True)

    assert "not verified" in str(caught.value)


def test_a_mangled_assembly_is_answered_promptly(tmp_path: Path) -> None:
    """Bounded work on hostile arithmetic, measured at about 12ms per file."""
    raw = MANAGED.read_bytes()
    path = tmp_path / "mangled.dll"
    path.write_bytes(_with(_cli_header_offset(raw) + 8, struct.pack("<I", 0x7FFFFFFF)))

    started = time.perf_counter()
    _report(path)

    assert time.perf_counter() - started < 5.0
