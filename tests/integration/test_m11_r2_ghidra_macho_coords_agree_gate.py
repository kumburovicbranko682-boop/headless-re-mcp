"""M11 cross-engine gate: r2 and Ghidra agree on a Mach-O coordinate frame.

Mach-O became a first-class session target, and both backends learned to derive
its load base and architecture from the header -- r2 via ``enrich_r2_payload``,
Ghidra via ``enrich_ghidra_payload``, both sharing ``preferred_base``. Every
existing agree/e2e gate is ELF or PE, so nothing exercised that convergence on a
real Mach-O through the running engines. This gate closes that gap: for a thin
x86_64 image (base 0x100000000) and a thin arm64 image (base 0x140000000), one
Mach-O session driven through the AnalysisService must have both engines

* accept the Mach-O and return a well-formed payload (no loader error), and
* report the identical top-level frame -- module, image_base, architecture --
  matching the base the header declares and the architecture the session was
  classified with.

The fixtures are hand-built Mach-O headers (no toolchain can emit Mach-O here),
which carry no code, so this pins the coordinate *frame* rather than recovered
functions; the ELF coords gate already pins item-level agreement where a
compiler is available. skip != pass when radare2/rizin or Ghidra is missing.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_LE64 = b"\xcf\xfa\xed\xfe"
# (cputype, cpusubtype, session architecture label, __TEXT base) per fixture.
_X64 = (0x01000007, 3, "x64", 0x100000000)
_ARM64 = (0x0100000C, 0, "arm64", 0x140000000)


def _segment(name: str, vmaddr: int, fileoff: int, filesize: int) -> bytes:
    body = struct.pack("<II", 0x19, 72) + name.encode().ljust(16, b"\x00")
    body += struct.pack("<QQQQ", vmaddr, 0x1000, fileoff, filesize)
    body += struct.pack("<IIII", 0, 5, 0, 0)
    return body


def _write_thin_macho(path: Path, *, cputype: int, cpusubtype: int, text_base: int) -> Path:
    """A minimal thin 64-bit Mach-O: __PAGEZERO + a header-mapping __TEXT.

    Real enough that both radare2 and Ghidra's Mach-O loader accept it and read
    the load base off __TEXT's vmaddr; it carries no code section, so neither
    engine recovers functions -- the frame is what this fixture pins.
    """
    cmds = _segment("__PAGEZERO", 0, 0, 0) + _segment("__TEXT", text_base, 0, 0x1000)
    header = _LE64 + struct.pack("<IIIII", cputype, cpusubtype, 2, 2, len(cmds))
    header += struct.pack("<II", 0, 0)  # flags + reserved
    path.write_bytes((header + cmds).ljust(0x1000, b"\x00"))
    return path


def _frame(payload: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (payload.get("module"), payload.get("image_base"), payload.get("architecture"))


@pytest.mark.integration
@pytest.mark.parametrize(
    ("cputype", "cpusubtype", "arch", "text_base"),
    [_X64, _ARM64],
    ids=["x86_64", "arm64"],
)
def test_m11_r2_and_ghidra_agree_on_macho_frame(
    tmp_path: Path, cputype: int, cpusubtype: int, arch: str, text_base: int
) -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — Mach-O coords Gate not run (skip != pass)")
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home or not GhidraClient(home=Path(home)).available:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")

    binary = _write_thin_macho(
        tmp_path / f"{arch}.macho",
        cputype=cputype,
        cpusubtype=cpusubtype,
        text_base=text_base,
    )

    service = AnalysisService(Settings.load())
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    # The regression this line guards: a Mach-O now creates a session and is
    # classified with the architecture its header names, not routed to the PE
    # machine probe that used to reject it.
    assert session["target"] == "macho", session
    assert session["architecture"] == arch, session
    sid = str(session["id"])

    # r2 accepts the Mach-O and reports the header-derived frame.
    r2_funcs = service.r2_functions(sid, timeout=60.0)
    assert r2_funcs.ok and r2_funcs.data is not None, r2_funcs.error
    assert r2_funcs.data.get("parsed") is True, r2_funcs.data
    assert isinstance(r2_funcs.data.get("items"), list), r2_funcs.data

    # Ghidra's Mach-O loader imports the same file through the same session and
    # returns a well-formed functions export (no loader error).
    gh_funcs = service.ghidra_functions(sid, limit=64, timeout=300.0)
    assert gh_funcs.ok and gh_funcs.data is not None, gh_funcs.error
    assert gh_funcs.data.get("mode") == "functions", gh_funcs.data
    assert isinstance(gh_funcs.data.get("items"), list), gh_funcs.data

    # The contract: one coordinate frame from both engines, equal to the base
    # the header declares and the architecture the session carries.
    expected = (binary.name, text_base, arch)
    assert _frame(r2_funcs.data) == expected, r2_funcs.data
    assert _frame(gh_funcs.data) == expected, gh_funcs.data
    assert _frame(r2_funcs.data) == _frame(gh_funcs.data)
