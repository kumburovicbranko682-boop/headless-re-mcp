"""Native (ELF) line, end to end through radare2. skip != pass when r2 missing.

The PE r2 gate proves the Windows path; this proves the native one, which used
to be impossible: an ELF classified as PE and failed create_session with "not a
PE file", so radare2/Ghidra/frida could never get a session over a Linux binary.
Now an ELF opens as a NATIVE session and the whole r2 surface runs against it --
open, info, functions, strings, disasm -- against real analysis output. It needs
radare2 and a system ELF, both present on the Linux CI lane, so it runs there.
"""

from __future__ import annotations

import glob
import re
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.core.service import AnalysisService

_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"
_MACHO_MARKER = "headless-macho-fixture"

# radare2 `iI` prints one mitigation per line, e.g. "nx    true" / "relro  full".
_R2_NX_RE = re.compile(r"^nx\s+(true|false)\s*$", re.MULTILINE)
_R2_RELRO_RE = re.compile(r"^relro\s+(\S+)\s*$", re.MULTILINE)
_R2_CANARY_RE = re.compile(r"^canary\s+(true|false)\s*$", re.MULTILINE)
# For a Mach-O, r2's crypto line reports LC_ENCRYPTION_INFO's cryptid -- the
# FairPlay question the stdlib reader answers as "encrypted".
_R2_CRYPTO_RE = re.compile(r"^crypto\s+(true|false)\s*$", re.MULTILINE)
# r2 spells "no RELRO" as "no"; the stdlib reader spells it "none".
_R2_RELRO = {"full": "full", "partial": "partial", "no": "none"}


def _system_elf() -> Path | None:
    for candidate in ["/bin/ls", "/usr/bin/ls", "/usr/bin/python3", *glob.glob("/lib/*/libc.so*")]:
        path = Path(candidate)
        if path.is_file():
            return path.resolve()
    return None


@pytest.mark.integration
def test_native_elf_opens_and_r2_maps_real_analysis() -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — native gate not run (skip != pass)")
    elf = _system_elf()
    if elf is None:
        pytest.skip("no system ELF available — native gate not run (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(str(elf))
        assert created.ok, created.error
        session = created.data["session"]
        # The classifier and the stdlib reader route the ELF to a NATIVE session
        # with identity facts before r2 ever runs.
        assert session["target"] == "native"
        native = session["metadata"]["native"]
        assert native["format"] == "elf"
        assert native["bits"] in (32, 64)
        assert native["arch"]
        # The stdlib reader also answers the triage questions before r2 runs.
        assert native["linking"] in {"dynamic", "static"}
        assert isinstance(native["pie"], bool)
        # Where execution starts, read pre-tool; every real executable has one.
        assert native["entry"] > 0
        # DT_NEEDED is the stdlib mirror of what r2's imports resolve against: a
        # dynamic ELF names the shared libraries it links, each a real name.
        needed = native.get("needed")
        if native["linking"] == "dynamic" and needed:
            assert all(isinstance(name, str) and name for name in needed)
        session_id = str(session["id"])

        opened = service.r2_open(session_id, timeout=60.0)
        assert opened.ok, opened.error
        assert opened.data["opened"] is True

        info = service.r2_info(session_id, timeout=60.0)
        assert info.ok, info.error
        # PE-specific ImageBase/arch mapping does not apply to an ELF, but the
        # module name always rides along, proving the info parse ran on our file.
        assert info.data["module"] == elf.name

        # Exploit-mitigation posture, cross-checked against r2's own decode. The
        # stdlib reader derives nx from PT_GNU_STACK and relro from PT_GNU_RELRO
        # plus eager-binding tags; r2 reads the same segments independently, so
        # the two must agree tool-free-fact for iI-line -- the mitigation
        # analogue of the entry-point cross-check below.
        iI = R2Client().run(elf, ["iI"], timeout=60.0)["raw"]
        nx_match = _R2_NX_RE.search(iI)
        relro_match = _R2_RELRO_RE.search(iI)
        assert nx_match, iI
        assert native["nx"] is (nx_match.group(1) == "true")
        assert relro_match, iI
        assert native["relro"] == _R2_RELRO[relro_match.group(1)]
        # Canary reads from the dynamic string table's guard symbol. That table
        # exists on any dynamic ELF, so when our binary is dynamic the reader
        # surfaces the fact and it must match r2's own canary line.
        canary_match = _R2_CANARY_RE.search(iI)
        assert canary_match, iI
        if native["linking"] == "dynamic":
            assert native["canary"] is (canary_match.group(1) == "true")

        funcs = service.r2_functions(session_id, timeout=60.0)
        assert funcs.ok, funcs.error
        assert funcs.data["parsed"] is True
        assert funcs.data["count"] >= 1
        rows = cast(list[dict[str, Any]], funcs.data["items"])
        mapped = [r for r in rows if isinstance(r.get("address"), dict) and "va" in r["address"]]
        assert mapped, f"no function carried a va-mapped address: {rows[:2]}"
        target_va = int(mapped[0]["address"]["va"])

        strings = service.r2_strings(session_id, timeout=60.0)
        assert strings.ok, strings.error
        assert strings.data["parsed"] is True
        assert any(
            str(row.get("string") or "").strip()
            for row in cast(list[dict[str, Any]], strings.data["items"])
        ), "string table came back with no readable entries"

        # A dynamically linked ELF pulls symbols from libc, so imports must come
        # back named; exports cover the reverse direction of the symbol table.
        imports = service.r2_imports(session_id, timeout=60.0)
        assert imports.ok, imports.error
        assert imports.data["parsed"] is True
        assert imports.data["count"] >= 1
        assert any(
            str(row.get("name") or "").strip()
            for row in cast(list[dict[str, Any]], imports.data["items"])
        ), "import table came back with no named entries"

        exports = service.r2_exports(session_id, timeout=60.0)
        assert exports.ok, exports.error
        assert exports.data["parsed"] is True
        assert exports.data["count"] >= 1
        assert any(
            str(row.get("name") or "").strip()
            for row in cast(list[dict[str, Any]], exports.data["items"])
        ), "export table came back with no named entries"

        disasm = service.r2_disasm(session_id, target_va, count=4, timeout=60.0)
        assert disasm.ok, disasm.error
        assert disasm.data["parsed"] is True
        ops = cast(list[dict[str, Any]], disasm.data["items"])
        assert ops, "disasm returned no instructions at the function entry"
        assert str(ops[0].get("opcode") or ops[0].get("disasm") or "").strip()
        assert int(ops[0]["address"]["va"]) == target_va

        # xrefs may find no callers for a given address, but the request address
        # must round-trip through the mapping layer unchanged.
        xrefs = service.r2_xrefs(session_id, target_va, timeout=60.0)
        assert xrefs.ok, xrefs.error
        assert int(xrefs.data["address_va"]) == target_va
        assert int(xrefs.data["address"]["va"]) == target_va
    finally:
        service.close_all()


@pytest.mark.integration
def test_native_macho_opens_and_r2_reads_it() -> None:
    """The macOS half of the native line, proven on Linux via a committed fixture.

    ELF is exercised against real system binaries above, but a Linux runner has
    no Mach-O to point at, so that half had only synthetic unit coverage of the
    stdlib reader. This opens a real (hand-built) Mach-O as a NATIVE session and
    drives the format-agnostic r2 surface -- open, info, functions, strings,
    disasm, xrefs -- proving classification, session wiring and r2 all handle the
    Mach-O container end to end. It needs radare2; skip != pass when it is absent.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — native gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    service = AnalysisService()
    try:
        created = service.create_session(str(_MACHO_FIXTURE))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "native"
        native = session["metadata"]["native"]
        assert native["format"] == "macho"
        assert native["bits"] == 64
        assert native["arch"] == "x86-64"
        assert native["type"] == "execute"
        assert native["pie"] is True
        # LC_UUID is the Mach-O build id; the stdlib reader surfaced it pre-tool.
        assert native["uuid"] == "00010203-0405-0607-0809-0a0b0c0d0e0f"
        # LC_LOAD_DYLINKER / LC_LOAD_DYLIB carry the dynamic-linkage identity a
        # real executable always has: dyld as interpreter, libSystem as dylib.
        assert native["interpreter"] == "/usr/lib/dyld"
        assert native["dylibs"] == ["/usr/lib/libSystem.B.dylib"]
        # LC_MAIN's offset mapped through __TEXT: the fixture's known entry.
        assert native["entry"] == 0x100000238
        session_id = str(session["id"])

        # Build posture, cross-checked against r2's own decode of the same
        # image -- the Mach-O counterpart of the ELF gate's nx/relro/canary
        # checks. The stdlib reader derives nx from MH_ALLOW_STACK_EXECUTION,
        # canary from the stack_chk imports in LC_SYMTAB's string table, and
        # encrypted from LC_ENCRYPTION_INFO's cryptid; r2 reads each fact from
        # the same commands independently (its canary line keys on the
        # __stack_chk_fail import the fixture really carries).
        iI = R2Client().run(_MACHO_FIXTURE, ["iI"], timeout=60.0)["raw"]
        nx_match = _R2_NX_RE.search(iI)
        canary_match = _R2_CANARY_RE.search(iI)
        crypto_match = _R2_CRYPTO_RE.search(iI)
        assert nx_match, iI
        assert native["nx"] is (nx_match.group(1) == "true")
        assert canary_match, iI
        assert native["canary"] is (canary_match.group(1) == "true")
        # The positive case, not two false negatives agreeing by accident: the
        # fixture imports the guard, and both readers saw it.
        assert native["canary"] is True
        assert crypto_match, iI
        assert native["encrypted"] is (crypto_match.group(1) == "true")

        opened = service.r2_open(session_id, timeout=60.0)
        assert opened.ok, opened.error
        assert opened.data["opened"] is True

        info = service.r2_info(session_id, timeout=60.0)
        assert info.ok, info.error
        assert info.data["module"] == _MACHO_FIXTURE.name

        funcs = service.r2_functions(session_id, timeout=60.0)
        assert funcs.ok, funcs.error
        assert funcs.data["parsed"] is True
        assert funcs.data["count"] >= 1
        rows = cast(list[dict[str, Any]], funcs.data["items"])
        mapped = [r for r in rows if isinstance(r.get("address"), dict) and "va" in r["address"]]
        assert mapped, f"no function carried a va-mapped address: {rows[:2]}"
        target_va = int(mapped[0]["address"]["va"])
        # r2's analysis found a function exactly at the tool-free entry point,
        # cross-validating the stdlib LC_MAIN mapping against real analysis.
        assert native["entry"] in {int(r["address"]["va"]) for r in mapped}

        strings = service.r2_strings(session_id, timeout=60.0)
        assert strings.ok, strings.error
        assert strings.data["parsed"] is True
        assert any(
            _MACHO_MARKER in str(row.get("string") or "")
            for row in cast(list[dict[str, Any]], strings.data["items"])
        ), "the fixture marker string did not come back from r2"

        disasm = service.r2_disasm(session_id, target_va, count=4, timeout=60.0)
        assert disasm.ok, disasm.error
        assert disasm.data["parsed"] is True
        ops = cast(list[dict[str, Any]], disasm.data["items"])
        assert ops, "disasm returned no instructions at the function entry"
        assert str(ops[0].get("opcode") or ops[0].get("disasm") or "").strip()
        assert int(ops[0]["address"]["va"]) == target_va

        xrefs = service.r2_xrefs(session_id, target_va, timeout=60.0)
        assert xrefs.ok, xrefs.error
        assert int(xrefs.data["address_va"]) == target_va
    finally:
        service.close_all()
