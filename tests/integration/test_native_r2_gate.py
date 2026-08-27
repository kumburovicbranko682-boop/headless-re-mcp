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
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.core.service import AnalysisService


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
        session_id = str(session["id"])

        opened = service.r2_open(session_id, timeout=60.0)
        assert opened.ok, opened.error
        assert opened.data["opened"] is True

        info = service.r2_info(session_id, timeout=60.0)
        assert info.ok, info.error
        # PE-specific ImageBase/arch mapping does not apply to an ELF, but the
        # module name always rides along, proving the info parse ran on our file.
        assert info.data["module"] == elf.name

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
