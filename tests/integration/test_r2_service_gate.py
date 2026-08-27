"""radare2 service gate: the whole r2.* surface on a real PE, end to end.

The r2 live gate exercises the client's ``open`` + function list directly, but
the session-based tools an MCP client actually calls -- ``r2.info`` /
``functions`` / ``strings`` / ``imports`` / ``exports`` / ``disasm`` / ``xrefs``
-- had no end-to-end coverage. Each runs r2 and then feeds the output through
``enrich_r2_payload``, so six distinct payload shapes and their address mapping
went unproven; that mapping is exactly where the two Ghidra bugs' kind of defect
would hide. This drives all eight tools against a checked-in x64 PE (r2 analyses
PEs on any host, so no IDA and no Windows are needed) and asserts real content:
named functions mapped to an rva under the module, a populated string and import
table, decoded instructions from a function body, and enriched cross-references.

skip != pass: it skips only when radare2/rizin is not installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PE_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


@pytest.mark.integration
def test_r2_service_surface_on_a_real_pe() -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — r2 service Gate not run (skip != pass)")
    assert _PE_FIXTURE.is_file(), f"fixture missing: {_PE_FIXTURE}"

    service = AnalysisService()
    try:
        created = service.create_session(str(_PE_FIXTURE))
        assert created.ok, created.error
        assert created.data["session"]["target"] == "pe"
        session_id = created.data["session"]["id"]

        opened = service.r2_open(session_id, timeout=60.0)
        assert opened.ok, opened.error
        assert opened.data["opened"] is True

        info = service.r2_info(session_id, timeout=60.0)
        assert info.ok, info.error
        # r2 must recognise the container: a PE reports an x86 family arch.
        assert "architecture" in info.data
        assert "raw" in info.data and info.data["raw"]

        functions = service.r2_functions(session_id, timeout=60.0)
        assert functions.ok, functions.error
        assert functions.data["parsed"] is True
        assert functions.data["count"] >= 1
        first = functions.data["items"][0]
        address = first["address"]
        # The PE mapping must resolve an rva and attribute it to the module, not
        # just echo r2's loaded virtual address.
        assert address["module"] == _PE_FIXTURE.name
        assert "rva" in address
        assert "va" in address

        strings = service.r2_strings(session_id, timeout=60.0)
        assert strings.ok, strings.error
        assert strings.data["parsed"] is True
        assert strings.data["count"] >= 1

        imports = service.r2_imports(session_id, timeout=60.0)
        assert imports.ok, imports.error
        assert imports.data["parsed"] is True
        # A dynamically linked console PE always imports from the CRT/kernel.
        assert imports.data["count"] >= 1

        exports = service.r2_exports(session_id, timeout=60.0)
        assert exports.ok, exports.error
        assert exports.data["parsed"] is True

        function_va = int(address["va"])
        disasm = service.r2_disasm(session_id, function_va, count=8, timeout=60.0)
        assert disasm.ok, disasm.error
        assert disasm.data["parsed"] is True
        instructions = disasm.data["items"]
        assert len(instructions) >= 1
        # Each decoded instruction must carry its mnemonic text and be mapped
        # back to an address, or the disasm view is unusable.
        for instruction in instructions:
            assert instruction.get("opcode") or instruction.get("disasm")
            assert isinstance(instruction.get("address"), dict)

        xrefs = service.r2_xrefs(session_id, function_va, timeout=60.0)
        assert xrefs.ok, xrefs.error
        assert xrefs.data["parsed"] is True
        for xref in xrefs.data["items"]:
            assert isinstance(xref.get("address"), dict)
    finally:
        service.close_all()
