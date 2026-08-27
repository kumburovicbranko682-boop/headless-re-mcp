"""radare2 inspection gate: the r2.* surface end to end on Linux.

The one existing r2 gate (test_m11_r2_live_gate.py) drives R2Client directly
against a Windows-built PE under artifacts/fixtures-x64/, which is not present on
a Linux checkout, and only runs one command (aflj). So the radare2 *service*
surface -- r2.open / info / functions / strings / imports / exports / disasm /
xrefs, with the session-state guards, backend recording and address mapping that
live in service_ext.py -- had no coverage that actually executes on Linux.

radare2 analyses a PE from any platform, so this gate points AnalysisService at a
committed PE fixture and asserts the whole surface returns real, mapped content
(rva/va/module resolved from the PE's image base). A second test reads a native
Linux ELF straight through R2Client to cover the va-only mapping branch (no image
base) and prove r2 works on a Linux-native target too.

Everything skips with an explicit "skip != pass" when radare2/rizin is absent;
verified against radare2 6.2.0 on Linux.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PE_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
_ELF_FIXTURE = _PROJECT_ROOT / "fixtures" / "native" / "r2_elf_fixture"
_ELF_MARKER = "headless-re radare2 gate fixture"
# A few of the imports rabin2 reports for the committed console fixture; the gate
# only needs one to prove the import table parsed into named entries.
_KNOWN_PE_IMPORTS = frozenset(
    {
        "CloseHandle",
        "WaitForSingleObject",
        "Sleep",
        "CreateThread",
        "VirtualAlloc",
        "VirtualFree",
        "GetModuleFileNameW",
    }
)


def _r2_available() -> bool:
    return R2Client().available


def _skip_without_r2() -> None:
    if not _r2_available():
        pytest.skip("radare2/rizin not installed — r2 Gate not run (skip != pass)")


@pytest.mark.integration
def test_r2_service_surface_maps_a_real_pe() -> None:
    """Every read-only r2 tool answers with parsed, address-mapped content.

    The PE carries an image base, so functions, disassembly and the request
    address all resolve to module + rva + va, not just a raw offset.
    """
    _skip_without_r2()
    assert _PE_FIXTURE.is_file(), f"fixture missing: {_PE_FIXTURE}"

    service = AnalysisService()
    try:
        created = service.create_session(str(_PE_FIXTURE))
        assert created.ok, created.error
        assert created.data["session"]["target"] == "pe"
        session_id = created.data["session"]["id"]

        opened = service.r2_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["opened"] is True

        info = service.r2_info(session_id)
        assert info.ok, info.error
        assert isinstance(info.data["image_base"], int) and info.data["image_base"] > 0
        assert info.data["architecture"] == "x64"
        assert info.data["raw"].strip() != ""

        functions = service.r2_functions(session_id)
        assert functions.ok, functions.error
        assert functions.data["parsed"] is True
        assert functions.data["count"] >= 1
        named = [item for item in functions.data["items"] if item.get("name")]
        assert named, "no function carried a name"
        address = named[0]["address"]
        assert address["module"] == _PE_FIXTURE.name
        assert isinstance(address["rva"], int)
        assert isinstance(address["va"], int)
        assert address["architecture"] == "x64"

        strings = service.r2_strings(session_id)
        assert strings.ok, strings.error
        assert strings.data["count"] >= 1
        assert any("string" in item for item in strings.data["items"])

        imports = service.r2_imports(session_id)
        assert imports.ok, imports.error
        assert imports.data["count"] >= 1
        names = {item.get("name") for item in imports.data["items"]}
        assert names & _KNOWN_PE_IMPORTS, f"no known import found in {sorted(names)[:10]}"

        exports = service.r2_exports(session_id)
        assert exports.ok, exports.error
        assert exports.data["parsed"] is True

        # The service records the backend and stamps the timeline for each call.
        timeline = service.timeline_list(session_id)
        assert timeline.ok, timeline.error
        events = {entry.get("event") for entry in timeline.data["events"]}
        assert "r2.open" in events
        assert "r2.request" in events
    finally:
        service.close_all()


@pytest.mark.integration
def test_r2_disasm_and_xrefs_carry_mapped_addresses() -> None:
    """disasm and xrefs preserve the requested address as a mapped Address."""
    _skip_without_r2()
    assert _PE_FIXTURE.is_file(), f"fixture missing: {_PE_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = service.create_session(str(_PE_FIXTURE)).data["session"]["id"]
        functions = service.r2_functions(session_id)
        assert functions.ok, functions.error
        va = functions.data["items"][0]["addr"]
        assert isinstance(va, int)

        disasm = service.r2_disasm(session_id, va, count=8)
        assert disasm.ok, disasm.error
        assert disasm.data["parsed"] is True
        assert disasm.data["count"] == 8
        assert disasm.data["address_va"] == va
        assert disasm.data["address"]["va"] == va
        assert disasm.data["address"]["module"] == _PE_FIXTURE.name
        assert isinstance(disasm.data["address"]["rva"], int)
        first = disasm.data["items"][0]
        assert isinstance(first.get("disasm"), str) and first["disasm"]
        assert "address" in first

        xrefs = service.r2_xrefs(session_id, va)
        assert xrefs.ok, xrefs.error
        assert xrefs.data["address"]["va"] == va
        assert "parsed" in xrefs.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_r2_disasm_rejects_out_of_range_input() -> None:
    """A negative address or an out-of-range count is invalid_params."""
    _skip_without_r2()
    assert _PE_FIXTURE.is_file(), f"fixture missing: {_PE_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = service.create_session(str(_PE_FIXTURE)).data["session"]["id"]

        negative = service.r2_disasm(session_id, -1)
        assert not negative.ok
        assert negative.error is not None
        assert negative.error.code == "invalid_params"

        zero_count = service.r2_disasm(session_id, 0x1000, count=0)
        assert not zero_count.ok
        assert zero_count.error is not None
        assert zero_count.error.code == "invalid_params"

        too_many = service.r2_disasm(session_id, 0x1000, count=9999)
        assert not too_many.ok
        assert too_many.error is not None
        assert too_many.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.integration
def test_r2_tools_refuse_a_closed_session() -> None:
    """A closed session cannot serve r2 reads: the guard fires before the CLI."""
    _skip_without_r2()
    assert _PE_FIXTURE.is_file(), f"fixture missing: {_PE_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = service.create_session(str(_PE_FIXTURE)).data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        refused = service.r2_functions(session_id)
        assert not refused.ok
        assert refused.error is not None
        assert refused.error.code == "invalid_request"
    finally:
        service.close_all()


@pytest.mark.integration
def test_r2_reads_a_native_linux_elf() -> None:
    """r2 analyses a Linux ELF, and the mapping degrades to va-only correctly.

    An ELF has no PE image base, so enrich_r2_payload cannot compute an rva:
    each item's address must carry va alone, with no module or rva bolted on.
    """
    _skip_without_r2()
    assert _ELF_FIXTURE.is_file(), f"fixture missing: {_ELF_FIXTURE}"

    client = R2Client()
    functions = client.run(_ELF_FIXTURE, ["aa", "aflj"])
    assert functions["parsed"] is True
    assert functions["count"] >= 1
    # No PE image base was found, so the enrichment leaves the key off entirely.
    assert "image_base" not in functions
    names = [str(item.get("name", "")) for item in functions["items"]]
    assert any("main" in name for name in names), names
    assert any("compute_checksum" in name for name in names), names
    mapped = next(item for item in functions["items"] if item.get("address"))
    assert "va" in mapped["address"]
    assert "rva" not in mapped["address"]
    assert "module" not in mapped["address"]

    strings = client.run(_ELF_FIXTURE, ["izj"])
    assert strings["parsed"] is True
    assert any(_ELF_MARKER in str(item.get("string", "")) for item in strings["items"])

    imports = client.run(_ELF_FIXTURE, ["iij"])
    assert imports["parsed"] is True
    import_names = {str(item.get("name", "")) for item in imports["items"]}
    assert import_names & {"printf", "puts"}, sorted(import_names)
