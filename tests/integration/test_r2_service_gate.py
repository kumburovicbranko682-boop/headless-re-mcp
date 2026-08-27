"""radare2 service-surface gate: the whole r2.* read path on a real PE.

The existing r2 live gate (``test_m11_r2_live_gate.py``) drives the low-level
``R2Client`` directly, against one built fixture that is not committed, and
asserts only that function addresses map. The service methods an agent actually
calls -- ``r2.open`` / ``r2.info`` / ``r2.functions`` / ``r2.strings`` /
``r2.imports`` / ``r2.exports`` / ``r2.disasm`` / ``r2.xrefs`` on
``AnalysisService`` -- had no end-to-end test at all: nothing created a session
and read a binary back through the service envelope.

This gate does exactly that against a committed, non-packed x64 PE
(``fixtures/upx/console_fixture-x64.pre-upx.exe``, the pre-UPX build of the
console fixture whose source is ``fixtures/native/console_fixture.c``). Every
assertion checks *recovered content* tied to that source, not a non-empty
envelope: the import table carries ``LoadLibraryW`` / ``GetProcAddress`` /
``CreateThread``, the string table carries the literal ``--debug-wait``, an
executable exports nothing, functions come back with full PE address mapping
(module + rva + va + arch), ``main`` disassembles to real instructions, and its
xrefs resolve to named imports and strings. radare2/rizin absent skips with
"skip != pass"; the closed-session (``invalid_request``) and unconfigured
(``capability_unavailable``) guards need no r2 and always run.

Verified against radare2 5.5.0 on Linux analysing a Windows PE.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PE_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _r2_available() -> bool:
    return R2Client().available


def _function_named(items: list[dict], name: str) -> dict | None:
    for item in items:
        if item.get("name") == name:
            return item
    return None


@pytest.mark.integration
def test_r2_service_recovers_pe_analysis() -> None:
    if not _r2_available():
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

        # `i` is plain text, not JSON, so it does not "parse" into items -- but
        # it must still identify the container as a PE.
        info = service.r2_info(session_id, timeout=60.0)
        assert info.ok, info.error
        assert "pe" in info.data["raw"].lower()

        functions = service.r2_functions(session_id, timeout=60.0)
        assert functions.ok, functions.error
        assert functions.data["parsed"] is True
        assert functions.data["count"] >= 1
        items = functions.data["items"]
        main = _function_named(items, "main")
        assert main is not None, [i.get("name") for i in items]
        # Every recovered function carries the unified PE Address mapping: the
        # module name, the file-relative rva and the absolute va, plus arch.
        address = main["address"]
        assert address["module"] == _PE_FIXTURE.name
        assert isinstance(address["rva"], int)
        assert isinstance(address["va"], int)
        assert address["architecture"] == "x64"

        strings = service.r2_strings(session_id, timeout=60.0)
        assert strings.ok, strings.error
        assert strings.data["parsed"] is True
        recovered = {item.get("string") for item in strings.data["items"]}
        # Literals straight out of console_fixture.c, so this proves the real
        # string table was read, not merely that some list came back.
        assert "--debug-wait" in recovered, sorted(s for s in recovered if s)[:20]
        assert "event_fixture.dll" in recovered

        imports = service.r2_imports(session_id, timeout=60.0)
        assert imports.ok, imports.error
        assert imports.data["parsed"] is True
        import_names = {item.get("name") for item in imports.data["items"]}
        assert {"LoadLibraryW", "GetProcAddress", "CreateThread"} <= import_names, import_names

        exports = service.r2_exports(session_id, timeout=60.0)
        assert exports.ok, exports.error
        assert exports.data["parsed"] is True
        # A console executable exports nothing; the honest recovered answer is an
        # empty list, and getting it proves the export path runs and parses.
        assert exports.data["count"] == 0

        main_va = main["address"]["va"]
        disasm = service.r2_disasm(session_id, main_va, count=8, timeout=60.0)
        assert disasm.ok, disasm.error
        assert disasm.data["parsed"] is True
        assert disasm.data["count"] == 8
        first_op = disasm.data["items"][0]
        assert first_op.get("disasm") or first_op.get("opcode"), first_op

        xrefs = service.r2_xrefs(session_id, main_va, timeout=60.0)
        assert xrefs.ok, xrefs.error
        assert xrefs.data["parsed"] is True
        assert xrefs.data["count"] >= 1
        xref_items = xrefs.data["items"]
        # Each xref maps its endpoint like a function does...
        assert all("address" in item for item in xref_items)
        # ...and at least one resolves to a named import or string, which is what
        # makes the xref useful rather than a bare address.
        refnames = " ".join(str(item.get("refname", "")) for item in xref_items)
        assert "KERNEL32" in refnames or "str." in refnames, refnames

        # A negative address is a clean invalid_params, never a crash.
        bad = service.r2_disasm(session_id, -1, timeout=60.0)
        assert not bad.ok
        assert bad.error is not None
        assert bad.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.integration
def test_r2_service_refuses_a_closed_session() -> None:
    """State is checked before the backend, so this runs without r2."""
    assert _PE_FIXTURE.is_file(), f"fixture missing: {_PE_FIXTURE}"
    service = AnalysisService()
    try:
        created = service.create_session(str(_PE_FIXTURE))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        service.close_session(session_id)

        result = service.r2_functions(session_id, timeout=60.0)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


@pytest.mark.integration
def test_r2_service_degrades_when_r2_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A machine without radare2 gets capability_unavailable, not a stack trace."""
    assert _PE_FIXTURE.is_file(), f"fixture missing: {_PE_FIXTURE}"
    # Force the "not installed" verdict even on a box that has it, so this guard
    # runs on every machine rather than only on one without r2.
    monkeypatch.setattr(
        "headless_re_mcp.backends.r2.client.R2Client.available",
        property(lambda self: False),
    )
    service = AnalysisService()
    try:
        created = service.create_session(str(_PE_FIXTURE))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        result = service.r2_functions(session_id, timeout=60.0)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "capability_unavailable"
    finally:
        service.close_all()
