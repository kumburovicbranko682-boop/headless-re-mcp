"""r2 portable backend proven through AnalysisService, not just the client.

test_m11_r2_live_gate.py drives R2Client directly. This gate exercises the same
radare2 analysis through the real entry point an agent uses -- create a session
on a PE, then r2.functions / r2.disasm / r2.xrefs off the service -- so the
wiring (settings discovery, session binary, address mapping, structured error
envelope) is proven on Linux too, not only the raw client. skip != pass when r2
is absent; the committed in-tree PE keeps it runnable on any host.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BUILT_FIXTURE = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
_COMMITTED_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _gate_fixture() -> Path:
    if _BUILT_FIXTURE.is_file():
        return _BUILT_FIXTURE
    if _COMMITTED_FIXTURE.is_file():
        return _COMMITTED_FIXTURE
    pytest.skip(f"no r2 fixture available: {_BUILT_FIXTURE} nor {_COMMITTED_FIXTURE}")


def _assert_mapped(address: object) -> None:
    assert isinstance(address, dict), address
    assert "va" in address or "rva" in address, address


@pytest.mark.integration
def test_r2_service_functions_disasm_xrefs_end_to_end() -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        opened = service.r2_open(session_id, timeout=60.0)
        assert opened.ok, opened.error

        funcs = service.r2_functions(session_id, timeout=60.0)
        assert funcs.ok and funcs.data is not None, funcs.error
        assert funcs.data.get("parsed") is True
        assert funcs.data.get("count", 0) >= 1
        assert isinstance(funcs.data.get("architecture"), str) and funcs.data["architecture"]
        items = funcs.data["items"]
        # Every function the service hands back must be address-mapped, since an
        # agent pivots from this list straight into disasm/xrefs by address.
        for item in items:
            _assert_mapped(item.get("address"))

        entry = int(items[0]["offset"])
        dis = service.r2_disasm(session_id, entry, count=8, timeout=60.0)
        assert dis.ok and dis.data is not None, dis.error
        assert dis.data.get("parsed") is True
        ops = dis.data.get("items") or []
        assert ops, "disassembly returned no instructions"
        for op in ops:
            _assert_mapped(op.get("address"))
            assert op.get("opcode"), op
            assert op.get("bytes"), op

        xref = service.r2_xrefs(session_id, entry, timeout=60.0)
        assert xref.ok and xref.data is not None, xref.error
        assert xref.data.get("parsed") is True
        assert isinstance(xref.data.get("items"), list)
    finally:
        service.close_session(session_id)


def _xref_touches(item: dict, va: int) -> bool:
    """True when an xref row names ``va`` as its origin or its target.

    Mirrors the endpoint keys the service filters on (``from`` origin; ``to`` or,
    on r2 5.x, ``addr`` target), reading either the raw int or the mapped VA.
    """
    for key in ("from", "to", "addr"):
        value = item.get(key)
        if isinstance(value, int) and value == va:
            return True
    for key in ("from_address", "to_address", "address"):
        mapped = item.get(key)
        if isinstance(mapped, dict) and mapped.get("va") == va:
            return True
    return False


@pytest.mark.integration
def test_r2_service_xrefs_are_scoped_to_the_requested_address() -> None:
    """xrefs must answer for the address asked, not dump the whole DB.

    radare2's ``axj`` lists every cross reference and ignores the ``@`` seek, so
    before the fix ``r2.xrefs`` returned an identical program-wide list for 0x0,
    a real function, and a bogus VA alike -- the address argument did nothing.
    This proves the query is now scoped: a VA far outside the image resolves to
    zero references, at least one real function resolves to some, and every row
    that comes back actually touches the address that was requested.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        assert service.r2_open(session_id, timeout=60.0).ok
        # Imported call targets are the reliable, fixture-neutral referenced
        # addresses: any PE that imports and calls an API has code pointing at
        # its import slots. (Function *entry* addresses are not themselves xref
        # targets here -- the calls land on the import thunks, not the entries.)
        imports = service.r2_imports(session_id, timeout=60.0)
        assert imports.ok and imports.data is not None, imports.error
        targets: list[int] = []
        for item in imports.data["items"]:
            mapped = item.get("address")
            if isinstance(mapped, dict) and isinstance(mapped.get("va"), int):
                targets.append(mapped["va"])
        assert targets, "no import addresses to pivot xrefs from"

        # A VA well past the image can reference nothing. Before the fix this
        # still returned the full axj dump; now it must be a clean empty list.
        bogus = service.r2_xrefs(session_id, 0xFFFFFFFFFFFF, timeout=60.0)
        assert bogus.ok and bogus.data is not None, bogus.error
        assert bogus.data["parsed"] is True
        assert bogus.data["count"] == 0
        assert bogus.data["items"] == []

        # Some referenced address must resolve to at least one xref, and every
        # row returned for it must actually involve that address -- otherwise the
        # "filter" is just passing the whole database through unchanged.
        found_with_refs = False
        for va in targets:
            result = service.r2_xrefs(session_id, va, timeout=60.0)
            assert result.ok and result.data is not None, result.error
            assert result.data["parsed"] is True
            request_va = result.data["address_va"]
            for row in result.data["items"]:
                assert _xref_touches(row, request_va), (va, row)
            if result.data["count"] >= 1:
                found_with_refs = True
        assert found_with_refs, "expected at least one import with resolvable xrefs"
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_xrefs_at_a_non_code_address_stay_empty() -> None:
    """A bad target must fail soft: a clean empty xref list, no internal_error.

    Agents point xrefs at addresses that turn out to be data, padding, or below
    the image base. 0x0 references nothing, so the envelope must come back parsed
    with zero items -- not an exception, not the whole-program dump the old axj
    behaviour produced, and not an internal_error.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        assert service.r2_open(session_id, timeout=60.0).ok
        xref = service.r2_xrefs(session_id, 0x0, timeout=60.0)
        assert xref.ok and xref.data is not None, xref.error
        assert xref.data["parsed"] is True
        assert xref.data["count"] == 0
        assert xref.data["items"] == []
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_refuses_a_closed_session_without_leaking() -> None:
    """A closed session must fail closed with a structured error, not a crash.

    The service guards state before touching r2; losing that guard would leak an
    internal exception (or worse, run r2 against a torn-down session) instead of
    the clean refusal an agent can branch on.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    service.close_session(session_id)

    clean_codes = {"invalid_request", "invalid_state", "session_not_found"}
    for call in (
        lambda: service.r2_functions(session_id, timeout=30.0),
        lambda: service.r2_disasm(session_id, 0x1000, count=4, timeout=30.0),
        lambda: service.r2_xrefs(session_id, 0x1000, timeout=30.0),
    ):
        result = call()
        assert not result.ok and result.error is not None
        assert result.error.code != "internal_error", result.error
        assert result.error.code in clean_codes, result.error
