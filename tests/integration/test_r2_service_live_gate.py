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
