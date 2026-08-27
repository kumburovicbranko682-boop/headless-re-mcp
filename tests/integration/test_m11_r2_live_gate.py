"""M11 r2 live gate: real analysis mapped to addresses. skip≠pass when r2 missing.

radare2 is a cross-platform backend wired into the Linux CI lane, so this gate
must actually run there. The build-artifact fixture is not committed, so it
falls back to a committed PE so a machine with r2 installed exercises the whole
r2 tool surface -- open, info, functions, strings, imports, disasm, xrefs --
against real analysis output rather than skipping for want of a target.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Prefer the freshly built fixture when a dev machine has it; otherwise the
# committed PE keeps the gate honest on CI (both are x64 PEs, so the address
# mapping assertions below hold for either).
_FIXTURE_CANDIDATES = (
    _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe",
    _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe",
)


def _fixture() -> Path:
    for candidate in _FIXTURE_CANDIDATES:
        if candidate.is_file():
            return candidate
    pytest.fail(f"no r2 fixture is committed at any of {[str(c) for c in _FIXTURE_CANDIDATES]}")


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _fixture()

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    item = funcs["items"][0]
    assert isinstance(item.get("address"), dict)
    assert "va" in item["address"] or "rva" in item["address"]
    if "rva" in item["address"]:
        assert item["address"].get("module") == fixture.name


@pytest.mark.integration
def test_m11_r2_service_surface_maps_real_analysis() -> None:
    """Every r2 tool must return the target's real analysis, address-mapped.

    Going through AnalysisService (not just R2Client) proves the wired tool
    surface end to end: a PE opens, its header is read, functions/strings/
    imports come back with content, a function disassembles to real opcodes,
    and both disasm and xrefs carry unified rva/va/module addresses.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _fixture()
    service = AnalysisService()
    try:
        created = service.create_session(str(fixture))
        assert created.ok, created.error
        session_id = str(created.data["session"]["id"])

        opened = service.r2_open(session_id, timeout=60.0)
        assert opened.ok, opened.error
        assert opened.data["opened"] is True

        info = service.r2_info(session_id, timeout=60.0)
        assert info.ok, info.error
        # The PE header parse feeds the mapping layer: a real ImageBase and a
        # decoded architecture are what let every later address carry an rva.
        assert int(info.data["image_base"]) > 0
        assert info.data["architecture"] == "x64"
        assert info.data["module"] == fixture.name

        funcs = service.r2_functions(session_id, timeout=60.0)
        assert funcs.ok, funcs.error
        assert funcs.data["parsed"] is True
        assert funcs.data["count"] >= 1
        rows = cast(list[dict[str, Any]], funcs.data["items"])
        mapped = [r for r in rows if isinstance(r.get("address"), dict) and "va" in r["address"]]
        assert mapped, f"no function carried a va-mapped address: {rows[:2]}"
        target = mapped[0]["address"]
        # A PE resolves an ImageBase, so functions must carry module-relative
        # addresses, not just absolute ones.
        assert target.get("rva") is not None
        assert target.get("module") == fixture.name
        target_va = int(target["va"])

        strings = service.r2_strings(session_id, timeout=60.0)
        assert strings.ok, strings.error
        assert strings.data["parsed"] is True
        assert strings.data["count"] >= 1
        assert any(
            str(row.get("string") or "").strip()
            for row in cast(list[dict[str, Any]], strings.data["items"])
        ), "string table came back with no readable entries"

        imports = service.r2_imports(session_id, timeout=60.0)
        assert imports.ok, imports.error
        assert imports.data["parsed"] is True
        assert imports.data["count"] >= 1
        assert any(
            str(row.get("name") or "").strip()
            for row in cast(list[dict[str, Any]], imports.data["items"])
        ), "import table came back with no named entries"

        disasm = service.r2_disasm(session_id, target_va, count=8, timeout=60.0)
        assert disasm.ok, disasm.error
        assert disasm.data["parsed"] is True
        ops = cast(list[dict[str, Any]], disasm.data["items"])
        assert ops, "disasm returned no instructions at the function entry"
        first = ops[0]
        assert str(first.get("opcode") or first.get("disasm") or "").strip()
        # The first instruction must sit exactly at the address we asked for,
        # with the same unified mapping the function listing produced.
        assert isinstance(first.get("address"), dict)
        assert int(first["address"]["va"]) == target_va
        assert first["address"].get("module") == fixture.name

        xrefs = service.r2_xrefs(session_id, target_va, timeout=60.0)
        assert xrefs.ok, xrefs.error
        # xrefs may find no callers for a given address, but the request address
        # must always round-trip through the mapping layer unchanged.
        assert int(xrefs.data["address_va"]) == target_va
        assert int(xrefs.data["address"]["va"]) == target_va
    finally:
        service.close_all()
