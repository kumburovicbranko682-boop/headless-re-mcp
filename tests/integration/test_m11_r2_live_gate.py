"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

radare2 is a *portable* backend -- its whole point is that it analyses PE (and
other) targets on any host, unlike the Windows-only idalib/x64dbg chain. The
gate therefore prefers the Windows-built fixture when present but falls back to
a PE that is committed in-tree, so it actually runs on a Linux CI runner instead
of skipping and letting the cross-platform claim go unproven.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
# Built only on the Windows CI job; absent in a fresh checkout elsewhere.
_BUILT_FIXTURE = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
# Committed to the repo (it backs the UPX gate), so it exists in every checkout
# and gives the portable backend a target r2 can open on any platform.
_COMMITTED_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _gate_fixture() -> Path:
    if _BUILT_FIXTURE.is_file():
        return _BUILT_FIXTURE
    if _COMMITTED_FIXTURE.is_file():
        return _COMMITTED_FIXTURE
    pytest.skip(f"no r2 fixture available: {_BUILT_FIXTURE} nor {_COMMITTED_FIXTURE}")


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()

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
def test_m11_r2_live_disasm_maps_every_instruction() -> None:
    """Disassembly must carry the same address contract as the function list.

    A caller that pivots from a function to its instructions relies on each op
    being mapped back to a module + RVA; losing that on the portable backend
    would silently break cross-tool address handoff for non-Windows targets.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    entry = int(funcs["items"][0]["offset"])

    dis = client.disasm(fixture, entry, count=8, timeout=60.0)
    assert dis.get("parsed") is True
    ops = dis.get("items") or []
    assert ops, "disassembly returned no instructions"
    first = ops[0]
    assert isinstance(first.get("address"), dict)
    assert "va" in first["address"] or "rva" in first["address"]

    # xrefs at a real function must parse into the same enriched envelope.
    xref = client.xrefs(fixture, entry, timeout=60.0)
    assert xref.get("parsed") is True
