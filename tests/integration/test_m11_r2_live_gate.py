"""M11 r2 live gate: address mapping, disassembly, xrefs. skip≠pass when r2 missing."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _r2_fixture() -> Path | None:
    """A PE for r2 to map, preferring the Windows-built gate fixture.

    r2 is a portable static backend, so it analyses a PE the same way on
    Linux as on Windows. The primary fixture is generated on the Windows CI
    and is absent from a plain checkout; falling back to a committed PE keeps
    this gate a real pass on Linux instead of an always-skip that only ever
    exercised the backend on one platform.
    """
    primary = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if primary.is_file():
        return primary
    committed = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
    return committed if committed.is_file() else None


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _r2_fixture()
    if fixture is None:
        pytest.skip("no PE fixture available for r2 — live Gate not run (skip≠pass)")

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

    # Past function listing into the analysis core. disasm (pdj) at a real
    # function entry runs the parameterized command past the whitelist, r2
    # returns instructions, and the request address round-trips through the
    # address mapping -- the surface a caller actually reverse-engineers with.
    va = item["address"]["va"]
    assert isinstance(va, int)
    disasm = client.disasm(fixture, va, count=8, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("count", 0) >= 1
    assert disasm.get("address_va") == va
    assert disasm["address"]["va"] == va
    instruction = disasm["items"][0]
    assert "opcode" in instruction or "disasm" in instruction

    # xrefs (axtj) exercises the second parameterized whitelist command; the
    # reference count is data-dependent (the first listed function is often the
    # entry point, which nothing references), so only its shape and the
    # round-tripped request address are asserted -- axtj answers [] for a
    # referent-free address, which must still read back as parsed with count 0.
    xrefs = client.xrefs(fixture, va, timeout=60.0)
    assert xrefs.get("parsed") is True
    assert isinstance(xrefs.get("count"), int)
    assert xrefs.get("address_va") == va
