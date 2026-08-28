"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if not fixture.is_file():
        pytest.skip(f"fixture missing: {fixture}")

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
def test_m11_r2_live_xrefs_are_scoped_to_the_asked_address() -> None:
    """Every returned xref must actually touch the asked address.

    Regression gate for the inert-address bug: xrefs used to run ``axj @
    addr``, and axj ignores the seek -- measured on this fixture, every
    address (including 0) got the same 1044-entry global dump back. The
    scoped axtj/axfj queries return only rows whose to/from side is the
    asked address, and an address with no code (the MZ header) gets none.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if not fixture.is_file():
        pytest.skip(f"fixture missing: {fixture}")

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    referenced = None
    for candidate in funcs.get("items", [])[:12]:
        address = candidate.get("address") or {}
        va = address.get("va")
        if type(va) is not int:
            continue
        result = client.xrefs(fixture, va, timeout=60.0)
        assert result.get("parsed") is True
        for entry in result.get("items", []):
            assert entry["direction"] in {"to", "from"}
            endpoint = entry["to"] if entry["direction"] == "to" else entry["from"]
            assert endpoint == va, "xref row does not touch the asked address"
        if result.get("count", 0) >= 1 and referenced is None:
            referenced = (va, result)
    assert referenced is not None, "no function in the first 12 had any xref"

    # The image base is the MZ header: no code, no refs. The old global dump
    # returned every xref in the binary here.
    header = client.xrefs(fixture, funcs["image_base"], timeout=60.0)
    assert header.get("parsed") is True
    assert header.get("count") == 0
