"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _require_r2_and_fixture(name: str) -> tuple[R2Client, Path]:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / name
    if not fixture.is_file():
        pytest.skip(f"fixture missing: {fixture}")
    return client, fixture


def _first_function_va(client: R2Client, fixture: Path) -> int:
    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    for item in funcs["items"]:
        address = item.get("address")
        if isinstance(address, dict) and isinstance(address.get("va"), int):
            return int(address["va"])
    pytest.skip("no function carried a virtual address (skip≠pass)")


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client, fixture = _require_r2_and_fixture("headless_fixture.exe")

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
def test_m11_r2_live_disasm_maps_the_request_address() -> None:
    """disasm exercises the ``pdj N @ addr`` whitelist branch and the request-
    address enrichment (``address_va`` plus a mapped ``address`` dict), neither
    of which the aflj listing above touches. rva must equal va-image_base."""
    client, fixture = _require_r2_and_fixture("headless_fixture.exe")
    va = _first_function_va(client, fixture)

    data = client.disasm(fixture, va, count=8, timeout=60.0)
    assert data.get("address_va") == va
    mapped = data.get("address")
    assert isinstance(mapped, dict)
    assert mapped.get("va") == va
    # PE fixtures carry a preferred ImageBase, so the request address must come
    # back module-relative, not just as a bare VA.
    image_base = data.get("image_base")
    assert isinstance(image_base, int)
    assert mapped.get("module") == fixture.name
    assert mapped.get("rva") == va - image_base


@pytest.mark.integration
def test_m11_r2_live_xrefs_returns_a_structured_envelope() -> None:
    """xrefs exercises the ``axj @ addr`` whitelist branch and must answer with
    a parsed, item-bounded envelope rather than raising on live output."""
    client, fixture = _require_r2_and_fixture("headless_fixture.exe")
    va = _first_function_va(client, fixture)

    data = client.xrefs(fixture, va, timeout=60.0)
    assert data.get("parsed") is True
    assert data.get("address_va") == va
    assert isinstance(data.get("items"), list)
    assert isinstance(data.get("count"), int)
