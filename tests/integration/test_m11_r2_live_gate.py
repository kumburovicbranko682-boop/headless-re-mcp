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
def test_m11_r2_live_elf_address_mapping(elf_fixture: Path) -> None:
    """radare2 maps an ELF's functions to va-based Address dicts.

    The PE case above exercises image-base relocation (rva/module). This covers
    the path enrich_r2_payload takes when there is no PE header to read a
    preferred base from -- which is every Linux/ELF target -- so the non-PE
    branch of the mapping gets real live coverage instead of only unit stubs.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")

    opened = client.open(elf_fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(elf_fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    # An ELF carries no PE preferred base, so mapping stays va-only: no
    # image_base is reported and functions get a va rather than a relocated rva.
    assert "image_base" not in funcs
    mapped = [item for item in funcs["items"] if isinstance(item.get("address"), dict)]
    assert mapped, "no function was mapped to an Address"
    address = mapped[0]["address"]
    assert "va" in address
    assert "rva" not in address
