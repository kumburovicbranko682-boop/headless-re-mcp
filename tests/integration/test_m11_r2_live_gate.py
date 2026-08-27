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


def _function_va(funcs: dict, prefer: str) -> int | None:
    """Pick a function's va from aflj output, preferring one named ``prefer``."""
    fallback: int | None = None
    for item in funcs.get("items", []):
        address = item.get("address")
        if not isinstance(address, dict) or "va" not in address:
            continue
        va = address["va"]
        if not isinstance(va, int):
            continue
        if prefer in str(item.get("name", "")):
            return va
        if fallback is None:
            fallback = va
    return fallback


@pytest.mark.integration
def test_m11_r2_live_elf_disassembly_parses_despite_bracket_operands(
    elf_fixture: Path,
) -> None:
    """Disassembling real code exercises parse_r2_json's pathological input.

    pdj output puts ``[`` inside opcode strings for every memory operand
    (``mov dword [rbp - 4], edi``), which is exactly what broke the old
    ``rfind("[")`` extraction: it sliced from a bracket inside an opcode, missed
    the root array, and reported parsed with no items. The -O0 fixture helper
    keeps its locals on the stack, so its disassembly is guaranteed to carry
    those bracketed operands -- real output of the shape only unit stubs covered.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")

    funcs = client.run(elf_fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    va = _function_va(funcs, prefer="elf_fixture_transform")
    assert va is not None, "no function va to disassemble"

    dis = client.disasm(elf_fixture, va, count=32, timeout=60.0)
    # The bracket is present in the raw payload (memory operands), and the parse
    # still produced opcode items -- the whole point of the parse_r2_json fix.
    assert "[" in str(dis.get("raw") or ""), "expected a bracketed memory operand"
    assert dis.get("parsed") is True
    assert dis.get("count", 0) >= 1
    mapped = [item for item in dis["items"] if isinstance(item.get("address"), dict)]
    assert mapped, "no opcode was mapped to an Address"
    assert "va" in mapped[0]["address"]


@pytest.mark.integration
def test_m11_r2_live_elf_strings_map_to_addresses(elf_fixture: Path) -> None:
    """izj on a real ELF parses and maps string addresses.

    Strings take the vaddr branch of _item_va rather than the function offset,
    so this covers a different key path through enrich_r2_payload against real
    output. The fixture's one printf literal is guaranteed to be in the binary.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")

    strings = client.run(elf_fixture, ["izj"], timeout=60.0)
    assert strings.get("parsed") is True
    assert "elf-fixture" in str(strings.get("raw") or ""), "fixture literal not found by izj"
    mapped = [item for item in strings.get("items", []) if isinstance(item.get("address"), dict)]
    assert mapped, "no string was mapped to an Address"
    assert "va" in mapped[0]["address"]
