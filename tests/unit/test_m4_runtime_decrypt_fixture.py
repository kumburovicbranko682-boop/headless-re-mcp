"""M4.5: runtime-decrypt fixture exports the flag/trigger contract."""

from __future__ import annotations

from pathlib import Path

import pytest

_PROJECT = Path(__file__).resolve().parents[2]


def _export_names(pe_path: Path) -> set[str]:
    data = pe_path.read_bytes()
    pe = int.from_bytes(data[0x3C:0x40], "little")
    magic = int.from_bytes(data[pe + 24 : pe + 26], "little")
    pe32_plus = magic == 0x20B
    opt = pe + 24
    dir_off = opt + (112 if pe32_plus else 96)
    export_rva = int.from_bytes(data[dir_off : dir_off + 4], "little")
    if export_rva == 0:
        return set()
    # Map RVA via section table.
    section_count = int.from_bytes(data[pe + 6 : pe + 8], "little")
    optional_size = int.from_bytes(data[pe + 20 : pe + 22], "little")
    section = pe + 24 + optional_size

    def rva_to_off(rva: int) -> int:
        for index in range(section_count):
            base = section + index * 40
            virt = int.from_bytes(data[base + 12 : base + 16], "little")
            raw_size = int.from_bytes(data[base + 16 : base + 20], "little")
            raw = int.from_bytes(data[base + 20 : base + 24], "little")
            vsize = int.from_bytes(data[base + 8 : base + 12], "little")
            size = max(vsize, raw_size)
            if virt <= rva < virt + size:
                return raw + (rva - virt)
        raise AssertionError(f"RVA {rva:#x} not mapped")

    exp = rva_to_off(export_rva)
    names_count = int.from_bytes(data[exp + 24 : exp + 28], "little")
    names_rva = int.from_bytes(data[exp + 32 : exp + 36], "little")
    names_off = rva_to_off(names_rva)
    result: set[str] = set()
    for index in range(names_count):
        name_rva = int.from_bytes(
            data[names_off + index * 4 : names_off + index * 4 + 4], "little"
        )
        name_off = rva_to_off(name_rva)
        end = data.index(0, name_off)
        result.add(data[name_off:end].decode("ascii", errors="replace"))
    return result


@pytest.mark.parametrize(
    "relative",
    [
        Path("artifacts/fixtures-x64/runtime_decrypt_fixture.dll"),
        Path("artifacts/fixtures-x86/runtime_decrypt_fixture.dll"),
    ],
)
def test_runtime_decrypt_fixture_exports(relative: Path) -> None:
    path = _PROJECT / relative
    if not path.is_file():
        pytest.skip(f"fixture not built: {path}")
    names = {name.casefold() for name in _export_names(path)}
    # x86 may decorate as _name@0; accept undecorated containment.
    assert any("runtime_decrypt_trigger" in name for name in names)
    assert any("runtime_decrypt_flag" in name for name in names)
