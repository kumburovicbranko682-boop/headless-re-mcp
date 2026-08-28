"""Fail-closed guards of the address-sync module parser.

test_addressing.py covers the happy translations and the common malformed
snapshots. This file drives the remaining fail-closed arms: the explicit
selector identity checks, the runtime metadata architecture guard, the
device-path resolver, the PE optional-header parser's truncation/magic/bounds
refusals, and the low-level address/path validators. These parse untrusted
x64dbg module output and on-disk PE images, so a loosened guard here is a
sync-integrity hole rather than a cosmetic gap.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.addressing import (
    AddressSyncError,
    ModuleAddressSpace,
    RuntimeModuleCatalog,
    _normalize_windows_path,
    _read_pe_image_layout,
    _require_address,
    _resolve_runtime_module_path,
    _runtime_architecture,
    build_main_module_mapping,
    build_rebased_module_mapping,
)
from headless_re_mcp.core.models import Architecture, BackendKind, ModuleSelector, Session


def _session(path: str = r"C:\sample\fixtures\fixture.exe") -> Session:
    return Session(binary=Path(path), sha256="a" * 64, architecture=Architecture.X64)


def _modules(*values: dict[str, object]) -> dict[str, object]:
    return {"modules": list(values), "count": len(values)}


def _module(
    base: int, path: str, name: str = "shared.dll", size: int = 0x5000
) -> dict[str, object]:
    return {"base": base, "size": size, "name": name, "path": path}


# --- RuntimeModuleCatalog.from_result / .select ------------------------------


def test_from_result_rejects_a_non_object_payload() -> None:
    with pytest.raises(AddressSyncError) as exc:
        RuntimeModuleCatalog.from_result(["not", "a", "dict"])
    assert exc.value.code == "module_list_invalid"


def test_from_result_rejects_a_modules_field_that_is_not_a_list() -> None:
    with pytest.raises(AddressSyncError) as exc:
        RuntimeModuleCatalog.from_result({"modules": "nope", "count": 0})
    assert exc.value.code == "module_list_invalid"


def test_from_result_rejects_a_module_entry_with_no_name_or_path() -> None:
    with pytest.raises(AddressSyncError) as exc:
        RuntimeModuleCatalog.from_result(_modules(_module(0x1000, path="   ", name="  ")))
    assert exc.value.code == "module_list_invalid"


def test_catalog_to_dict_round_trips_the_modules() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules(_module(0x180000000, path=r"C:\a\shared.dll"))
    )
    payload = catalog.to_dict()
    assert payload["count"] == 1
    assert payload["modules"][0]["base"] == 0x180000000


def test_select_reports_no_match_for_an_absent_base() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules(_module(0x180000000, path=r"C:\a\shared.dll"))
    )
    with pytest.raises(AddressSyncError) as exc:
        catalog.select(ModuleSelector(base=0xDEADBEEF))
    assert exc.value.code == "module_not_found"


def test_select_by_base_rejects_a_conflicting_path_constraint() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules(_module(0x180000000, path=r"C:\a\shared.dll"))
    )
    with pytest.raises(AddressSyncError) as exc:
        catalog.select(ModuleSelector(base=0x180000000, path=r"C:\b\other.dll"))
    assert exc.value.code == "module_identity_mismatch"
    assert exc.value.details["actual"] == {"path": r"C:\a\shared.dll"}


def test_select_by_base_rejects_a_conflicting_name_constraint() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules(_module(0x180000000, path=r"C:\a\shared.dll", name="shared.dll"))
    )
    with pytest.raises(AddressSyncError) as exc:
        catalog.select(ModuleSelector(base=0x180000000, name="different.dll"))
    assert exc.value.code == "module_identity_mismatch"
    assert exc.value.details["actual"] == {"name": "shared.dll"}


# --- build_main_module_mapping architecture + ambiguity ----------------------


def test_main_mapping_rejects_non_string_runtime_architecture() -> None:
    with pytest.raises(AddressSyncError) as exc:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            _modules(),
            {"architecture": 123},
        )
    assert exc.value.code == "runtime_metadata_invalid"


def test_main_mapping_rejects_an_unsupported_runtime_architecture() -> None:
    with pytest.raises(AddressSyncError) as exc:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            _modules(),
            {"architecture": "sparc"},
        )
    assert exc.value.code == "runtime_metadata_invalid"


def test_main_mapping_rejects_two_modules_sharing_the_binary_path() -> None:
    shared = r"C:\sample\fixtures\fixture.exe"
    with pytest.raises(AddressSyncError) as exc:
        build_main_module_mapping(
            _session(shared),
            {"image_base": 0x140000000},
            _modules(
                _module(0x180000000, path=shared, name="fixture.exe"),
                _module(0x190000000, path=shared.lower(), name="fixture.exe"),
            ),
            {"architecture": "x64"},
        )
    assert exc.value.code == "module_ambiguous"
    assert exc.value.details["count"] == 2


def test_runtime_architecture_helper_reads_a_valid_value() -> None:
    assert _runtime_architecture({"architecture": "X64"}) == Architecture.X64


# --- ModuleAddressSpace bounds ----------------------------------------------


def test_address_space_from_rva_rejects_an_rva_past_the_image() -> None:
    space = ModuleAddressSpace(
        backend=BackendKind.X64DBG,
        base=0x180000000,
        size=0x1000,
        name="m.dll",
        path=r"C:\m.dll",
    )
    assert space.from_rva(0xFFF) == 0x180000FFF
    with pytest.raises(AddressSyncError) as exc:
        space.from_rva(0x1000)
    assert exc.value.code == "address_out_of_range"


# --- _resolve_runtime_module_path -------------------------------------------


def test_resolve_path_strips_a_device_prefix_then_resolves(tmp_path: Path) -> None:
    real = tmp_path / "payload.dll"
    real.write_bytes(b"MZ")
    resolved = _resolve_runtime_module_path("\\??\\" + real.as_posix())
    assert resolved == real.resolve()


def test_resolve_path_rejects_a_prefix_only_device_path() -> None:
    with pytest.raises(AddressSyncError) as exc:
        _resolve_runtime_module_path("\\??\\")
    assert exc.value.code == "module_file_unavailable"


def test_resolve_path_rejects_a_directory(tmp_path: Path) -> None:
    with pytest.raises(AddressSyncError) as exc:
        _resolve_runtime_module_path(str(tmp_path))
    assert exc.value.code == "module_file_unavailable"


# --- _read_pe_image_layout truncation / magic / bounds -----------------------


def _pe(
    *,
    machine: int = 0x8664,
    magic: int = 0x20B,
    optional_size: int = 0xF0,
    optional_payload_len: int = 0xF0,
    image_base: int = 0x180000000,
    image_size: int = 0x5000,
    file_header_len: int = 24,
) -> bytes:
    pe_off = 0x80
    total = pe_off + max(file_header_len, 0) + max(optional_payload_len, 0)
    buf = bytearray(total)
    buf[:2] = b"MZ"
    buf[0x3C:0x40] = pe_off.to_bytes(4, "little")
    if file_header_len >= 6:
        buf[pe_off : pe_off + 4] = b"PE\0\0"
        buf[pe_off + 4 : pe_off + 6] = machine.to_bytes(2, "little")
    if file_header_len >= 22:
        buf[pe_off + 20 : pe_off + 22] = optional_size.to_bytes(2, "little")
    opt = pe_off + file_header_len
    base_off = 28 if machine == 0x014C else 24
    base_size = 4 if machine == 0x014C else 8
    if optional_payload_len >= 2:
        buf[opt : opt + 2] = magic.to_bytes(2, "little")
    if optional_payload_len >= base_off + base_size:
        buf[opt + base_off : opt + base_off + base_size] = image_base.to_bytes(base_size, "little")
    if optional_payload_len >= 60:
        buf[opt + 56 : opt + 60] = image_size.to_bytes(4, "little")
    return bytes(buf)


def _write(tmp_path: Path, payload: bytes, name: str = "mod.dll") -> Path:
    target = tmp_path / name
    target.write_bytes(payload)
    return target


def test_pe_layout_rejects_a_truncated_file_header(tmp_path: Path) -> None:
    # Enough for detect_pe_architecture (6 bytes at pe_offset) but < 24 for layout.
    path = _write(tmp_path, _pe(file_header_len=6, optional_payload_len=0))
    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(path)
    assert exc.value.code == "module_file_invalid"


def test_pe_layout_rejects_a_truncated_optional_header(tmp_path: Path) -> None:
    path = _write(tmp_path, _pe(optional_size=0xF0, optional_payload_len=10))
    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(path)
    assert exc.value.code == "module_file_invalid"


def test_pe_layout_rejects_a_magic_that_disagrees_with_the_machine(tmp_path: Path) -> None:
    # 64-bit machine but a PE32 (0x10B) optional magic.
    path = _write(tmp_path, _pe(machine=0x8664, magic=0x10B))
    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(path)
    assert exc.value.code == "module_file_invalid"


def test_pe_layout_rejects_a_zero_image_base(tmp_path: Path) -> None:
    path = _write(tmp_path, _pe(image_base=0))
    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(path)
    assert exc.value.code == "module_file_invalid"


def test_pe_layout_rejects_a_zero_image_size(tmp_path: Path) -> None:
    path = _write(tmp_path, _pe(image_size=0))
    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(path)
    assert exc.value.code == "module_file_invalid"


def test_pe_layout_reads_a_well_formed_image(tmp_path: Path) -> None:
    path = _write(tmp_path, _pe(image_base=0x180000000, image_size=0x5000))
    architecture, preferred_base, image_size = _read_pe_image_layout(path)
    assert architecture == Architecture.X64
    assert preferred_base == 0x180000000
    assert image_size == 0x5000


# --- low-level validators ----------------------------------------------------


def test_normalize_windows_path_strips_the_nt_object_prefix() -> None:
    assert _normalize_windows_path("\\??\\C:\\Windows\\x.dll") == _normalize_windows_path(
        r"C:\Windows\x.dll"
    )
    assert _normalize_windows_path("   ") == ""


@pytest.mark.parametrize("value", [-1, True, "0x1000"])
def test_require_address_rejects_bad_values(value: object) -> None:
    with pytest.raises(AddressSyncError) as exc:
        _require_address(value)  # type: ignore[arg-type]
    assert exc.value.code == "invalid_address"


def test_rebased_mapping_to_dict_exposes_both_coordinate_frames(tmp_path: Path) -> None:
    module = tmp_path / "payload.dll"
    module.write_bytes(_pe(image_base=0x180000000, image_size=0x5000))
    runtime_base = 0x7FF800000000
    mapping = build_rebased_module_mapping(
        _modules(_module(runtime_base, path=str(module), name=module.name)),
        {"architecture": "x64"},
        ModuleSelector(base=runtime_base),
    )
    payload = mapping.to_dict()
    assert payload["preferred"]["base"] == 0x180000000
    assert payload["runtime"]["base"] == runtime_base
    assert payload["rebase_delta"] == runtime_base - 0x180000000
