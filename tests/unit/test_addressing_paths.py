"""Error-branch tests for the address-sync helpers in ``core.addressing``.

The public happy paths and a handful of failures are covered by
``test_addressing``; this file pins the remaining validation arcs: malformed
runtime module snapshots, identity mismatches on extra selector constraints,
runtime-architecture metadata rejection, and the low-level PE optional-header
parsing guards in ``_read_pe_image_layout`` / ``_resolve_runtime_module_path``.
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
    build_main_module_mapping,
    build_rebased_module_mapping,
)
from headless_re_mcp.core.models import Architecture, BackendKind, ModuleSelector, Session


def _write_pe(
    path: Path,
    *,
    architecture: Architecture = Architecture.X64,
    preferred_base: int = 0x180000000,
    image_size: int = 0x5000,
) -> None:
    machine = 0x014C if architecture == Architecture.X86 else 0x8664
    magic = 0x10B if architecture == Architecture.X86 else 0x20B
    optional_size = 0xE0 if architecture == Architecture.X86 else 0xF0
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    image[0x94:0x96] = optional_size.to_bytes(2, "little")
    optional = 0x98
    image[optional : optional + 2] = magic.to_bytes(2, "little")
    base_offset = optional + (28 if architecture == Architecture.X86 else 24)
    base_size = 4 if architecture == Architecture.X86 else 8
    image[base_offset : base_offset + base_size] = preferred_base.to_bytes(base_size, "little")
    image[optional + 56 : optional + 60] = image_size.to_bytes(4, "little")
    path.write_bytes(image)


def _session(path: str = r"C:\sample\fixtures\fixture.exe") -> Session:
    return Session(binary=Path(path), sha256="a" * 64, architecture=Architecture.X64)


def _modules(*values: dict[str, object]) -> dict[str, object]:
    return {"modules": list(values), "count": len(values)}


def _runtime_metadata(architecture: Architecture = Architecture.X64) -> dict[str, object]:
    return {"architecture": architecture.value}


# --- RuntimeModuleCatalog.from_result shape guards --------------------------


def test_from_result_rejects_non_object() -> None:
    with pytest.raises(AddressSyncError) as exc:
        RuntimeModuleCatalog.from_result(["not", "a", "dict"])
    assert exc.value.code == "module_list_invalid"


def test_from_result_rejects_non_list_modules() -> None:
    with pytest.raises(AddressSyncError) as exc:
        RuntimeModuleCatalog.from_result({"modules": None, "count": 0})
    assert exc.value.code == "module_list_invalid"


def test_runtime_module_rejects_blank_name_and_path() -> None:
    with pytest.raises(AddressSyncError) as exc:
        RuntimeModuleCatalog.from_result(
            _modules({"base": 0x1000, "size": 0x1000, "name": "  ", "path": "  "})
        )
    assert exc.value.code == "module_list_invalid"


# --- explicit-selector identity mismatch ------------------------------------


def test_select_rejects_identity_mismatch_on_extra_constraints() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules(
            {
                "base": 0x180000000,
                "size": 0x5000,
                "name": "real.dll",
                "path": r"C:\real\real.dll",
            }
        )
    )
    with pytest.raises(AddressSyncError) as exc:
        catalog.select(
            ModuleSelector(base=0x180000000, path="c:/wrong/other.dll", name="other.dll")
        )
    assert exc.value.code == "module_identity_mismatch"
    assert exc.value.details["actual"]["path"] == r"C:\real\real.dll"
    assert exc.value.details["actual"]["name"] == "real.dll"


def test_catalog_round_trips_to_dict() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules(
            {"base": 0x180000000, "size": 0x5000, "name": "a.dll", "path": r"C:\a.dll"},
            {"base": 0x190000000, "size": 0x6000, "name": "b.dll", "path": r"C:\b.dll"},
        )
    )
    payload = catalog.to_dict()
    assert payload["count"] == 2
    assert payload["modules"][0]["base"] == 0x180000000


def test_select_rejects_absent_base() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules({"base": 0x180000000, "size": 0x5000, "name": "a.dll", "path": r"C:\a.dll"})
    )
    with pytest.raises(AddressSyncError) as exc:
        catalog.select(ModuleSelector(base=0xDEADBEEF))
    assert exc.value.code == "module_not_found"


def test_rebased_module_mapping_to_dict(tmp_path: Path) -> None:
    module = tmp_path / "event_fixture.dll"
    _write_pe(module, preferred_base=0x180000000, image_size=0x5000)
    runtime_base = 0x7FF800000000
    mapping = build_rebased_module_mapping(
        _modules({"base": runtime_base, "size": 0x5000, "name": module.name, "path": str(module)}),
        _runtime_metadata(),
        ModuleSelector(base=runtime_base),
    )
    payload = mapping.to_dict()
    assert payload["rebase_delta"] == runtime_base - 0x180000000
    assert payload["preferred"]["base"] == 0x180000000
    assert payload["runtime"]["base"] == runtime_base


def test_main_module_mapping_rejects_ambiguous_path() -> None:
    modules = _modules(
        {
            "base": 0x180000000,
            "size": 0x5000,
            "name": "fixture.exe",
            "path": r"C:\sample\fixtures\fixture.exe",
        },
        {
            "base": 0x190000000,
            "size": 0x5000,
            "name": "fixture.exe",
            "path": r"C:\sample\fixtures\fixture.exe",
        },
    )
    with pytest.raises(AddressSyncError) as exc:
        build_main_module_mapping(
            _session(), {"image_base": 0x140000000}, modules, _runtime_metadata()
        )
    assert exc.value.code == "module_ambiguous"


# --- runtime architecture metadata ------------------------------------------


def test_runtime_architecture_rejects_non_string() -> None:
    with pytest.raises(AddressSyncError) as exc:
        build_main_module_mapping(
            _session(), {"image_base": 0x140000000}, _modules(), {"architecture": 123}
        )
    assert exc.value.code == "runtime_metadata_invalid"


def test_runtime_architecture_rejects_unsupported_value() -> None:
    with pytest.raises(AddressSyncError) as exc:
        build_main_module_mapping(
            _session(), {"image_base": 0x140000000}, _modules(), {"architecture": "sparc"}
        )
    assert exc.value.code == "runtime_metadata_invalid"


# --- ModuleAddressSpace.from_rva --------------------------------------------


def test_module_address_space_from_rva_rejects_out_of_range() -> None:
    space = ModuleAddressSpace(
        backend=BackendKind.X64DBG, base=0x1000, size=0x100, name="x", path="x"
    )
    assert space.from_rva(0xFF) == 0x10FF
    with pytest.raises(AddressSyncError) as exc:
        space.from_rva(0x100)
    assert exc.value.code == "address_out_of_range"


# --- _resolve_runtime_module_path -------------------------------------------


def test_resolve_runtime_module_path_strips_nt_prefix(tmp_path: Path) -> None:
    real = tmp_path / "mod.dll"
    real.write_bytes(b"MZ")
    resolved = _resolve_runtime_module_path("\\??\\" + str(real))
    assert resolved == real.resolve()


def test_resolve_runtime_module_path_rejects_empty() -> None:
    with pytest.raises(AddressSyncError) as exc:
        _resolve_runtime_module_path("   ")
    assert exc.value.code == "module_file_unavailable"


def test_resolve_runtime_module_path_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(AddressSyncError) as exc:
        _resolve_runtime_module_path(str(tmp_path))
    assert exc.value.code == "module_file_unavailable"


# --- _read_pe_image_layout optional-header guards ---------------------------


def _pe_layout_file(path: Path, *, machine: int = 0x8664, optional: bytes = b"") -> None:
    """A file whose PE signature/machine parse but whose optional header is
    supplied verbatim, so each optional-header guard can be triggered."""
    dos = bytearray(64)
    dos[:2] = b"MZ"
    dos[0x3C:0x40] = (64).to_bytes(4, "little")
    file_header = bytearray(24)
    file_header[0:4] = b"PE\0\0"
    file_header[4:6] = machine.to_bytes(2, "little")
    file_header[20:22] = len(optional).to_bytes(2, "little")
    path.write_bytes(bytes(dos) + bytes(file_header) + optional)


def test_read_pe_image_layout_rejects_truncated_header(tmp_path: Path) -> None:
    module = tmp_path / "truncated.dll"
    dos = bytearray(64)
    dos[:2] = b"MZ"
    dos[0x3C:0x40] = (64).to_bytes(4, "little")
    # Exactly the 6 bytes detect_pe_architecture reads, so it parses X64, but
    # the 24-byte COFF header read in _read_pe_image_layout comes up short.
    module.write_bytes(bytes(dos) + b"PE\0\0" + (0x8664).to_bytes(2, "little"))
    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(module)
    assert exc.value.code == "module_file_invalid"


def test_read_pe_image_layout_rejects_truncated_optional(tmp_path: Path) -> None:
    module = tmp_path / "short_optional.dll"
    _pe_layout_file(module, optional=bytes(10))
    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(module)
    assert exc.value.code == "module_file_invalid"


def test_read_pe_image_layout_rejects_bad_magic(tmp_path: Path) -> None:
    module = tmp_path / "bad_magic.dll"
    _pe_layout_file(module, optional=bytes(240))
    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(module)
    assert exc.value.code == "module_file_invalid"


def test_read_pe_image_layout_rejects_invalid_bounds(tmp_path: Path) -> None:
    module = tmp_path / "zero_base.dll"
    optional = bytearray(240)
    optional[0:2] = (0x20B).to_bytes(2, "little")
    optional[56:60] = (0x5000).to_bytes(4, "little")
    _pe_layout_file(module, optional=bytes(optional))
    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(module)
    assert exc.value.code == "module_file_invalid"


# --- small path/address helpers ---------------------------------------------


def test_normalize_windows_path_strips_nt_prefix() -> None:
    assert _normalize_windows_path("\\??\\C:\\Dir\\File.DLL") == _normalize_windows_path(
        "C:\\Dir\\File.DLL"
    )


def test_require_address_rejects_negative_and_bool() -> None:
    with pytest.raises(AddressSyncError) as exc:
        _require_address(-1)
    assert exc.value.code == "invalid_address"
    with pytest.raises(AddressSyncError):
        _require_address(True)
