"""Error and edge paths in core/addressing.py that the happy-path suite skips.

addressing.py is the trust boundary between a static analyzer's view of a binary
and a live debugger's: every translation it hands out is only sound if the two
module images genuinely line up. These tests exercise the rejections and helpers
that guard that invariant -- malformed x64dbg snapshots, selectors that half-match
the loaded module, PE files that are truncated or inconsistent, and the small
path/integer/address validators the public API leans on -- by driving the module
functions directly so each guard is pinned in isolation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.addressing import (
    AddressSyncError,
    ModuleAddressSpace,
    ModuleIdentity,
    RebasedModuleMapping,
    RuntimeModule,
    RuntimeModuleCatalog,
    _normalize_windows_path,
    _read_pe_image_layout,
    _require_address,
    _resolve_runtime_module_path,
    _runtime_architecture,
    _runtime_module,
    _select_main_module,
)
from headless_re_mcp.core.models import Architecture, BackendKind, ModuleSelector


def _modules(*values: dict[str, object]) -> dict[str, object]:
    return {"modules": list(values), "count": len(values)}


# --- RuntimeModuleCatalog.from_result / to_dict -----------------------------


def test_a_non_object_module_result_is_rejected() -> None:
    with pytest.raises(AddressSyncError) as exc:
        RuntimeModuleCatalog.from_result(["not", "an", "object"])
    assert exc.value.code == "module_list_invalid"
    assert "must be an object" in str(exc.value)


def test_a_result_without_a_modules_array_is_rejected() -> None:
    with pytest.raises(AddressSyncError) as exc:
        RuntimeModuleCatalog.from_result({"modules": "nope", "count": 0})
    assert exc.value.code == "module_list_invalid"
    assert "modules array" in str(exc.value)


def test_the_catalog_round_trips_through_to_dict() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules(
            {"base": 0x1000, "size": 0x100, "name": "a.dll", "path": r"C:\a.dll"},
            {"base": 0x2000, "size": 0x200, "name": "b.dll", "path": r"C:\b.dll"},
        )
    )

    dumped = catalog.to_dict()

    assert dumped["count"] == 2
    assert [m["base"] for m in dumped["modules"]] == [0x1000, 0x2000]


# --- RuntimeModuleCatalog.select --------------------------------------------


def _one_module_catalog() -> RuntimeModuleCatalog:
    return RuntimeModuleCatalog.from_result(
        _modules(
            {
                "base": 0x180000000,
                "size": 0x5000,
                "name": "fixture.exe",
                "path": r"C:\real\fixture.exe",
            }
        )
    )


def test_a_selector_matching_nothing_reports_module_not_found() -> None:
    with pytest.raises(AddressSyncError) as exc:
        _one_module_catalog().select(ModuleSelector(base=0xDEAD0000))
    assert exc.value.code == "module_not_found"


def test_a_base_match_that_violates_path_and_name_constraints_is_rejected() -> None:
    # A selector can pin the module by base yet also assert its path and name.
    # When the resolved module fails those extra constraints, the translation
    # must not proceed on a module the caller did not actually mean.
    selector = ModuleSelector(
        base=0x180000000,
        path=r"C:\somewhere\else.exe",
        name="other.exe",
    )

    with pytest.raises(AddressSyncError) as exc:
        _one_module_catalog().select(selector)

    assert exc.value.code == "module_identity_mismatch"
    actual = exc.value.details["actual"]
    assert isinstance(actual, dict)
    assert set(actual) == {"path", "name"}


# --- RebasedModuleMapping.to_dict -------------------------------------------


def test_a_rebased_mapping_serializes_both_images() -> None:
    identity = ModuleIdentity(
        name="x.dll",
        path=r"C:\x.dll",
        sha256="a" * 64,
        architecture=Architecture.X64,
    )
    runtime = RuntimeModule(base=0x7FF800000000, size=0x1000, name="x.dll", path=r"C:\x.dll")
    mapping = RebasedModuleMapping(
        identity=identity,
        preferred_base=0x180000000,
        image_size=0x1000,
        runtime=runtime,
        match_basis="base",
    )

    dumped = mapping.to_dict()

    assert dumped["rebase_delta"] == 0x7FF800000000 - 0x180000000
    assert dumped["preferred"]["base"] == 0x180000000
    assert dumped["runtime"]["base"] == 0x7FF800000000


# --- ModuleAddressSpace.from_rva --------------------------------------------


def test_an_rva_past_the_image_end_is_out_of_range() -> None:
    space = ModuleAddressSpace(
        backend=BackendKind.X64DBG,
        base=0x1000,
        size=0x100,
        name="x",
        path="x",
    )

    with pytest.raises(AddressSyncError) as exc:
        space.from_rva(0x100)
    assert exc.value.code == "address_out_of_range"


# --- _runtime_architecture ---------------------------------------------------


def test_runtime_metadata_without_a_string_architecture_is_rejected() -> None:
    with pytest.raises(AddressSyncError) as exc:
        _runtime_architecture({"architecture": 123})
    assert exc.value.code == "runtime_metadata_invalid"


def test_runtime_metadata_with_an_unsupported_architecture_is_rejected() -> None:
    with pytest.raises(AddressSyncError) as exc:
        _runtime_architecture({"architecture": "sparc"})
    assert exc.value.code == "runtime_metadata_invalid"


# --- _select_main_module -----------------------------------------------------


def test_two_modules_sharing_the_session_path_are_ambiguous() -> None:
    # from_result forbids duplicate bases but not duplicate paths, so the
    # runtime can legitimately report the same path twice at different bases;
    # picking one silently would map addresses into the wrong image.
    shared = r"C:\real\fixture.exe"
    identity = ModuleIdentity(
        name="fixture.exe",
        path=shared,
        sha256="a" * 64,
        architecture=Architecture.X64,
    )
    modules = (
        RuntimeModule(base=0x180000000, size=0x5000, name="fixture.exe", path=shared),
        RuntimeModule(base=0x190000000, size=0x5000, name="fixture.exe", path=shared),
    )

    with pytest.raises(AddressSyncError) as exc:
        _select_main_module(identity, modules)
    assert exc.value.code == "module_ambiguous"


# --- _runtime_module ---------------------------------------------------------


def test_a_module_entry_with_neither_name_nor_path_is_rejected() -> None:
    with pytest.raises(AddressSyncError) as exc:
        _runtime_module({"base": 1, "size": 1, "name": "   ", "path": "  "}, index=3)
    assert exc.value.code == "module_list_invalid"
    assert exc.value.details["index"] == 3


# --- _resolve_runtime_module_path -------------------------------------------


def test_a_dos_device_prefixed_path_is_stripped_and_resolved(tmp_path: Path) -> None:
    real = tmp_path / "module.dll"
    real.write_bytes(b"contents")

    resolved = _resolve_runtime_module_path("\\??\\" + str(real))

    assert resolved == real.resolve()


def test_a_blank_module_path_is_unavailable() -> None:
    with pytest.raises(AddressSyncError) as exc:
        _resolve_runtime_module_path("   ")
    assert exc.value.code == "module_file_unavailable"


def test_a_module_path_that_is_a_directory_is_unavailable(tmp_path: Path) -> None:
    with pytest.raises(AddressSyncError) as exc:
        _resolve_runtime_module_path(str(tmp_path))
    assert exc.value.code == "module_file_unavailable"


# --- _read_pe_image_layout ---------------------------------------------------


def _pe_bytes(
    *,
    machine: int = 0x8664,
    optional_size: int = 0xF0,
    magic: int = 0x20B,
    image_base: int = 0x180000000,
    image_size: int = 0x5000,
    truncate_to: int | None = None,
) -> bytes:
    """Craft a PE just complete enough for detect_pe_architecture to read the
    machine word, so _read_pe_image_layout's own parser is what gets tested."""
    pe_off = 0x80
    buf = bytearray(pe_off)
    buf[:2] = b"MZ"
    buf[0x3C:0x40] = pe_off.to_bytes(4, "little")
    file_header = bytearray(24)
    file_header[:4] = b"PE\0\0"
    file_header[4:6] = machine.to_bytes(2, "little")
    file_header[20:22] = optional_size.to_bytes(2, "little")
    buf += file_header
    optional = bytearray(optional_size)
    if len(optional) >= 2:
        optional[0:2] = magic.to_bytes(2, "little")
    base_off = 24 if machine == 0x8664 else 28
    base_sz = 8 if machine == 0x8664 else 4
    if len(optional) >= base_off + base_sz:
        optional[base_off : base_off + base_sz] = image_base.to_bytes(base_sz, "little")
    if len(optional) >= 60:
        optional[56:60] = image_size.to_bytes(4, "little")
    buf += optional
    if truncate_to is not None:
        buf = buf[:truncate_to]
    return bytes(buf)


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_a_well_formed_pe_yields_its_layout(tmp_path: Path) -> None:
    module = _write(tmp_path / "ok.dll", _pe_bytes(image_base=0x180000000, image_size=0x5000))

    architecture, base, size = _read_pe_image_layout(module)

    assert architecture == Architecture.X64
    assert base == 0x180000000
    assert size == 0x5000


def test_a_pe_header_cut_short_after_the_signature_is_invalid(tmp_path: Path) -> None:
    # detect_pe_architecture only needs six bytes at the PE offset; the layout
    # reader needs a full 24-byte file header and must reject a file that ends
    # in between rather than read past EOF.
    module = _write(tmp_path / "short.dll", _pe_bytes(truncate_to=0x86))

    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(module)
    assert exc.value.code == "module_file_invalid"


def test_a_truncated_optional_header_is_invalid(tmp_path: Path) -> None:
    module = _write(tmp_path / "trunc_opt.dll", _pe_bytes(optional_size=0x10))

    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(module)
    assert exc.value.code == "module_file_invalid"


def test_an_optional_header_magic_that_disagrees_with_the_machine_is_invalid(
    tmp_path: Path,
) -> None:
    # machine says x64 but the optional-header magic says PE32: a mismatched
    # pair is corruption or a mislabelled dump, not a translatable image.
    module = _write(tmp_path / "magic.dll", _pe_bytes(machine=0x8664, magic=0x10B))

    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(module)
    assert exc.value.code == "module_file_invalid"


def test_a_pe_declaring_a_zero_image_base_is_invalid(tmp_path: Path) -> None:
    module = _write(tmp_path / "zero_base.dll", _pe_bytes(image_base=0, image_size=0x5000))

    with pytest.raises(AddressSyncError) as exc:
        _read_pe_image_layout(module)
    assert exc.value.code == "module_file_invalid"


# --- _normalize_windows_path / _require_address ------------------------------


def test_normalize_strips_the_dos_device_prefix() -> None:
    normalized = _normalize_windows_path("\\??\\C:\\Windows\\System32\\x.dll")

    assert "?" not in normalized
    assert normalized == _normalize_windows_path(r"C:\Windows\System32\x.dll")


def test_a_negative_address_is_rejected() -> None:
    with pytest.raises(AddressSyncError) as exc:
        _require_address(-1)
    assert exc.value.code == "invalid_address"
