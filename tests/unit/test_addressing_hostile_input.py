"""Fail-closed branches of the static/runtime address sync layer.

`core/addressing.py` turns x64dbg's module snapshot and an on-disk PE into a
translation between IDA's static image and the live process. Every input here
is attacker-influenced: the module list arrives over RPC, the selector comes
from the model, and the PE bytes come from whatever the debuggee mapped. The
happy paths and the common rejections already have tests; this file pins the
remaining refusal branches so a malformed snapshot or a corrupt optional header
can never silently produce a wrong address.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.addressing import (
    AddressSyncError,
    ModuleAddressSpace,
    RebasedModuleMapping,
    RuntimeModuleCatalog,
    build_main_module_mapping,
    build_rebased_module_mapping,
)
from headless_re_mcp.core.models import (
    Architecture,
    BackendKind,
    ModuleSelector,
    Session,
)


def _session(path: str = r"C:\sample\fixtures\fixture.exe") -> Session:
    return Session(binary=Path(path), sha256="a" * 64, architecture=Architecture.X64)


def _modules(*values: dict[str, object]) -> dict[str, object]:
    return {"modules": list(values), "count": len(values)}


def _pe_bytes(
    *,
    machine: int = 0x8664,
    optional_size: int = 0xF0,
    optional_written: int | None = None,
    magic: int = 0x20B,
    image_base: int = 0x180000000,
    image_size: int = 0x5000,
    file_header_len: int = 24,
) -> bytes:
    """Craft a PE whose header knobs let each layout guard be reached in turn."""
    pe_off = 0x80
    body = bytearray(0x400)
    body[0:2] = b"MZ"
    body[0x3C:0x40] = pe_off.to_bytes(4, "little")
    body[pe_off : pe_off + 4] = b"PE\0\0"
    body[pe_off + 4 : pe_off + 6] = machine.to_bytes(2, "little")
    # COFF file header spans pe_off .. pe_off+24; optional-header size at +20.
    body[pe_off + 20 : pe_off + 22] = optional_size.to_bytes(2, "little")
    opt = pe_off + 24
    body[opt : opt + 2] = magic.to_bytes(2, "little")
    base_off = opt + 24  # x64 ImageBase offset
    body[base_off : base_off + 8] = image_base.to_bytes(8, "little")
    body[opt + 56 : opt + 60] = image_size.to_bytes(4, "little")
    # `optional_written` truncates the file so read(optional_size) comes up short.
    if optional_written is not None:
        return bytes(body[: opt + optional_written])
    if file_header_len < 24:
        return bytes(body[: pe_off + file_header_len])
    return bytes(body)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


# --- RuntimeModuleCatalog.from_result shape guards -------------------------


def test_a_non_object_module_result_is_refused() -> None:
    with pytest.raises(AddressSyncError) as caught:
        RuntimeModuleCatalog.from_result("not an object")
    assert caught.value.code == "module_list_invalid"


def test_a_result_without_a_modules_array_is_refused() -> None:
    with pytest.raises(AddressSyncError) as caught:
        RuntimeModuleCatalog.from_result({"modules": "nope", "count": 0})
    assert caught.value.code == "module_list_invalid"


def test_a_module_entry_with_neither_name_nor_path_is_refused() -> None:
    with pytest.raises(AddressSyncError) as caught:
        RuntimeModuleCatalog.from_result(
            _modules({"base": 0x1000, "size": 0x1000, "name": "  ", "path": "  "})
        )
    assert caught.value.code == "module_list_invalid"


# --- selector identity constraints beyond the matching basis ---------------


def test_extra_selector_constraints_must_also_hold(tmp_path: Path) -> None:
    # The base picks exactly one module, but the caller also pinned a path and
    # name that do not describe it; both mismatches must be reported, not
    # silently ignored in favor of the base match.
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
    with pytest.raises(AddressSyncError) as caught:
        catalog.select(
            ModuleSelector(
                base=0x180000000,
                path=r"C:\wrong\other.dll",
                name="other.dll",
            )
        )
    assert caught.value.code == "module_identity_mismatch"
    actual = caught.value.details["actual"]
    assert isinstance(actual, dict)
    assert actual["path"] == r"C:\real\real.dll"
    assert actual["name"] == "real.dll"


def test_a_selector_matching_nothing_is_module_not_found() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules(
            {"base": 0x180000000, "size": 0x5000, "name": "mod.dll", "path": r"C:\dir\mod.dll"}
        )
    )
    with pytest.raises(AddressSyncError) as caught:
        catalog.select(ModuleSelector(base=0xDEAD0000))
    assert caught.value.code == "module_not_found"


def test_catalog_round_trips_through_to_dict() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules(
            {"base": 0x180000000, "size": 0x5000, "name": "mod.dll", "path": r"C:\dir\mod.dll"}
        )
    )
    payload = catalog.to_dict()
    assert payload["count"] == 1
    assert payload["modules"][0]["base"] == 0x180000000
    assert payload["modules"][0]["path"] == r"C:\dir\mod.dll"


def test_a_device_prefixed_selector_path_still_matches(tmp_path: Path) -> None:
    # `\??\` is the NT object-manager prefix x64dbg sometimes reports; the
    # normalizer strips it so a caller can select with the clean path.
    catalog = RuntimeModuleCatalog.from_result(
        _modules(
            {
                "base": 0x180000000,
                "size": 0x5000,
                "name": "mod.dll",
                "path": r"C:\dir\mod.dll",
            }
        )
    )
    module, basis = catalog.select(ModuleSelector(path=r"\??\C:\dir\mod.dll"))
    assert basis == "path"
    assert module.base == 0x180000000


# --- ModuleAddressSpace bounds and address validation ----------------------


def _space(size: int = 0x5000) -> ModuleAddressSpace:
    return ModuleAddressSpace(
        backend=BackendKind.X64DBG,
        base=0x140000000,
        size=size,
        name="mod.dll",
        path=r"C:\dir\mod.dll",
    )


def test_from_rva_past_the_image_is_out_of_range() -> None:
    with pytest.raises(AddressSyncError) as caught:
        _space().from_rva(0x5000)
    assert caught.value.code == "address_out_of_range"


def test_a_negative_address_is_rejected_before_any_math() -> None:
    with pytest.raises(AddressSyncError) as caught:
        _space().to_rva(-1)
    assert caught.value.code == "invalid_address"


# --- runtime metadata architecture guards ----------------------------------


_MAIN_PATH = r"C:\sample\fixtures\fixture.exe"


def _main_module() -> dict[str, object]:
    return {"base": 0x140000000, "size": 0x5000, "name": "fixture.exe", "path": _MAIN_PATH}


def test_a_non_string_runtime_architecture_is_refused() -> None:
    with pytest.raises(AddressSyncError) as caught:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            _modules(_main_module()),
            {"architecture": 123},
        )
    assert caught.value.code == "runtime_metadata_invalid"


def test_an_unsupported_runtime_architecture_is_refused() -> None:
    with pytest.raises(AddressSyncError) as caught:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            _modules(_main_module()),
            {"architecture": "sparc"},
        )
    assert caught.value.code == "runtime_metadata_invalid"


def test_two_runtime_modules_on_the_session_path_are_ambiguous() -> None:
    path = r"C:\sample\fixtures\fixture.exe"
    with pytest.raises(AddressSyncError) as caught:
        build_main_module_mapping(
            _session(path),
            {"image_base": 0x140000000},
            _modules(
                {"base": 0x140000000, "size": 0x5000, "name": "fixture.exe", "path": path},
                {"base": 0x150000000, "size": 0x5000, "name": "fixture.exe", "path": path},
            ),
            {"architecture": "x64"},
        )
    assert caught.value.code == "module_ambiguous"


# --- runtime module file resolution -----------------------------------------


def _rebased(tmp_path: Path, module_path: str, *, size: int = 0x5000) -> RebasedModuleMapping:
    runtime_base = 0x7FF800000000
    return build_rebased_module_mapping(
        _modules({"base": runtime_base, "size": size, "name": "mod.dll", "path": module_path}),
        {"architecture": "x64"},
        ModuleSelector(base=runtime_base),
    )


def test_a_module_that_reports_no_path_is_unavailable(tmp_path: Path) -> None:
    with pytest.raises(AddressSyncError) as caught:
        _rebased(tmp_path, "   ")
    assert caught.value.code == "module_file_unavailable"


def test_a_module_path_that_is_a_directory_is_unavailable(tmp_path: Path) -> None:
    a_dir = tmp_path / "adir"
    a_dir.mkdir()
    with pytest.raises(AddressSyncError) as caught:
        _rebased(tmp_path, str(a_dir))
    assert caught.value.code == "module_file_unavailable"


def test_a_device_prefixed_module_path_is_resolved_and_read(tmp_path: Path) -> None:
    module = _write(tmp_path, "mod.dll", _pe_bytes(image_size=0x5000))
    mapping = _rebased(tmp_path, "\\??\\" + str(module))
    assert Path(mapping.identity.path) == module.resolve()
    assert mapping.image_size == 0x5000


def test_a_rebased_mapping_serializes_both_module_spaces(tmp_path: Path) -> None:
    module = _write(tmp_path, "mod.dll", _pe_bytes(image_base=0x180000000, image_size=0x5000))
    mapping = _rebased(tmp_path, str(module))
    payload = mapping.to_dict()
    assert payload["preferred"]["base"] == 0x180000000
    assert payload["runtime"]["base"] == 0x7FF800000000
    assert payload["rebase_delta"] == 0x7FF800000000 - 0x180000000
    assert payload["module"]["path"] == str(module.resolve())


# --- PE optional-header guards ----------------------------------------------


def test_a_non_pe_module_file_is_invalid(tmp_path: Path) -> None:
    junk = _write(tmp_path, "mod.dll", b"this is not a PE at all")
    with pytest.raises(AddressSyncError) as caught:
        _rebased(tmp_path, str(junk))
    assert caught.value.code == "module_file_invalid"


def test_a_truncated_pe_file_header_is_invalid(tmp_path: Path) -> None:
    # detect_pe_architecture only needs the 6-byte signature+machine, but the
    # layout reader wants a full 24-byte COFF header and must reject a short one.
    stub = _write(tmp_path, "mod.dll", _pe_bytes(file_header_len=10))
    with pytest.raises(AddressSyncError) as caught:
        _rebased(tmp_path, str(stub))
    assert caught.value.code == "module_file_invalid"


def test_a_truncated_optional_header_is_invalid(tmp_path: Path) -> None:
    stub = _write(tmp_path, "mod.dll", _pe_bytes(optional_size=0xF0, optional_written=40))
    with pytest.raises(AddressSyncError) as caught:
        _rebased(tmp_path, str(stub))
    assert caught.value.code == "module_file_invalid"


def test_a_wrong_optional_magic_is_inconsistent(tmp_path: Path) -> None:
    stub = _write(tmp_path, "mod.dll", _pe_bytes(magic=0x999))
    with pytest.raises(AddressSyncError) as caught:
        _rebased(tmp_path, str(stub))
    assert caught.value.code == "module_file_invalid"


def test_a_zero_image_base_is_invalid_bounds(tmp_path: Path) -> None:
    stub = _write(tmp_path, "mod.dll", _pe_bytes(image_base=0))
    with pytest.raises(AddressSyncError) as caught:
        _rebased(tmp_path, str(stub))
    assert caught.value.code == "module_file_invalid"
