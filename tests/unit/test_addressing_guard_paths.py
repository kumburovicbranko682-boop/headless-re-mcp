"""Guard-path coverage for the x64dbg address-sync builders.

The happy paths and the headline rejections live in ``test_addressing.py``.
This file pins the remaining fail-closed guards in ``core/addressing.py`` -- the
ones that turn a malformed x64dbg module snapshot, a hostile module path, or a
corrupt on-disk PE into a structured ``AddressSyncError`` instead of letting a
``struct``/``OSError``/``ValueError`` escape as an uncaught crash. Each test
drives one guard through the public builder (or the ``ModuleAddressSpace``
primitive) so the invariant is exercised the same way the service reaches it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.addressing import (
    AddressSyncError,
    ModuleAddressSpace,
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
    return Session(
        binary=Path(path),
        sha256="a" * 64,
        architecture=Architecture.X64,
    )


def _modules(*values: dict[str, object]) -> dict[str, object]:
    return {"modules": list(values), "count": len(values)}


def _pe_image(
    *,
    machine: int = 0x8664,
    magic: int = 0x20B,
    size_of_optional_header: int = 0xF0,
    preferred_base: int = 0x180000000,
    image_size: int = 0x5000,
    optional_present: int | None = None,
    total_size: int | None = None,
) -> bytes:
    """Build a PE image whose fields ``_read_pe_image_layout`` reads back.

    ``detect_pe_architecture`` only inspects the DOS stub plus the 4-byte PE
    signature and the 2-byte machine field, whereas ``_read_pe_image_layout``
    re-reads a full 24-byte file header and then ``size_of_optional_header``
    bytes of the optional header. The keyword knobs let a test satisfy the
    former while deliberately corrupting the latter (truncated header, short
    optional, wrong magic, zeroed bounds), and ``total_size`` truncates the
    whole file so even the 24-byte header read can come up short.
    """
    pe_off = 0x80
    optional_start = pe_off + 24
    present = size_of_optional_header if optional_present is None else optional_present
    full_len = max(optional_start + present, 0x100)
    buf = bytearray(full_len)
    buf[:2] = b"MZ"
    buf[0x3C:0x40] = pe_off.to_bytes(4, "little")
    buf[pe_off : pe_off + 4] = b"PE\0\0"
    buf[pe_off + 4 : pe_off + 6] = machine.to_bytes(2, "little")
    buf[pe_off + 20 : pe_off + 22] = size_of_optional_header.to_bytes(2, "little")
    if present >= 2:
        buf[optional_start : optional_start + 2] = magic.to_bytes(2, "little")
    if present >= 32:
        buf[optional_start + 24 : optional_start + 32] = preferred_base.to_bytes(8, "little")
    if present >= 60:
        buf[optional_start + 56 : optional_start + 60] = image_size.to_bytes(4, "little")
    payload = bytes(buf)
    return payload if total_size is None else payload[:total_size]


# --- RuntimeModuleCatalog.from_result structural guards -------------------


def test_from_result_rejects_a_non_object_payload() -> None:
    with pytest.raises(AddressSyncError) as caught:
        RuntimeModuleCatalog.from_result(["not", "an", "object"])
    assert caught.value.code == "module_list_invalid"
    assert "object" in str(caught.value)


def test_from_result_rejects_a_missing_modules_array() -> None:
    with pytest.raises(AddressSyncError) as caught:
        RuntimeModuleCatalog.from_result({"count": 0})
    assert caught.value.code == "module_list_invalid"


def test_from_result_rejects_an_entry_without_a_name_or_path() -> None:
    payload = _modules({"base": 0x1000, "size": 0x1000, "name": "   ", "path": "\t"})
    with pytest.raises(AddressSyncError) as caught:
        RuntimeModuleCatalog.from_result(payload)
    assert caught.value.code == "module_list_invalid"


# --- catalog.select identity cross-checks ---------------------------------


def _single_catalog() -> RuntimeModuleCatalog:
    return RuntimeModuleCatalog.from_result(
        _modules(
            {
                "base": 0x180000000,
                "size": 0x5000,
                "name": "shared.dll",
                "path": r"C:\real\shared.dll",
            }
        )
    )


def test_select_rejects_a_selector_that_matches_nothing() -> None:
    catalog = _single_catalog()
    with pytest.raises(AddressSyncError) as caught:
        catalog.select(ModuleSelector(base=0xDEADBEEF))
    assert caught.value.code == "module_not_found"


def test_catalog_round_trips_through_to_dict() -> None:
    catalog = _single_catalog()
    payload = catalog.to_dict()
    assert payload["count"] == 1
    assert payload["modules"][0]["base"] == 0x180000000
    assert payload["modules"][0]["path"] == r"C:\real\shared.dll"


def test_select_by_base_rejects_a_conflicting_path_constraint() -> None:
    catalog = _single_catalog()
    with pytest.raises(AddressSyncError) as caught:
        catalog.select(ModuleSelector(base=0x180000000, path=r"C:\wrong\shared.dll"))
    assert caught.value.code == "module_identity_mismatch"
    assert caught.value.details["actual"] == {"path": r"C:\real\shared.dll"}


def test_select_by_base_rejects_a_conflicting_name_constraint() -> None:
    catalog = _single_catalog()
    with pytest.raises(AddressSyncError) as caught:
        catalog.select(ModuleSelector(base=0x180000000, name="other.dll"))
    assert caught.value.code == "module_identity_mismatch"
    assert caught.value.details["actual"] == {"name": "shared.dll"}


def test_select_by_path_normalizes_the_dos_device_prefix() -> None:
    """A ``\\??\\`` device-path prefix on the selector must still match.

    x64dbg reports some module paths with the NT object-manager prefix.
    ``_normalize_windows_path`` strips it so a selector carrying the prefix
    resolves to the same module the bare path would; this pins that the
    prefixed selector matches rather than falling through to module_not_found.
    """
    catalog = _single_catalog()
    module, basis = catalog.select(ModuleSelector(path="\\??\\C:\\real\\shared.dll"))
    assert basis == "path"
    assert module.base == 0x180000000


# --- _select_main_module ambiguity by path --------------------------------


def test_main_module_mapping_rejects_ambiguous_path() -> None:
    """Two modules whose paths normalize to the session binary are ambiguous.

    The name-ambiguity arm is covered elsewhere; this drives the earlier
    path-ambiguity arm, where distinct bases share a case/slash-folded path.
    """
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
            "path": "c:/SAMPLE/FIXTURES/fixture.exe",
        },
    )
    with pytest.raises(AddressSyncError) as caught:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            modules,
            {"architecture": "x64"},
        )
    assert caught.value.code == "module_ambiguous"
    assert caught.value.details["count"] == 2


# --- runtime architecture metadata guards ---------------------------------


def test_runtime_metadata_rejects_a_non_string_architecture() -> None:
    with pytest.raises(AddressSyncError) as caught:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            _modules(),
            {"architecture": 123},
        )
    assert caught.value.code == "runtime_metadata_invalid"


def test_runtime_metadata_rejects_an_unsupported_architecture() -> None:
    with pytest.raises(AddressSyncError) as caught:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            _modules(),
            {"architecture": "mips"},
        )
    assert caught.value.code == "runtime_metadata_invalid"


# --- ModuleAddressSpace primitive guards ----------------------------------


def _space() -> ModuleAddressSpace:
    return ModuleAddressSpace(
        backend=BackendKind.X64DBG,
        base=0x180000000,
        size=0x1000,
        name="m.dll",
        path=r"C:\m.dll",
    )


def test_from_rva_rejects_a_negative_rva() -> None:
    with pytest.raises(AddressSyncError) as caught:
        _space().from_rva(-1)
    assert caught.value.code == "invalid_address"
    assert caught.value.details["field"] == "rva"


def test_from_rva_rejects_an_rva_past_the_module_size() -> None:
    with pytest.raises(AddressSyncError) as caught:
        _space().from_rva(0x1000)
    assert caught.value.code == "address_out_of_range"


# --- runtime module path resolution guards --------------------------------


def _rebase_metadata() -> dict[str, object]:
    return {"architecture": "x64"}


def test_rebased_mapping_strips_the_dos_device_prefix_from_the_path(
    tmp_path: Path,
) -> None:
    """A ``\\??\\``-prefixed module path resolves to the real file and succeeds.

    This is the positive counterpart to the failure guards below: the prefix is
    stripped, the on-disk PE is read, and its SizeOfImage matches the loaded
    module, so a well-formed rebased mapping is produced.
    """
    module = tmp_path / "prefixed.dll"
    module.write_bytes(_pe_image(preferred_base=0x180000000, image_size=0x5000))
    runtime_base = 0x7FF800000000
    mapping = build_rebased_module_mapping(
        _modules(
            {
                "base": runtime_base,
                "size": 0x5000,
                "name": module.name,
                "path": "\\??\\" + str(module),
            }
        ),
        _rebase_metadata(),
        ModuleSelector(base=runtime_base),
    )
    assert mapping.preferred_base == 0x180000000
    assert mapping.rebase_delta == runtime_base - 0x180000000
    serialized = mapping.to_dict()
    assert serialized["rebase_delta"] == runtime_base - 0x180000000
    assert serialized["preferred"]["base"] == 0x180000000
    assert serialized["runtime"]["base"] == runtime_base


def test_rebased_mapping_rejects_a_path_that_is_only_the_device_prefix() -> None:
    with pytest.raises(AddressSyncError) as caught:
        build_rebased_module_mapping(
            _modules(
                {
                    "base": 0x7FF800000000,
                    "size": 0x5000,
                    "name": "ghost.dll",
                    "path": "\\??\\",
                }
            ),
            _rebase_metadata(),
            ModuleSelector(base=0x7FF800000000),
        )
    assert caught.value.code == "module_file_unavailable"


def test_rebased_mapping_rejects_a_module_path_that_is_a_directory(
    tmp_path: Path,
) -> None:
    with pytest.raises(AddressSyncError) as caught:
        build_rebased_module_mapping(
            _modules(
                {
                    "base": 0x7FF800000000,
                    "size": 0x5000,
                    "name": "dir",
                    "path": str(tmp_path),
                }
            ),
            _rebase_metadata(),
            ModuleSelector(base=0x7FF800000000),
        )
    assert caught.value.code == "module_file_unavailable"


# --- on-disk PE layout guards ---------------------------------------------


@pytest.mark.parametrize(
    "image_kwargs",
    [
        pytest.param({"total_size": 0x86}, id="truncated-file-header"),
        pytest.param(
            {"size_of_optional_header": 40, "optional_present": 40},
            id="short-optional-header",
        ),
        pytest.param({"magic": 0x10B}, id="magic-disagrees-with-machine"),
        pytest.param({"image_size": 0}, id="zeroed-image-size"),
        pytest.param({"preferred_base": 0}, id="zeroed-image-base"),
    ],
)
def test_rebased_mapping_rejects_a_corrupt_pe_image(
    tmp_path: Path, image_kwargs: dict[str, object]
) -> None:
    """Every corrupt-PE shape becomes module_file_invalid, never a raw crash.

    ``_read_pe_image_layout`` reads fixed offsets out of the optional header;
    without its bounds checks a truncated file or a mismatched magic would leak
    a ``ValueError``/``struct`` error. Each parametrization corrupts one field
    that ``detect_pe_architecture`` does not look at, so the file passes the
    initial architecture sniff and then trips a specific layout guard.
    """
    module = tmp_path / "corrupt.dll"
    module.write_bytes(_pe_image(**image_kwargs))  # type: ignore[arg-type]
    with pytest.raises(AddressSyncError) as caught:
        build_rebased_module_mapping(
            _modules(
                {
                    "base": 0x7FF800000000,
                    "size": 0x5000,
                    "name": module.name,
                    "path": str(module),
                }
            ),
            _rebase_metadata(),
            ModuleSelector(base=0x7FF800000000),
        )
    assert caught.value.code == "module_file_invalid"
