from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.addressing import (
    AddressSyncError,
    RuntimeModuleCatalog,
    build_main_module_mapping,
    build_rebased_module_mapping,
)
from headless_re_mcp.core.models import Architecture, ModuleSelector, Session
from headless_re_mcp.core.session import file_sha256


def _session(path: str = r"C:\sample\fixtures\fixture.exe") -> Session:
    return Session(
        binary=Path(path),
        sha256="a" * 64,
        architecture=Architecture.X64,
    )


def _modules(*values: dict[str, object]) -> dict[str, object]:
    return {"modules": list(values), "count": len(values)}


def _runtime_metadata(
    architecture: Architecture = Architecture.X64,
) -> dict[str, object]:
    return {"architecture": architecture.value}


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
    image[base_offset : base_offset + base_size] = preferred_base.to_bytes(
        base_size,
        "little",
    )
    image[optional + 56 : optional + 60] = image_size.to_bytes(4, "little")
    path.write_bytes(image)


def test_main_module_mapping_translates_both_directions() -> None:
    mapping = build_main_module_mapping(
        _session(),
        {"image_base": 0x140000000},
        _modules(
            {
                "base": 0x7FF700000000,
                "size": 0x6000,
                "name": "fixture.exe",
                "path": "c:/SAMPLE/FIXTURES/fixture.exe",
            }
        ),
        _runtime_metadata(),
    )

    runtime = mapping.translate("static", 0x140001234)
    assert runtime["rva"] == 0x1234
    assert runtime["runtime"]["address"] == 0x7FF700001234
    assert runtime["match_basis"] == "path"
    assert runtime["module"]["sha256"] == "a" * 64

    static = mapping.translate("runtime", 0x7FF700001234)
    assert static["rva"] == 0x1234
    assert static["static"]["address"] == 0x140001234


def test_main_module_mapping_falls_back_to_unique_name() -> None:
    mapping = build_main_module_mapping(
        _session(),
        {"image_base": 0x140000000},
        _modules(
            {
                "base": 0x180000000,
                "size": 0x5000,
                "name": "fixture.exe",
                "path": r"C:\staged\fixture.exe",
            }
        ),
        _runtime_metadata(),
    )

    assert mapping.match_basis == "name"
    assert mapping.translate("static", 0x140000100)["runtime"]["address"] == 0x180000100


def test_main_module_mapping_rejects_ambiguous_name() -> None:
    modules = _modules(
        {
            "base": 0x180000000,
            "size": 0x5000,
            "name": "fixture.exe",
            "path": r"C:\first\fixture.exe",
        },
        {
            "base": 0x190000000,
            "size": 0x5000,
            "name": "fixture.exe",
            "path": r"C:\second\fixture.exe",
        },
    )

    with pytest.raises(AddressSyncError) as exc_info:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            modules,
            _runtime_metadata(),
        )
    assert exc_info.value.code == "module_ambiguous"


def test_main_module_mapping_rejects_missing_module() -> None:
    with pytest.raises(AddressSyncError) as exc_info:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            _modules(
                {
                    "base": 0x180000000,
                    "size": 0x5000,
                    "name": "other.dll",
                    "path": r"C:\Windows\System32\other.dll",
                }
            ),
            _runtime_metadata(),
        )
    assert exc_info.value.code == "module_not_found"


def test_main_module_mapping_rejects_runtime_architecture_mismatch() -> None:
    with pytest.raises(AddressSyncError) as exc_info:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            _modules(),
            _runtime_metadata(Architecture.X86),
        )

    assert exc_info.value.code == "architecture_mismatch"
    assert exc_info.value.details == {"expected": "x64", "actual": "x86"}


def test_translation_rejects_address_outside_module() -> None:
    mapping = build_main_module_mapping(
        _session(),
        {"image_base": 0x140000000},
        _modules(
            {
                "base": 0x180000000,
                "size": 0x1000,
                "name": "fixture.exe",
                "path": r"C:\sample\fixtures\fixture.exe",
            }
        ),
        _runtime_metadata(),
    )

    with pytest.raises(AddressSyncError) as exc_info:
        mapping.translate("static", 0x140001000)
    assert exc_info.value.code == "address_out_of_range"


def test_runtime_module_catalog_requires_explicit_unique_selection() -> None:
    catalog = RuntimeModuleCatalog.from_result(
        _modules(
            {
                "base": 0x180000000,
                "size": 0x5000,
                "name": "shared.dll",
                "path": r"C:\first\shared.dll",
            },
            {
                "base": 0x190000000,
                "size": 0x6000,
                "name": "shared.dll",
                "path": r"C:\second\shared.dll",
            },
        )
    )

    by_base, base_basis = catalog.select(ModuleSelector(base=0x180000000))
    by_path, path_basis = catalog.select(
        ModuleSelector(path="c:/SECOND/shared.dll")
    )

    assert by_base.path == r"C:\first\shared.dll"
    assert base_basis == "base"
    assert by_path.base == 0x190000000
    assert path_basis == "path"
    with pytest.raises(AddressSyncError) as exc_info:
        catalog.select(ModuleSelector(name="shared.dll"))
    assert exc_info.value.code == "module_ambiguous"
    assert exc_info.value.details["bases"] == [0x180000000, 0x190000000]


def test_win32_long_path_prefix_does_not_hide_a_path_match() -> None:
    # x64dbg can report module paths in the Win32 long-path form; the plain
    # spelling must still select the module, exactly like the NT \??\ form.
    catalog = RuntimeModuleCatalog.from_result(
        _modules(
            {
                "base": 0x180000000,
                "size": 0x5000,
                "name": "shared.dll",
                "path": "\\\\?\\C:\\first\\shared.dll",
            }
        )
    )
    by_plain, basis = catalog.select(ModuleSelector(path=r"C:\first\shared.dll"))
    assert by_plain.base == 0x180000000
    assert basis == "path"

    # And a selector carrying the prefix must match a plain runtime path.
    plain_catalog = RuntimeModuleCatalog.from_result(
        _modules(
            {
                "base": 0x190000000,
                "size": 0x5000,
                "name": "shared.dll",
                "path": r"C:\first\shared.dll",
            }
        )
    )
    by_prefixed, _ = plain_catalog.select(
        ModuleSelector(path="\\\\?\\C:\\first\\shared.dll")
    )
    assert by_prefixed.base == 0x190000000


def test_main_module_path_match_survives_the_long_path_prefix() -> None:
    mapping = build_main_module_mapping(
        _session(),
        {"image_base": 0x140000000},
        _modules(
            {
                "base": 0x7FF700000000,
                "size": 0x6000,
                "name": "fixture.exe",
                "path": "\\\\?\\C:\\sample\\fixtures\\fixture.exe",
            }
        ),
        _runtime_metadata(),
    )

    # Before the prefix was stripped this silently degraded to the weaker
    # name match; the path identity must survive the long-path spelling.
    assert mapping.match_basis == "path"


@pytest.mark.parametrize(
    "payload",
    [
        {"modules": [], "count": 1},
        {"modules": [None], "count": 1},
        {
            "modules": [
                {"base": True, "size": 0x1000, "name": "a.dll", "path": "a.dll"}
            ],
            "count": 1,
        },
        {
            "modules": [
                {"base": 0x1000, "size": 0, "name": "a.dll", "path": "a.dll"}
            ],
            "count": 1,
        },
        {
            "modules": [
                {"base": 0x1000, "size": 0x1000, "name": 1, "path": "a.dll"}
            ],
            "count": 1,
        },
        {
            "modules": [
                {"base": 0x1000, "size": 0x1000, "name": "a.dll", "path": "a.dll"},
                {"base": 0x1000, "size": 0x2000, "name": "b.dll", "path": "b.dll"},
            ],
            "count": 2,
        },
    ],
)
def test_runtime_module_catalog_rejects_malformed_snapshot(
    payload: dict[str, object],
) -> None:
    with pytest.raises(AddressSyncError) as exc_info:
        RuntimeModuleCatalog.from_result(payload)
    assert exc_info.value.code == "module_list_invalid"


def test_rebased_module_mapping_verifies_file_and_translates(tmp_path: Path) -> None:
    module = tmp_path / "event_fixture.dll"
    _write_pe(module, preferred_base=0x180000000, image_size=0x5000)
    runtime_base = 0x7FF800000000
    mapping = build_rebased_module_mapping(
        _modules(
            {
                "base": runtime_base,
                "size": 0x5000,
                "name": module.name,
                "path": str(module),
            }
        ),
        _runtime_metadata(),
        ModuleSelector(
            base=runtime_base,
            path=str(module),
            name="EVENT_FIXTURE.DLL",
            sha256=file_sha256(module).upper(),
        ),
    )

    to_runtime = mapping.translate("preferred", 0x180001234)
    to_preferred = mapping.translate("runtime", runtime_base + 0x1234)

    assert mapping.identity.sha256 == file_sha256(module)
    assert mapping.rebase_delta == runtime_base - 0x180000000
    assert to_runtime["rva"] == 0x1234
    assert to_runtime["runtime"]["address"] == runtime_base + 0x1234
    assert to_runtime["match_basis"] == "base"
    assert to_preferred["preferred"]["address"] == 0x180001234
    assert to_preferred["target"] == "preferred"


def test_rebased_module_mapping_rejects_identity_architecture_and_size_mismatch(
    tmp_path: Path,
) -> None:
    module = tmp_path / "event_fixture.dll"
    _write_pe(module, preferred_base=0x180000000, image_size=0x5000)
    runtime_module = {
        "base": 0x7FF800000000,
        "size": 0x5000,
        "name": module.name,
        "path": str(module),
    }

    with pytest.raises(AddressSyncError) as hash_error:
        build_rebased_module_mapping(
            _modules(runtime_module),
            _runtime_metadata(),
            ModuleSelector(path=str(module), sha256="0" * 64),
        )
    assert hash_error.value.code == "module_identity_mismatch"

    with pytest.raises(AddressSyncError) as architecture_error:
        build_rebased_module_mapping(
            _modules(runtime_module),
            _runtime_metadata(Architecture.X86),
            ModuleSelector(path=str(module)),
        )
    assert architecture_error.value.code == "architecture_mismatch"

    with pytest.raises(AddressSyncError) as size_error:
        build_rebased_module_mapping(
            _modules({**runtime_module, "size": 0x6000}),
            _runtime_metadata(),
            ModuleSelector(path=str(module)),
        )
    assert size_error.value.code == "module_size_mismatch"


def test_rebased_module_mapping_rejects_unavailable_file_and_bounds(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.dll"
    runtime_base = 0x7FF800000000
    with pytest.raises(AddressSyncError) as missing_error:
        build_rebased_module_mapping(
            _modules(
                {
                    "base": runtime_base,
                    "size": 0x5000,
                    "name": missing.name,
                    "path": str(missing),
                }
            ),
            _runtime_metadata(),
            ModuleSelector(base=runtime_base),
        )
    assert missing_error.value.code == "module_file_unavailable"

    module = tmp_path / "event_fixture.dll"
    _write_pe(module, image_size=0x5000)
    mapping = build_rebased_module_mapping(
        _modules(
            {
                "base": runtime_base,
                "size": 0x5000,
                "name": module.name,
                "path": str(module),
            }
        ),
        _runtime_metadata(),
        ModuleSelector(base=runtime_base),
    )
    with pytest.raises(AddressSyncError) as bounds_error:
        mapping.translate("runtime", runtime_base + 0x5000)
    assert bounds_error.value.code == "address_out_of_range"
