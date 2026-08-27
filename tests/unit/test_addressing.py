from __future__ import annotations

from collections.abc import Callable
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
    magic: int | None = None,
    optional_size: int | None = None,
) -> None:
    machine = 0x014C if architecture == Architecture.X86 else 0x8664
    if magic is None:
        magic = 0x10B if architecture == Architecture.X86 else 0x20B
    if optional_size is None:
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


def _rebased(
    module: Path,
    *,
    size: int = 0x5000,
    metadata: dict[str, object] | None = None,
    selector: ModuleSelector | None = None,
) -> object:
    base = 0x7FF800000000
    return build_rebased_module_mapping(
        _modules({"base": base, "size": size, "name": module.name, "path": str(module)}),
        metadata if metadata is not None else _runtime_metadata(),
        selector if selector is not None else ModuleSelector(base=base),
    )


@pytest.mark.parametrize("bad", [-1, True])
def test_translate_rejects_a_non_integer_or_negative_address(bad: int) -> None:
    """translate guards the address before any range math.

    The value arrives from a tool argument. A negative number, or a bool
    (an int subclass that is never an address), must be refused with
    ``invalid_address`` rather than flowing into the base/size comparison as a
    real offset and quietly translating to something.
    """
    mapping = build_main_module_mapping(
        _session(),
        {"image_base": 0x140000000},
        _modules(
            {
                "base": 0x180000000,
                "size": 0x5000,
                "name": "fixture.exe",
                "path": r"C:\sample\fixtures\fixture.exe",
            }
        ),
        _runtime_metadata(),
    )
    with pytest.raises(AddressSyncError) as exc_info:
        mapping.translate("static", bad)
    assert exc_info.value.code == "invalid_address"


@pytest.mark.parametrize("architecture", [None, "sparc", 64])
def test_runtime_metadata_architecture_must_be_a_known_string(architecture: object) -> None:
    """x64dbg metadata is untrusted; a missing or unknown arch fails cleanly.

    ``_runtime_architecture`` is the first gate in the build. A non-string
    (metadata omitted the field) and a string that is not a supported
    ``Architecture`` (a debugger reporting an arch this tool does not map) both
    surface ``runtime_metadata_invalid`` instead of a raw TypeError/ValueError.
    """
    with pytest.raises(AddressSyncError) as exc_info:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            _modules(),
            {"architecture": architecture},
        )
    assert exc_info.value.code == "runtime_metadata_invalid"


def test_main_module_mapping_rejects_ambiguous_path() -> None:
    """Two runtime modules sharing the session path cannot identify the main one.

    The name-ambiguity case has its own test; this is the earlier, stricter
    path branch of ``_select_main_module``, which must refuse rather than pick
    one of two modules loaded from the same file.
    """
    same = r"C:\sample\fixtures\fixture.exe"
    with pytest.raises(AddressSyncError) as exc_info:
        build_main_module_mapping(
            _session(),
            {"image_base": 0x140000000},
            _modules(
                {"base": 0x180000000, "size": 0x5000, "name": "fixture.exe", "path": same},
                {"base": 0x190000000, "size": 0x5000, "name": "fixture.exe", "path": same},
            ),
            _runtime_metadata(),
        )
    assert exc_info.value.code == "module_ambiguous"


def test_runtime_module_entry_requires_a_name_or_path() -> None:
    """A module row that is all whitespace carries no usable identity.

    The malformed-snapshot suite covers wrong types; this is the both-blank
    branch, where name and path strip to empty and the entry must be rejected
    instead of becoming a nameless, pathless module.
    """
    with pytest.raises(AddressSyncError) as exc_info:
        RuntimeModuleCatalog.from_result(
            _modules({"base": 0x1000, "size": 0x1000, "name": "   ", "path": "  "})
        )
    assert exc_info.value.code == "module_list_invalid"


@pytest.mark.parametrize(
    "payload",
    [
        ["not", "an", "object"],
        {"modules": "not-a-list", "count": 0},
    ],
)
def test_catalog_rejects_a_result_that_is_not_a_module_object(payload: object) -> None:
    """The x64dbg result shape itself is validated before its rows.

    A reply that is not an object, or whose ``modules`` is not an array, is the
    outermost hostile-input branch and must read as ``module_list_invalid``
    rather than an AttributeError on ``.get`` or iterating a string.
    """
    with pytest.raises(AddressSyncError) as exc_info:
        RuntimeModuleCatalog.from_result(payload)
    assert exc_info.value.code == "module_list_invalid"


def test_catalog_select_reports_not_found_and_identity_mismatch() -> None:
    """Explicit selection fails loudly on no match and on a partial match.

    ``select`` first filters by the primary key (here, base). No match is
    ``module_not_found``. A single match that then violates a second constraint
    the caller also supplied (a name that does not fit) is
    ``module_identity_mismatch`` -- the caller asked for a specific module and
    must not be handed a different one that merely shared the base.
    """
    catalog = RuntimeModuleCatalog.from_result(
        _modules({"base": 0x180000000, "size": 0x5000, "name": "a.dll", "path": r"C:\x\a.dll"})
    )
    with pytest.raises(AddressSyncError) as not_found:
        catalog.select(ModuleSelector(base=0xDEAD0000))
    assert not_found.value.code == "module_not_found"

    with pytest.raises(AddressSyncError) as name_mismatch:
        catalog.select(ModuleSelector(base=0x180000000, name="other.dll"))
    assert name_mismatch.value.code == "module_identity_mismatch"

    with pytest.raises(AddressSyncError) as path_mismatch:
        catalog.select(ModuleSelector(base=0x180000000, path=r"C:\wrong\a.dll"))
    assert path_mismatch.value.code == "module_identity_mismatch"


def test_rebased_mapping_rejects_a_non_pe_file(tmp_path: Path) -> None:
    """The selected module's file on disk is parsed and must be a real PE.

    ``_read_pe_image_layout`` reads the preferred base straight out of the
    optional header, so a file that is not a PE (or one the architecture probe
    rejects) must fail with ``module_file_invalid`` rather than letting the
    OSError/ValueError escape as an internal error.
    """
    module = tmp_path / "junk.dll"
    module.write_bytes(b"not a pe file at all" * 8)
    with pytest.raises(AddressSyncError) as exc_info:
        _rebased(module)
    assert exc_info.value.code == "module_file_invalid"


@pytest.mark.parametrize(
    "prepare",
    [
        pytest.param(lambda p: _write_pe(p, optional_size=40), id="truncated-optional-header"),
        pytest.param(lambda p: _write_pe(p, magic=0x10B), id="magic-mismatch"),
        pytest.param(lambda p: _write_pe(p, preferred_base=0), id="zero-image-base"),
    ],
)
def test_rebased_mapping_rejects_a_broken_optional_header(
    tmp_path: Path,
    prepare: Callable[[Path], None],
) -> None:
    """A PE whose optional header is short, mismatched, or zero-based is refused.

    Each of these is a distinct guard in ``_read_pe_image_layout`` reading a
    possibly-corrupt file: a header cut off before ImageBase, a magic that does
    not agree with the detected architecture, and a nonsensical zero image
    base. All must surface ``module_file_invalid`` rather than compute a bogus
    rebase from garbage bytes.
    """
    module = tmp_path / "broken.dll"
    prepare(module)
    with pytest.raises(AddressSyncError) as exc_info:
        _rebased(module)
    assert exc_info.value.code == "module_file_invalid"


def test_resolve_runtime_module_path_strips_the_nt_object_prefix(tmp_path: Path) -> None:
    """An x64dbg ``\\??\\`` device path still resolves to the real file.

    x64dbg reports module paths in NT object form. The resolver strips the
    ``\\??\\`` prefix before touching the filesystem; without that the file
    lookup would miss and a valid module would read as unavailable.
    """
    module = tmp_path / "real.dll"
    _write_pe(module)
    base = 0x7FF800000000
    mapping = build_rebased_module_mapping(
        _modules(
            {"base": base, "size": 0x5000, "name": "real.dll", "path": "\\??\\" + str(module)}
        ),
        _runtime_metadata(),
        ModuleSelector(base=base),
    )
    assert mapping.identity.path == str(module.resolve())


def test_resolve_runtime_module_path_rejects_empty_and_non_file(tmp_path: Path) -> None:
    """A blank path, or one that resolves to a directory, is not a module file.

    Both land on ``module_file_unavailable``: a whitespace-only path reports no
    file at all, and a path that resolves but is a directory is rejected by the
    ``is_file`` check rather than being opened as a PE.
    """
    base = 0x7FF800000000
    with pytest.raises(AddressSyncError) as empty:
        build_rebased_module_mapping(
            _modules({"base": base, "size": 0x5000, "name": "x.dll", "path": "   "}),
            _runtime_metadata(),
            ModuleSelector(base=base),
        )
    assert empty.value.code == "module_file_unavailable"

    directory = tmp_path / "moddir"
    directory.mkdir()
    with pytest.raises(AddressSyncError) as not_file:
        build_rebased_module_mapping(
            _modules({"base": base, "size": 0x5000, "name": "moddir", "path": str(directory)}),
            _runtime_metadata(),
            ModuleSelector(base=base),
        )
    assert not_file.value.code == "module_file_unavailable"


def test_catalog_and_rebased_mapping_serialise_their_public_shape(tmp_path: Path) -> None:
    """to_dict is the wire contract the JSON envelope hands to callers.

    The catalog and the rebased mapping serialise to fixed shapes downstream
    consumers read; pin the keys and the computed ``rebase_delta`` so a field
    rename or a delta sign flip cannot slip through unnoticed.
    """
    module = tmp_path / "real.dll"
    _write_pe(module, preferred_base=0x180000000, image_size=0x5000)
    base = 0x7FF800000000
    catalog = RuntimeModuleCatalog.from_result(
        _modules({"base": base, "size": 0x5000, "name": "real.dll", "path": str(module)})
    )
    assert catalog.to_dict() == {
        "modules": [{"base": base, "size": 0x5000, "name": "real.dll", "path": str(module)}],
        "count": 1,
    }

    mapping = build_rebased_module_mapping(
        _modules({"base": base, "size": 0x5000, "name": "real.dll", "path": str(module)}),
        _runtime_metadata(),
        ModuleSelector(base=base),
    )
    payload = mapping.to_dict()
    assert set(payload) == {"module", "match_basis", "rebase_delta", "preferred", "runtime"}
    assert payload["rebase_delta"] == base - 0x180000000
    assert payload["preferred"]["base"] == 0x180000000
    assert payload["runtime"]["base"] == base
