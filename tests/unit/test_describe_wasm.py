"""describe_wasm: tool-free WebAssembly identity facts (no wabt).

The WASM line otherwise depends entirely on wabt (wasm2wat / wasm-objdump), so
a module on a machine without it yields nothing. describe_wasm walks the
module's own section table for the version, present sections, vector counts, and
the import/export names that identify it -- the WASM analogue of describe_apk.
These cover the counts, the import/export name lists, the fail-closed behaviour
on a malformed tail, and that non-WASM inputs return an empty dict rather than
raising.
"""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import SessionRegistry, describe_wasm

# A real, hand-assembled ``add(i32,i32)->i32`` module (type + function + export
# + code sections). The same bytes the web gate feeds to wasm2wat.
_ADD_WASM = bytes.fromhex(
    "0061736d0100000001070160027f7f017f030201000707010361646400000a09010700200020016a0b"
)


def _leb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _leb(len(payload)) + payload


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _leb(len(raw)) + raw


def _module(sections: list[bytes]) -> bytes:
    return b"\x00asm" + struct.pack("<I", 1) + b"".join(sections)


def test_describe_wasm_reads_a_real_add_module(tmp_path: Path) -> None:
    path = tmp_path / "add.wasm"
    path.write_bytes(_ADD_WASM)
    info = describe_wasm(path)["wasm"]
    assert info["version"] == 1
    assert info["well_formed"] is True
    assert info["truncated"] is False
    assert info["type_count"] == 1
    assert info["function_count"] == 1
    assert info["export_count"] == 1
    assert set(info["section_counts"]) == {"type", "function", "export", "code"}
    assert info["has_start"] is False
    # No start section means no entry point to name -- None, not a guess.
    assert info["start_function"] is None
    # The one export is surfaced by name and kind, not just counted.
    assert info["exports"] == [{"name": "add", "kind": "func"}]
    assert info["imports"] == []
    # No producers custom section at all reads as None, not an empty record.
    assert info["producers"] is None
    # And no name section: a stripped module has no module name, no function
    # names, and a None count -- distinct from a present-but-empty name map.
    assert info["module_name"] is None
    assert info["function_name_count"] is None
    assert info["function_names"] == []


def test_describe_wasm_lists_import_and_export_names_with_kinds(tmp_path: Path) -> None:
    """The import/export names -- what the module needs and exposes -- are read.

    Each descriptor has a different shape (a func's type index, a memory's
    limits), so this also proves the walk advances past all of them to reach the
    next entry rather than stopping after the first.
    """
    imports = _leb(2)
    imports += _name("env") + _name("log") + bytes([0]) + _leb(0)  # func, type 0
    imports += _name("env") + _name("mem") + bytes([2]) + bytes([0]) + _leb(1)  # memory min 1
    exports = _leb(2)
    exports += _name("memory") + bytes([2]) + _leb(0)  # memory export
    exports += _name("g") + bytes([3]) + _leb(0)  # global export
    module = _module([_section(2, imports), _section(7, exports)])
    path = tmp_path / "linked.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["import_count"] == 2
    assert info["export_count"] == 2
    # A memory import carries its own size limits, so its entry is enriched with
    # min/max/shared; the other kinds keep the bare module/name/kind shape.
    assert info["imports"] == [
        {"module": "env", "name": "log", "kind": "func"},
        {"module": "env", "name": "mem", "kind": "memory", "min": 1, "max": None, "shared": False},
    ]
    assert info["exports"] == [
        {"name": "memory", "kind": "memory"},
        {"name": "g", "kind": "global"},
    ]
    # That imported memory is the module's whole linear-memory footprint.
    assert info["memories"] == [
        {"min": 1, "max": None, "shared": False, "imported": True}
    ]


def test_defined_memory_limits_with_a_maximum(tmp_path: Path) -> None:
    # A Memory section (id 5) memory whose flag bit 0 is set carries min then
    # max pages; the reader reports both as the module's own footprint.
    mem = _leb(1) + bytes([0x01]) + _leb(2) + _leb(16)  # one memory, min 2, max 16
    module = _module([_section(5, mem)])
    path = tmp_path / "mem.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["memory_count"] == 1
    assert info["memories"] == [{"min": 2, "max": 16, "shared": False, "imported": False}]


def test_shared_memory_is_flagged(tmp_path: Path) -> None:
    # A threads build marks its memory shared (flag bit 1) and always bounds it;
    # both the shared flag and the max survive.
    mem = _leb(1) + bytes([0x03]) + _leb(1) + _leb(1)  # shared, min == max == 1
    module = _module([_section(5, mem)])
    path = tmp_path / "shared.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["memories"] == [{"min": 1, "max": 1, "shared": True, "imported": False}]


def test_imported_and_defined_memories_are_both_reported(tmp_path: Path) -> None:
    # A module can both import a memory and define one; imported entries lead the
    # index space, so they lead the footprint list too, each tagged by origin.
    imports = _leb(1) + _name("env") + _name("mem") + bytes([2]) + bytes([0x00]) + _leb(4)
    defined = _leb(1) + bytes([0x01]) + _leb(8) + _leb(32)
    module = _module([_section(2, imports), _section(5, defined)])
    path = tmp_path / "both.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["memories"] == [
        {"min": 4, "max": None, "shared": False, "imported": True},
        {"min": 8, "max": 32, "shared": False, "imported": False},
    ]


def test_module_without_a_memory_reports_an_empty_footprint(tmp_path: Path) -> None:
    path = tmp_path / "add.wasm"
    path.write_bytes(_ADD_WASM)
    info = describe_wasm(path)["wasm"]
    assert info["memories"] == []


def test_a_truncated_memory_limit_stops_the_walk(tmp_path: Path) -> None:
    # The flag promises a maximum but the bytes end before it; the entry is not
    # emitted with a guessed max, and the reader does not read past the section.
    mem = _leb(1) + bytes([0x01]) + _leb(2)  # max missing
    module = _module([_section(5, mem)])
    path = tmp_path / "bad.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["memories"] == []


def test_start_function_reports_the_entry_index(tmp_path: Path) -> None:
    # The start section names the function run automatically at instantiation
    # -- the WASM entry point, e_entry's analogue. With no name section only
    # the index (the one identity the binary format guarantees) is reported.
    module = _module([_section(8, _leb(2))])
    path = tmp_path / "start.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["has_start"] is True
    assert info["start_function"] == {"index": 2}


def test_start_function_resolves_its_debug_name(tmp_path: Path) -> None:
    # An unstripped module names its functions; the entry point picks up its
    # source-level name from the same map wasm2wat renders as (start $name).
    # Two names in the map prove the resolution matches on index, not position.
    module = _module(
        [
            _section(8, _leb(1)),
            _name_section([_name_subsec(1, _func_name_map([(0, "init"), (1, "wasm_ctor")]))]),
        ]
    )
    path = tmp_path / "named_start.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["start_function"] == {"index": 1, "name": "wasm_ctor"}


def test_a_start_index_outside_the_name_map_stays_nameless(tmp_path: Path) -> None:
    # The name map names other functions but not the entry point; the index is
    # still a fact, a name is not invented from the wrong entry.
    module = _module(
        [
            _section(8, _leb(7)),
            _name_section([_name_subsec(1, _func_name_map([(0, "init")]))]),
        ]
    )
    path = tmp_path / "unnamed_start.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["start_function"] == {"index": 7}


def test_an_empty_start_section_keeps_only_its_presence(tmp_path: Path) -> None:
    # A start section with no body is malformed for this one fact: the section
    # exists (has_start) but the index read must not cross into the next
    # section's bytes, so no entry point is reported.
    module = _module([_section(8, b""), _section(1, _leb(0))])
    path = tmp_path / "empty_start.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["has_start"] is True
    assert info["start_function"] is None


def test_describe_wasm_surfaces_every_vector_count_and_custom_name(tmp_path: Path) -> None:
    module = _module(
        [
            _section(1, _leb(3) + b"\x00" * 6),  # type_count = 3
            _section(2, _leb(2) + b"\x00" * 4),  # import_count = 2
            _section(3, _leb(4) + b"\x00" * 4),  # function_count = 4
            _section(4, _leb(1) + b"\x00" * 3),  # table_count = 1
            _section(5, _leb(1) + b"\x00" * 2),  # memory_count = 1
            _section(6, _leb(5) + b"\x00" * 5),  # global_count = 5
            _section(7, _leb(7) + b"\x00" * 7),  # export_count = 7
            _section(8, _leb(0)),  # start present
            _section(0, _leb(len(b"producers")) + b"producers" + b"\x00"),  # custom
        ]
    )
    path = tmp_path / "full.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["type_count"] == 3
    assert info["import_count"] == 2
    assert info["function_count"] == 4
    assert info["table_count"] == 1
    assert info["memory_count"] == 1
    assert info["global_count"] == 5
    assert info["export_count"] == 7
    assert info["has_start"] is True
    assert info["custom_sections"] == ["producers"]
    # The section is present but declares zero fields: an empty record, which
    # is distinct from the None an absent section reads as.
    assert info["producers"] == {}
    assert info["well_formed"] is True


def _producers_section(fields: list[tuple[str, list[tuple[str, str]]]]) -> bytes:
    body = _name("producers") + _leb(len(fields))
    for field, values in fields:
        body += _name(field) + _leb(len(values))
        for name, version in values:
            body += _name(name) + _name(version)
    return _section(0, body)


def test_describe_wasm_reads_the_producers_toolchain(tmp_path: Path) -> None:
    """The producers section names what built the module -- rustc, bindgen, ...

    This is the WASM analogue of an ELF .comment: the first triage fact about
    provenance, and exactly what rustc/wasm-bindgen and Emscripten emit.
    """
    module = _module(
        [
            _producers_section(
                [
                    ("language", [("Rust", "")]),
                    ("processed-by", [("rustc", "1.76.0"), ("wasm-bindgen", "0.2.92")]),
                ]
            )
        ]
    )
    path = tmp_path / "built.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["producers"] == {
        "language": ["Rust"],  # an empty version joins away rather than dangling
        "processed-by": ["rustc 1.76.0", "wasm-bindgen 0.2.92"],
    }
    assert info["well_formed"] is True


def _name_subsec(sub_id: int, payload: bytes) -> bytes:
    return bytes([sub_id]) + _leb(len(payload)) + payload


def _name_section(subsections: list[bytes]) -> bytes:
    return _section(0, _name("name") + b"".join(subsections))


def _func_name_map(entries: list[tuple[int, str]], declared: int | None = None) -> bytes:
    body = _leb(declared if declared is not None else len(entries))
    for index, fname in entries:
        body += _leb(index) + _name(fname)
    return body


def test_describe_wasm_reads_the_debug_names(tmp_path: Path) -> None:
    """The name section's module and function names -- WASM's debug symbols.

    An unstripped module carries its source-level function names here (not in
    exports, which only name the public interface); reading them tool-free is
    the WASM analogue of the ELF reader's stripped flag plus symbol names.
    """
    module = _module(
        [
            _name_section(
                [
                    _name_subsec(0, _name("demo")),
                    _name_subsec(1, _func_name_map([(0, "host_log"), (1, "add_impl")])),
                    # Local names (id 2): present in real wat2wasm output and
                    # skipped by size, proving the walk is not derailed by
                    # subsections it does not read.
                    _name_subsec(2, _leb(1) + _leb(0) + _leb(0)),
                ]
            )
        ]
    )
    path = tmp_path / "named.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["module_name"] == "demo"
    assert info["function_name_count"] == 2
    assert info["function_names"] == [
        {"index": 0, "name": "host_log"},
        {"index": 1, "name": "add_impl"},
    ]
    assert info["custom_sections"] == ["name"]
    assert info["well_formed"] is True


def test_function_names_without_a_module_name(tmp_path: Path) -> None:
    # rustc and clang commonly emit function names with no module-name
    # subsection at all; each fact stands alone.
    module = _module([_name_section([_name_subsec(1, _func_name_map([(3, "main")]))])])
    path = tmp_path / "funcs_only.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["module_name"] is None
    assert info["function_name_count"] == 1
    assert info["function_names"] == [{"index": 3, "name": "main"}]


def test_name_map_with_a_hostile_count_keeps_what_parsed(tmp_path: Path) -> None:
    # The map declares 1000 names but carries two; the reader keeps the real
    # pairs, reports the declared count as the claim it is, and does not
    # allocate for the lie -- the same posture as the producers reader.
    module = _module(
        [
            _name_section(
                [_name_subsec(1, _func_name_map([(0, "a"), (1, "b")], declared=1000))]
            ),
            _section(1, _leb(3) + b"\x00" * 6),
        ]
    )
    path = tmp_path / "liar_names.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["function_name_count"] == 1000
    assert info["function_names"] == [{"index": 0, "name": "a"}, {"index": 1, "name": "b"}]
    assert info["type_count"] == 3  # the section after the liar still parsed


def test_a_malformed_name_subsection_keeps_what_parsed(tmp_path: Path) -> None:
    # The module name parses, then a subsection declares a size running past
    # the section end: the walk stops there without poisoning the module-level
    # facts -- custom section contents never flip well_formed.
    module = _module(
        [
            _name_section(
                [_name_subsec(0, _name("demo")), bytes([1]) + _leb(9999)]
            ),
            _section(1, _leb(2) + b"\x00" * 4),
        ]
    )
    path = tmp_path / "torn_names.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["module_name"] == "demo"
    assert info["function_name_count"] is None
    assert info["function_names"] == []
    assert info["type_count"] == 2
    assert info["well_formed"] is True


def test_producers_with_a_hostile_count_keeps_what_parsed(tmp_path: Path) -> None:
    # The field declares 1000 values but carries one; the reader keeps the real
    # pair and stops rather than misreading past the section (or allocating for
    # the claim), and the rest of the module walk is unaffected.
    body = _name("producers") + _leb(1) + _name("processed-by") + _leb(1000)
    body += _name("clang") + _name("17.0.0")
    module = _module([_section(0, body), _section(1, _leb(3) + b"\x00" * 6)])
    path = tmp_path / "liar.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["producers"] == {"processed-by": ["clang 17.0.0"]}
    assert info["type_count"] == 3  # the section after the liar still parsed


def test_describe_wasm_is_fail_closed_on_a_malformed_tail(tmp_path: Path) -> None:
    # A valid type section, then an export section whose declared payload runs
    # past the end of the file. The walk must stop and report not-well-formed.
    module = _module([_section(1, _leb(1) + b"\x00")]) + bytes([7]) + _leb(99)
    path = tmp_path / "bad.wasm"
    path.write_bytes(module)
    info = describe_wasm(path)["wasm"]
    assert info["well_formed"] is False
    assert info["type_count"] == 1
    # The unreadable export section contributed no count.
    assert info["export_count"] is None


def test_describe_wasm_ignores_a_non_wasm_file(tmp_path: Path) -> None:
    path = tmp_path / "app.js"
    path.write_bytes(b"export const x = 1;\n")
    assert describe_wasm(path) == {}


def test_describe_wasm_ignores_a_truncated_magic(tmp_path: Path) -> None:
    path = tmp_path / "tiny.wasm"
    path.write_bytes(b"\x00as")
    assert describe_wasm(path) == {}


def test_web_session_over_a_local_wasm_carries_the_facts(tmp_path: Path) -> None:
    """Creating a session on a local .wasm attaches the identity metadata."""
    path = tmp_path / "add.wasm"
    path.write_bytes(_ADD_WASM)
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.WEB
    assert session.metadata["wasm"]["function_count"] == 1
    assert session.metadata["wasm"]["export_count"] == 1


def test_web_session_over_a_js_asset_has_no_wasm_facts(tmp_path: Path) -> None:
    """A JS asset gets its own facts (describe_js), never a spurious wasm block."""
    path = tmp_path / "app.js"
    path.write_bytes(b"export const x = 1;\n")
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.WEB
    assert "wasm" not in session.metadata
    assert "js" in session.metadata
