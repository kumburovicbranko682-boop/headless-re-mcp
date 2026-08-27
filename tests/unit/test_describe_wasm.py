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
    # The one export is surfaced by name and kind, not just counted.
    assert info["exports"] == [{"name": "add", "kind": "func"}]
    assert info["imports"] == []


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
    assert info["imports"] == [
        {"module": "env", "name": "log", "kind": "func"},
        {"module": "env", "name": "mem", "kind": "memory"},
    ]
    assert info["exports"] == [
        {"name": "memory", "kind": "memory"},
        {"name": "g", "kind": "global"},
    ]


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
    assert info["well_formed"] is True


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
