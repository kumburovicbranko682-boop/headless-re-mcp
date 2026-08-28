"""radare2 6.x keys addresses ``addr``; the mapping must still resolve them.

Every other address-mapping test in this suite feeds ``enrich_r2_payload``
entries keyed ``offset`` -- the shape old radare2 emitted. Current radare2
(6.2.0, verified live on Linux) emits ``addr`` instead, with no ``offset`` and
no ``vaddr``, for both ``aflj`` (functions) and ``pdj`` (disassembly). The
production priority tuple in ``_item_va`` handles that, but until this file no
test exercised it: someone "simplifying" the tuple down to ``offset``/``vaddr``
would have silently zeroed out every function and instruction address on a
modern r2 install while the whole suite stayed green.

The fixtures below are trimmed captures of real ``r2 -q0`` output for a small
non-PE (ELF) binary. What matters and is preserved exactly: which address keys
are present (``addr``) and which are absent (``offset``, ``vaddr``), plus the
neighbouring numeric fields (``minaddr``, ``maxaddr``, ``fcn_addr``,
``fcn_last``) that must NOT be mistaken for the entry's own address.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.r2.mapping import enrich_r2_payload

# aflj on an ELF, r2 6.2.0: the function's entry lives in ``addr``. minaddr and
# maxaddr bracket the body and must not win over addr.
_AFLJ_620 = [
    {
        "addr": 4560,
        "name": "main",
        "size": 109,
        "is-pure": "false",
        "realsz": 109,
        "noreturn": False,
        "stackframe": 16,
        "calltype": "amd64",
        "cost": 40,
        "cc": 2,
        "bits": 64,
        "type": "sym",
        "nbbs": 3,
        "is-lineal": False,
        "ninstrs": 30,
        "edges": 3,
        "ebbs": 1,
        "signature": "int main (int argc, char **argv);",
        "minaddr": 4560,
        "maxaddr": 4669,
    },
    {
        "addr": 4208,
        "name": "sym.imp.puts",
        "size": 10,
        "realsz": 10,
        "type": "sym",
        "minaddr": 4208,
        "maxaddr": 4218,
    },
]

# pdj on the same binary: each instruction's own address is ``addr``; fcn_addr
# repeats the containing function's entry (4560) on every row, so an entry-vs-
# function mixup shows up as the second instruction mapping to 4560.
_PDJ_620 = [
    {
        "addr": 4560,
        "esil": "",
        "refptr": 0,
        "fcn_addr": 4560,
        "fcn_last": 4665,
        "size": 4,
        "opcode": "endbr64",
        "disasm": "endbr64",
        "bytes": "f30f1efa",
        "family": "cpu",
        "type": "null",
        "reloc": False,
        "flags": ["main", "sym.main"],
    },
    {
        "addr": 4564,
        "esil": "rbp,8,rsp,-,=[8],8,rsp,-=",
        "refptr": 0,
        "fcn_addr": 4560,
        "fcn_last": 4666,
        "size": 1,
        "opcode": "push rbp",
        "disasm": "push rbp",
        "bytes": "55",
        "family": "cpu",
        "type": "rpush",
        "reloc": False,
    },
]


def _enrich(parsed: list[dict[str, Any]], command: str, tmp_path: Path) -> dict[str, Any]:
    # A real ELF prefix so pe_preferred_base sees a non-PE and reports no
    # image_base -- addresses must come out as bare {"va": ...}.
    binary = tmp_path / "t.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    return enrich_r2_payload({"raw": json.dumps(parsed), "commands": [command]}, binary=binary)


def test_functions_keyed_addr_map_to_their_entry(tmp_path: Path) -> None:
    out = _enrich(_AFLJ_620, "aflj", tmp_path)
    assert out["parsed"] is True and out["count"] == 2
    main, puts = out["items"]
    assert main["address"] == {"va": 4560}
    assert puts["address"] == {"va": 4208}
    # The rest of the row rides along untouched.
    assert main["name"] == "main" and main["size"] == 109


def test_instructions_keyed_addr_map_per_instruction_not_per_function(
    tmp_path: Path,
) -> None:
    out = _enrich(_PDJ_620, "pdj 2 @ 4560", tmp_path)
    first, second = out["items"]
    assert first["address"] == {"va": 4560}
    # The tell: 4564 is this instruction, 4560 is its fcn_addr. Mapping the
    # function's entry here means the priority tuple regressed.
    assert second["address"] == {"va": 4564}
    assert second["disasm"] == "push rbp"


def test_legacy_offset_keyed_entries_still_map(tmp_path: Path) -> None:
    # Old radare2 keyed the same listings ``offset``; both generations must
    # resolve so a pinned r2 version in one environment does not break another.
    legacy = [{"offset": 4560, "name": "main", "size": 109}]
    out = _enrich(legacy, "aflj", tmp_path)
    assert out["items"][0]["address"] == {"va": 4560}


def test_neighbouring_numeric_fields_never_stand_in_for_the_address(
    tmp_path: Path,
) -> None:
    # An entry with fcn_addr/minaddr/maxaddr but no recognised address key gets
    # no address at all -- better absent than a plausible wrong one.
    stray = [{"fcn_addr": 4560, "minaddr": 4560, "maxaddr": 4669, "name": "x"}]
    out = _enrich(stray, "aflj", tmp_path)
    assert "address" not in out["items"][0]
