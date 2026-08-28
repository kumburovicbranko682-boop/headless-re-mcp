"""r2.cfg builds a function's control-flow graph: basic blocks and branch edges.

The native twin of static.cfg. Where r2.disasm_function reads a function as a
flat op list, this reads its shape. These tests patch ``R2Client.run`` so the
real ``cfg`` logic runs against canned ``afij`` (function bounds) then ``afbj``
(basic blocks) output -- the two-array stream r2 prints for ``aa; afij; afbj`` --
with per-block ``jump``/``fail`` successors, the fields r2 5.x/6.x emit.
"""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import (
    R2Client,
    R2Error,
    _require_allowed_command,
    _switch_targets,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.r2 import build_r2_tools

# A function with a conditional, a merge, and a loop:
#   B0 branches to B2 (taken) or B1 (fall-through); both reach the loop header
#   B3; B3 enters the body B4 (which loops back to B3) or exits to the return B5.
FUNC = 0x1000
_AFIJ: list[dict[str, Any]] = [
    {"offset": FUNC, "name": "sym.classify", "size": 0x65, "nbbs": 6}
]
_AFBJ: list[dict[str, Any]] = [
    {"addr": 0x1000, "size": 0x10, "jump": 0x1030, "fail": 0x1010, "ninstr": 7},
    {"addr": 0x1010, "size": 0x08, "jump": 0x1040, "fail": None, "ninstr": 2},
    {"addr": 0x1030, "size": 0x08, "jump": 0x1040, "fail": None, "ninstr": 2},
    {"addr": 0x1040, "size": 0x08, "jump": 0x1050, "fail": 0x1060, "ninstr": 3},
    {"addr": 0x1050, "size": 0x08, "jump": 0x1040, "fail": None, "ninstr": 2},
    {"addr": 0x1060, "size": 0x05, "jump": None, "fail": None, "ninstr": 3},
]


def _tool_docstring(name: str) -> str:
    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


def _patch_run(monkeypatch: Any, afij: Any, afbj: Any) -> list[list[str]]:
    """Make R2Client.run echo the afij array then the afbj array as one stream."""
    seen: list[list[str]] = []
    raw = "[x] Analyze all functions\n" + json.dumps(afij) + "\n" + json.dumps(afbj)

    def _run(
        self: R2Client, binary: Path, commands: list[str], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        del self, binary, timeout
        seen.append(list(commands))
        return {"raw": raw, "commands": list(commands)}

    monkeypatch.setattr(R2Client, "run", _run)
    return seen


def _bin(tmp_path: Path) -> Path:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00" * 64)
    return binary


def _edge(result: dict[str, Any], src: int, dst: int) -> dict[str, Any] | None:
    return next(
        (e for e in result["edges"] if e["src"] == src and e["dst"] == dst), None
    )


def test_nodes_carry_block_geometry(tmp_path: Path, monkeypatch: Any) -> None:
    """Every basic block becomes a node with addr, size, end, ninstr and address."""
    _patch_run(monkeypatch, _AFIJ, _AFBJ)
    result = R2Client(None).cfg(_bin(tmp_path), FUNC)

    assert result["node_count"] == 6
    starts = [n["addr"] for n in result["nodes"]]
    assert starts == [0x1000, 0x1010, 0x1030, 0x1040, 0x1050, 0x1060]
    b0 = result["nodes"][0]
    assert b0["size"] == 0x10
    assert b0["end"] == 0x1010
    assert b0["ninstr"] == 7
    assert b0["address"]["va"] == 0x1000


def test_a_conditional_block_has_both_a_jump_and_a_fail_edge(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """B0 branches: jump is the taken target, fail the fall-through."""
    _patch_run(monkeypatch, _AFIJ, _AFBJ)
    result = R2Client(None).cfg(_bin(tmp_path), FUNC)

    taken = _edge(result, 0x1000, 0x1030)
    fall = _edge(result, 0x1000, 0x1010)
    assert taken is not None and taken["kind"] == "jump"
    assert fall is not None and fall["kind"] == "fail"
    assert taken["dst_address"]["va"] == 0x1030


def test_an_unconditional_block_has_a_single_jump_edge(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """B1 flows straight to the merge with no fail edge."""
    _patch_run(monkeypatch, _AFIJ, _AFBJ)
    result = R2Client(None).cfg(_bin(tmp_path), FUNC)

    out = [e for e in result["edges"] if e["src"] == 0x1010]
    assert len(out) == 1
    assert out[0]["dst"] == 0x1040
    assert out[0]["kind"] == "jump"


def test_the_loop_back_edge_is_present(tmp_path: Path, monkeypatch: Any) -> None:
    """B4 jumps back to the loop header B3 -- the edge that makes it a loop."""
    _patch_run(monkeypatch, _AFIJ, _AFBJ)
    result = R2Client(None).cfg(_bin(tmp_path), FUNC)

    back = _edge(result, 0x1050, 0x1040)
    assert back is not None and back["kind"] == "jump"
    # And the loop header's own conditional: continue into the body or exit.
    assert _edge(result, 0x1040, 0x1050)["kind"] == "jump"
    assert _edge(result, 0x1040, 0x1060)["kind"] == "fail"


def test_the_return_block_has_no_out_edges(tmp_path: Path, monkeypatch: Any) -> None:
    """B5 returns, so nothing flows out of it."""
    _patch_run(monkeypatch, _AFIJ, _AFBJ)
    result = R2Client(None).cfg(_bin(tmp_path), FUNC)

    assert [e for e in result["edges"] if e["src"] == 0x1060] == []
    assert result["edge_count"] == 7


def test_the_function_node_is_reported(tmp_path: Path, monkeypatch: Any) -> None:
    """afij names the containing function with its start, size and block count."""
    _patch_run(monkeypatch, _AFIJ, _AFBJ)
    result = R2Client(None).cfg(_bin(tmp_path), FUNC)

    func = result["function"]
    assert func is not None
    assert func["name"] == "sym.classify"
    assert func["addr"] == FUNC
    assert func["size"] == 0x65
    assert func["nbbs"] == 6
    assert func["address"]["va"] == FUNC


def test_edges_are_sorted_and_deduplicated(tmp_path: Path, monkeypatch: Any) -> None:
    """The edge list is deterministic: sorted by (src, dst, kind)."""
    _patch_run(monkeypatch, _AFIJ, _AFBJ)
    result = R2Client(None).cfg(_bin(tmp_path), FUNC)

    keys = [(e["src"], e["dst"], e["kind"]) for e in result["edges"]]
    assert keys == sorted(keys)


def test_switch_op_cases_become_switch_edges(tmp_path: Path, monkeypatch: Any) -> None:
    """A jump table fans out: each case is a switch edge, the default its own kind.

    The plain jump/fail pair cannot express a fan-out, so a switch would lose
    every arm but one without reading switch_op. A duplicate case target collapses.
    """
    afij = [{"offset": 0x2000, "name": "sym.pick", "size": 0x60, "nbbs": 5}]
    afbj = [
        {
            "addr": 0x2000,
            "size": 0x10,
            "jump": None,
            "fail": None,
            "ninstr": 4,
            "switch_op": {
                "cases": [
                    {"jump": 0x2020},
                    {"jump": 0x2030},
                    {"addr": 0x2040},
                    {"jump": 0x2020},  # duplicate case target
                ],
                "def": 0x2050,
            },
        },
        {"addr": 0x2020, "size": 0x08, "jump": 0x2050, "fail": None, "ninstr": 2},
        {"addr": 0x2030, "size": 0x08, "jump": 0x2050, "fail": None, "ninstr": 2},
        {"addr": 0x2040, "size": 0x08, "jump": 0x2050, "fail": None, "ninstr": 2},
        {"addr": 0x2050, "size": 0x05, "jump": None, "fail": None, "ninstr": 2},
    ]
    _patch_run(monkeypatch, afij, afbj)
    result = R2Client(None).cfg(_bin(tmp_path), 0x2000)

    from_switch = sorted(
        (e["dst"], e["kind"]) for e in result["edges"] if e["src"] == 0x2000
    )
    assert from_switch == [
        (0x2020, "switch"),
        (0x2030, "switch"),
        (0x2040, "switch"),
        (0x2050, "switch_default"),
    ]


def test_switch_targets_helper_ignores_unshaped_input() -> None:
    """The switch reader must tolerate a missing or oddly-shaped switch_op."""
    assert _switch_targets(None) == []
    assert _switch_targets({"cases": "not-a-list"}) == []
    assert _switch_targets({"cases": [{"no_target": 1}]}) == []
    assert _switch_targets({"cases": [{"jump": 0x10}]}) == [(0x10, "switch")]


def test_an_address_outside_every_function_is_a_clean_empty_graph(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """afij/afbj print empty arrays off a function; report an empty graph, not a fault."""
    _patch_run(monkeypatch, [], [])
    result = R2Client(None).cfg(_bin(tmp_path), 0x9999)

    assert result["function"] is None
    assert result["nodes"] == []
    assert result["edges"] == []
    assert result["node_count"] == 0
    assert result["edge_count"] == 0
    assert result["parsed"] is True


def test_the_r2_6x_addr_key_names_the_function_start(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """r2 6.x keys the function start under ``addr`` where 5.x used ``offset``."""
    afij = [{"addr": FUNC, "name": "sym.classify", "size": 0x20, "nbbs": 1}]
    afbj = [{"addr": FUNC, "size": 0x10, "jump": None, "fail": None, "ninstr": 3}]
    _patch_run(monkeypatch, afij, afbj)
    result = R2Client(None).cfg(_bin(tmp_path), FUNC)

    assert result["function"]["addr"] == FUNC
    assert result["nodes"][0]["addr"] == FUNC


def test_a_larger_function_is_truncated_and_disclosed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A function with more blocks than the cap is trimmed, said out loud.

    Edges are built only from the kept nodes, so "this is the whole CFG" is never
    a wrong read on a crafted function.
    """
    monkeypatch.setattr("headless_re_mcp.backends.r2.client._MAX_ITEMS", 2)
    _patch_run(monkeypatch, _AFIJ, _AFBJ)
    result = R2Client(None).cfg(_bin(tmp_path), FUNC)

    assert result["node_count"] == 2
    assert result["nodes_truncated"] is True
    assert result["nodes_total"] == 6
    assert result["nodes_limit"] == 2


def test_the_commands_on_the_wire_are_aa_afij_afbj(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """One analysis pass, then the function bounds, then its basic blocks."""
    seen = _patch_run(monkeypatch, _AFIJ, _AFBJ)
    R2Client(None).cfg(_bin(tmp_path), FUNC)
    assert seen[0] == ["aa", f"afij @ {FUNC}", f"afbj @ {FUNC}"]


def test_afbj_is_whitelisted_but_only_with_a_numeric_seek() -> None:
    """The command gate must admit afbj with a hex/decimal seek and refuse the rest."""
    _require_allowed_command("afbj @ 0x1000")
    _require_allowed_command("afbj @ 4096")
    for bad in ("afbj @ main", "afbj", "afbj @", "afbj @ 0x10; i", "afxj @ 0x10"):
        with pytest.raises(R2Error) as excinfo:
            _require_allowed_command(bad)
        assert excinfo.value.code == "invalid_params"


def test_a_negative_address_is_invalid_params(tmp_path: Path) -> None:
    """A negative address is rejected before r2 is ever run."""
    with pytest.raises(R2Error) as excinfo:
        R2Client(None).cfg(_bin(tmp_path), -1)
    assert excinfo.value.code == "invalid_params"


def test_cfg_service_wires_through_to_a_session(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """End-to-end through AnalysisService with the radare2 backend tag."""
    _patch_run(monkeypatch, _AFIJ, _AFBJ)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        result = service.r2_cfg(session_id, FUNC)
        assert result.ok, result.error
        assert result.data is not None
        assert result.meta.get("backend") == "radare2"
        assert result.data["function"]["name"] == "sym.classify"
        assert result.data["node_count"] == 6
        assert result.data["edge_count"] == 7
    finally:
        service.close_all()


def test_docstring_frames_it_as_the_native_cfg_reader() -> None:
    """The docstring must tell an agent it reads blocks and branch edges via afbj."""
    doc = _tool_docstring("r2.cfg")
    assert "nodes" in doc
    assert "edges" in doc
    assert "afbj" in doc
    assert "jump" in doc
    assert "fail" in doc
    assert "static.cfg" in doc
