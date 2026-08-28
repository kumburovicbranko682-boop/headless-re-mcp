"""r2.callgraph collapses a function to its direct callees and callers.

The native twin of apk.method_xrefs: where r2.xrefs answers one address and
r2.disasm_function reads a whole body, this names the functions a routine calls
and the functions that call it. These tests patch ``R2Client.run`` so the real
``callgraph`` logic runs against a canned ``aflj`` array -- the one-array shape
r2 prints for ``aa; aflj`` -- with per-function ``callrefs`` (outbound) and
``codexrefs`` (inbound), the exact fields r2 5.x/6.x emit.
"""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.r2 import build_r2_tools

# A small program: main -> run -> {helper, other} -> leaf, plus main -> printf.
# Each function names its outbound calls (callrefs: addr=target, at=call site)
# and inbound calls (codexrefs: addr=the calling instruction, at=this start).
MAIN = 0x1000
RUN = 0x1100
HELPER = 0x1200
OTHER = 0x1300
LEAF = 0x1400
PRINTF = 0x2000

_AFLJ: list[dict[str, Any]] = [
    {
        "offset": MAIN,
        "name": "main",
        "size": 0x40,
        "callrefs": [
            {"addr": RUN, "type": "CALL", "at": 0x1010},
            {"addr": PRINTF, "type": "CALL", "at": 0x1020},
        ],
        "codexrefs": [],
    },
    {
        "offset": RUN,
        "name": "sym.run",
        "size": 0x30,
        "callrefs": [
            {"addr": HELPER, "type": "CALL", "at": 0x1110},
            {"addr": OTHER, "type": "CALL", "at": 0x1120},
        ],
        "codexrefs": [{"addr": 0x1010, "type": "CALL", "at": RUN}],
    },
    {
        "offset": HELPER,
        "name": "sym.helper",
        "size": 0x20,
        "callrefs": [{"addr": LEAF, "type": "CALL", "at": 0x1210}],
        "codexrefs": [{"addr": 0x1110, "type": "CALL", "at": HELPER}],
    },
    {
        "offset": OTHER,
        "name": "sym.other",
        "size": 0x20,
        # A tail call reaches leaf with a jmp, which r2 tags CODE, not CALL.
        "callrefs": [{"addr": LEAF, "type": "CODE", "at": 0x1310}],
        "codexrefs": [{"addr": 0x1120, "type": "CALL", "at": OTHER}],
    },
    {
        "offset": LEAF,
        "name": "sym.leaf",
        "size": 0x10,
        "callrefs": [],
        "codexrefs": [
            {"addr": 0x1210, "type": "CALL", "at": LEAF},
            {"addr": 0x1310, "type": "CODE", "at": LEAF},
        ],
    },
    {
        "offset": PRINTF,
        "name": "sym.imp.printf",
        "size": 0x6,
        "callrefs": [],
        "codexrefs": [{"addr": 0x1020, "type": "CALL", "at": PRINTF}],
    },
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


def _patch_run(monkeypatch: Any, aflj: Any) -> list[list[str]]:
    """Make R2Client.run echo the aflj array as the one stream ``aa; aflj`` prints."""
    seen: list[list[str]] = []
    raw = "[x] Analyze all flags\n" + json.dumps(aflj)

    def _run(
        self: R2Client, binary: Path, commands: list[str], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        del self, binary, timeout
        seen.append(list(commands))
        return {"raw": raw, "commands": list(commands)}

    monkeypatch.setattr(R2Client, "run", _run)
    return seen


def _edges(result: dict[str, Any], direction: str | None = None) -> list[dict[str, Any]]:
    items = result["edges"]
    if direction is None:
        return list(items)
    return [e for e in items if e["direction"] == direction]


def _bin(tmp_path: Path) -> Path:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00" * 64)
    return binary


def test_callees_name_the_functions_a_routine_calls(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """run calls helper and other; each edge carries the resolved target + site."""
    _patch_run(monkeypatch, _AFLJ)
    result = R2Client(None).callgraph(_bin(tmp_path), RUN, direction="callees")

    callees = _edges(result, "callee")
    names = {e["name"] for e in callees}
    assert names == {"sym.helper", "sym.other"}
    helper = next(e for e in callees if e["name"] == "sym.helper")
    assert helper["addr"] == HELPER
    assert helper["address"]["va"] == HELPER
    assert helper["call_site_va"] == 0x1110
    assert helper["call_site"]["va"] == 0x1110
    assert helper["type"] == "CALL"
    assert helper["resolved"] is True


def test_callers_name_the_functions_that_call_a_routine(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """run is called only by main; the caller's call site is the calling insn."""
    _patch_run(monkeypatch, _AFLJ)
    result = R2Client(None).callgraph(_bin(tmp_path), RUN, direction="callers")

    callers = _edges(result, "caller")
    assert len(callers) == 1
    main = callers[0]
    assert main["name"] == "main"
    assert main["addr"] == MAIN
    assert main["call_site_va"] == 0x1010
    assert main["resolved"] is True


def test_both_returns_callees_then_callers_with_direction_totals(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """direction=both merges the two, and the totals count each side of the graph."""
    _patch_run(monkeypatch, _AFLJ)
    result = R2Client(None).callgraph(_bin(tmp_path), RUN, direction="both")

    assert result["direction"] == "both"
    assert result["callees_total"] == 2
    assert result["callers_total"] == 1
    assert result["total"] == 3
    # Sorted deterministically: callee edges (by target) precede caller edges.
    dirs = [e["direction"] for e in result["edges"]]
    assert dirs == ["callee", "callee", "caller"]


def test_the_node_function_is_reported(tmp_path: Path, monkeypatch: Any) -> None:
    """The resolved function carries name, start, size and a mapped address."""
    _patch_run(monkeypatch, _AFLJ)
    result = R2Client(None).callgraph(_bin(tmp_path), RUN, direction="both")

    func = result["function"]
    assert func is not None
    assert func["name"] == "sym.run"
    assert func["addr"] == RUN
    assert func["size"] == 0x30
    assert func["address"]["va"] == RUN


def test_an_address_inside_the_body_resolves_to_its_function(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """address need not be the entry: a byte mid-function still names the function."""
    _patch_run(monkeypatch, _AFLJ)
    result = R2Client(None).callgraph(_bin(tmp_path), RUN + 8, direction="callees")

    assert result["function"]["name"] == "sym.run"
    assert {e["name"] for e in _edges(result, "callee")} == {"sym.helper", "sym.other"}


def test_a_leaf_has_callers_but_no_callees(tmp_path: Path, monkeypatch: Any) -> None:
    """leaf is reached from helper and other and calls nothing itself."""
    _patch_run(monkeypatch, _AFLJ)
    result = R2Client(None).callgraph(_bin(tmp_path), LEAF, direction="both")

    assert result["callees_total"] == 0
    assert result["callers_total"] == 2
    assert {e["name"] for e in _edges(result, "caller")} == {"sym.helper", "sym.other"}


def test_an_import_thunk_target_resolves_to_its_name(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A call into sym.imp.printf resolves like any other function edge."""
    _patch_run(monkeypatch, _AFLJ)
    result = R2Client(None).callgraph(_bin(tmp_path), MAIN, direction="callees")

    printf = next(e for e in _edges(result, "callee") if e["addr"] == PRINTF)
    assert printf["name"] == "sym.imp.printf"
    assert printf["resolved"] is True


def test_the_edge_type_is_preserved(tmp_path: Path, monkeypatch: Any) -> None:
    """other tail-calls leaf with a jmp, so that callee edge is CODE, not CALL."""
    _patch_run(monkeypatch, _AFLJ)
    result = R2Client(None).callgraph(_bin(tmp_path), OTHER, direction="callees")

    leaf = next(e for e in _edges(result, "callee") if e["name"] == "sym.leaf")
    assert leaf["type"] == "CODE"


def test_an_unresolved_target_keeps_its_raw_address(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A call to an address inside no function is reported, flagged unresolved.

    The edge still carries the raw target so an agent can r2.resolve it, but
    ``resolved`` is false and the name is empty (every aflj function has a name).
    """
    aflj = [
        {
            "offset": MAIN,
            "name": "main",
            "size": 0x40,
            "callrefs": [{"addr": 0x9000, "type": "CALL", "at": 0x1010}],
            "codexrefs": [],
        }
    ]
    _patch_run(monkeypatch, aflj)
    result = R2Client(None).callgraph(_bin(tmp_path), MAIN, direction="callees")

    edge = _edges(result, "callee")[0]
    assert edge["addr"] == 0x9000
    assert edge["name"] == ""
    assert edge["resolved"] is False
    assert edge["address"]["va"] == 0x9000


def test_an_address_outside_every_function_is_a_clean_empty_graph(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A data address has no node; function is null and edges are empty, not a fault."""
    _patch_run(monkeypatch, _AFLJ)
    result = R2Client(None).callgraph(_bin(tmp_path), 0x9999, direction="both")

    assert result["function"] is None
    assert result["edges"] == []
    assert result["count"] == 0
    assert result["total"] == 0
    assert result["parsed"] is True


def test_an_empty_function_list_parses_to_nothing(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A binary r2 found no functions in is parsed False with a null node."""
    _patch_run(monkeypatch, [])
    result = R2Client(None).callgraph(_bin(tmp_path), RUN, direction="both")

    assert result["function"] is None
    assert result["edges"] == []
    assert result["parsed"] is False


def test_the_r2_6x_addr_key_names_the_function_start(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """r2 6.x keys the function start under ``addr`` where 5.x used ``offset``.

    The index must read either or a 6.x graph resolves no names at all.
    """
    aflj = [
        {
            "addr": MAIN,
            "name": "main",
            "size": 0x40,
            "callrefs": [{"addr": RUN, "type": "CALL", "at": 0x1010}],
            "codexrefs": [],
        },
        {"addr": RUN, "name": "sym.run", "size": 0x30, "callrefs": [], "codexrefs": []},
    ]
    _patch_run(monkeypatch, aflj)
    result = R2Client(None).callgraph(_bin(tmp_path), MAIN, direction="callees")

    assert result["function"]["name"] == "main"
    assert _edges(result, "callee")[0]["name"] == "sym.run"


def test_two_call_sites_to_one_target_stay_distinct_but_duplicates_collapse(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Dedup keys on endpoint and call site: same target twice at one site is one
    edge; the same target at two sites is two edges."""
    aflj = [
        {
            "offset": MAIN,
            "name": "main",
            "size": 0x40,
            "callrefs": [
                {"addr": RUN, "type": "CALL", "at": 0x1010},
                {"addr": RUN, "type": "CALL", "at": 0x1010},  # exact duplicate row
                {"addr": RUN, "type": "CALL", "at": 0x1030},  # second call site
            ],
            "codexrefs": [],
        },
        {"offset": RUN, "name": "sym.run", "size": 0x30, "callrefs": [], "codexrefs": []},
    ]
    _patch_run(monkeypatch, aflj)
    result = R2Client(None).callgraph(_bin(tmp_path), MAIN, direction="callees")

    sites = sorted(e["call_site_va"] for e in _edges(result, "callee"))
    assert sites == [0x1010, 0x1030]


def test_direction_filter_only_returns_the_requested_side(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """callees never carries a caller edge and vice versa."""
    _patch_run(monkeypatch, _AFLJ)
    only_callees = R2Client(None).callgraph(_bin(tmp_path), RUN, direction="callees")
    only_callers = R2Client(None).callgraph(_bin(tmp_path), RUN, direction="callers")

    assert {e["direction"] for e in only_callees["edges"]} == {"callee"}
    assert {e["direction"] for e in only_callers["edges"]} == {"caller"}


def test_pagination_slices_the_edge_list(tmp_path: Path, monkeypatch: Any) -> None:
    """offset/limit page the sorted edges and has_more marks the tail."""
    _patch_run(monkeypatch, _AFLJ)
    page1 = R2Client(None).callgraph(_bin(tmp_path), RUN, direction="both", offset=0, limit=2)
    page2 = R2Client(None).callgraph(_bin(tmp_path), RUN, direction="both", offset=2, limit=2)

    assert page1["count"] == 2
    assert page1["total"] == 3
    assert page1["has_more"] is True
    assert page1["offset"] == 0
    assert page2["count"] == 1
    assert page2["has_more"] is False
    # No edge appears on both pages.
    seen = {(e["direction"], e["addr"], e["call_site_va"]) for e in page1["edges"]}
    seen2 = {(e["direction"], e["addr"], e["call_site_va"]) for e in page2["edges"]}
    assert seen.isdisjoint(seen2)


def test_the_collect_cap_is_disclosed(tmp_path: Path, monkeypatch: Any) -> None:
    """A pathological fan-in stops at the ceiling and sets scan_capped."""
    monkeypatch.setattr("headless_re_mcp.backends.r2.client._MAX_CALLGRAPH_COLLECT", 1)
    _patch_run(monkeypatch, _AFLJ)
    result = R2Client(None).callgraph(_bin(tmp_path), RUN, direction="both")

    assert result["scan_capped"] is True


def test_the_commands_on_the_wire_are_aa_then_aflj(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """One analysis pass then the function list -- no per-address seek."""
    seen = _patch_run(monkeypatch, _AFLJ)
    R2Client(None).callgraph(_bin(tmp_path), RUN, direction="both")
    assert seen[0] == ["aa", "aflj"]


def test_a_bad_direction_is_invalid_params(tmp_path: Path) -> None:
    """Only callees/callers/both are accepted."""
    with pytest.raises(R2Error) as excinfo:
        R2Client(None).callgraph(_bin(tmp_path), RUN, direction="sideways")
    assert excinfo.value.code == "invalid_params"


def test_a_negative_address_is_invalid_params(tmp_path: Path) -> None:
    """A negative address is rejected before r2 is ever run."""
    with pytest.raises(R2Error) as excinfo:
        R2Client(None).callgraph(_bin(tmp_path), -1)
    assert excinfo.value.code == "invalid_params"


def test_callgraph_service_wires_through_to_a_session(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """End-to-end through AnalysisService with the radare2 backend tag."""
    _patch_run(monkeypatch, _AFLJ)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        result = service.r2_callgraph(session_id, RUN, direction="both")
        assert result.ok, result.error
        assert result.data is not None
        assert result.meta.get("backend") == "radare2"
        assert result.data["function"]["name"] == "sym.run"
        assert result.data["callees_total"] == 2
        assert result.data["callers_total"] == 1
    finally:
        service.close_all()


def test_docstring_frames_it_as_the_call_graph_reader() -> None:
    """The docstring must tell an agent it walks callees/callers via aflj refs."""
    doc = _tool_docstring("r2.callgraph")
    assert "callees" in doc
    assert "callers" in doc
    assert "aflj" in doc
    assert "callrefs" in doc
    assert "codexrefs" in doc
    assert "edges" in doc
