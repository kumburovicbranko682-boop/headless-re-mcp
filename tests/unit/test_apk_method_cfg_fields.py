"""Unit coverage for ApkClient.method_cfg (apk.method_cfg).

method_cfg resolves one Dalvik method through ``_parsed`` (monkeypatched here)
and reads its basic blocks via androguard's ``MethodAnalysis.basic_blocks``,
turning each block into a node and each successor into a fall_through/branch
edge. These fakes stand in for the androguard objects so the block/edge shaping,
the terminator, truncation and fault contract are exercised without a real DEX;
the live gate proves the same path against androguard on a hand-assembled
branchy method.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import (
    ApkClient,
    ApkError,
    _bb_children,
    _bb_end,
    _bb_start,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


class _Ins:
    def __init__(self, name: str) -> None:
        self._name = name

    def get_name(self) -> str:
        return self._name


class _Block:
    """An androguard DVMBasicBlock stand-in.

    ``childs`` mirrors androguard's ``(pos, child_start, child_block)`` tuples;
    the shaping code reads the child block's own start, so the tuple's middle
    element is informational only.
    """

    def __init__(
        self, name: str, start: int, end: int, mnemonics: list[str], childs: list[_Block]
    ) -> None:
        self._name = name
        self._start = start
        self._end = end
        self._instrs = [_Ins(m) for m in mnemonics]
        self._childs = childs

    def get_name(self) -> str:
        return self._name

    def get_start(self) -> int:
        return self._start

    def get_end(self) -> int:
        return self._end

    def get_instructions(self) -> Any:
        return iter(self._instrs)

    @property
    def childs(self) -> list[tuple[int, int, _Block]]:
        return [(0, c._start, c) for c in self._childs]


class _BasicBlocks:
    def __init__(self, blocks: list[_Block]) -> None:
        self._blocks = blocks

    def get(self) -> list[_Block]:
        return list(self._blocks)


class _Code:
    """Truthy marker: a non-None get_code() means the method has a body."""


class _Encoded:
    def __init__(self, code: _Code | None) -> None:
        self._code = code

    def get_code(self) -> _Code | None:
        return self._code


class _MCA:
    def __init__(
        self,
        name: str,
        descriptor: str,
        blocks: list[_Block],
        *,
        code: bool = True,
        external: bool = False,
        access: str = "public",
    ) -> None:
        self.name = name
        self.descriptor = descriptor
        self.access = access
        self._external = external
        self._blocks = _BasicBlocks(blocks)
        self._encoded = _Encoded(_Code() if code else None)

    def is_external(self) -> bool:
        return self._external

    def get_method(self) -> _Encoded:
        return self._encoded

    @property
    def basic_blocks(self) -> _BasicBlocks:
        return self._blocks


class _FakeClass:
    def __init__(self, name: str, methods: list[_MCA]) -> None:
        self.name = name
        self._methods = methods

    def get_methods(self) -> list[_MCA]:
        return self._methods


class _FakeAnalysis:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


class _FakeParsed:
    def __init__(self, analysis: _FakeAnalysis) -> None:
        self.analysis = analysis


def _client_with(classes: list[_FakeClass], monkeypatch: pytest.MonkeyPatch) -> ApkClient:
    client = ApkClient()
    monkeypatch.setattr(client, "_parsed", lambda _path: _FakeParsed(_FakeAnalysis(classes)))
    return client


_APK = Path("/nonexistent/app.apk")


def _conditional_blocks() -> list[_Block]:
    """B0 ends in a conditional: fall-through to B1 (at end), branch to B2."""
    b1 = _Block("m-BB@0x6", 6, 10, ["const/4", "return-void"], [])
    b2 = _Block("m-BB@0xa", 10, 14, ["const/4", "return-void"], [])
    b0 = _Block("m-BB@0x0", 0, 6, ["const/4", "if-eqz"], [b1, b2])
    return [b0, b1, b2]


def _loop_blocks() -> list[_Block]:
    """B0 -> B1; B1 falls through to B2 and branches back to B0 (a loop)."""
    b2 = _Block("m-BB@0x8", 8, 12, ["return-void"], [])
    b0 = _Block("m-BB@0x0", 0, 4, ["const/4"], [])  # child wired below
    b1 = _Block("m-BB@0x4", 4, 8, ["add-int", "if-lt"], [b2, b0])
    b0._childs = [b1]
    return [b0, b1, b2]


def _cfg(client: ApkClient, method: str = "m", **kw: Any) -> dict[str, Any]:
    return client.method_cfg(_APK, "com.example.App", method, **kw)


def test_conditional_block_splits_into_fall_through_and_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _MCA("m", "()V", _conditional_blocks())
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    data = _cfg(client)
    assert data["has_code"] is True
    assert data["node_count"] == 3
    edges = {(e["src"], e["dst"]): e["kind"] for e in data["edges"]}
    # The successor at the block's end is the not-taken fall-through; the other
    # is the taken branch target.
    assert edges[(0, 6)] == "fall_through"
    assert edges[(0, 10)] == "branch"


def test_unconditional_goto_is_a_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    # B0 ends 4 but its only successor starts at 8 (a goto over B_mid): branch.
    dest = _Block("m-BB@0x8", 8, 12, ["return-void"], [])
    b0 = _Block("m-BB@0x0", 0, 4, ["goto"], [dest])
    target = _MCA("m", "()V", [b0, dest])
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    (edge,) = _cfg(client)["edges"]
    assert (edge["src"], edge["dst"], edge["kind"]) == (0, 8, "branch")


def test_straightline_successor_is_fall_through(monkeypatch: pytest.MonkeyPatch) -> None:
    nxt = _Block("m-BB@0x4", 4, 8, ["return-void"], [])
    b0 = _Block("m-BB@0x0", 0, 4, ["const/4"], [nxt])
    target = _MCA("m", "()V", [b0, nxt])
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    (edge,) = _cfg(client)["edges"]
    assert (edge["src"], edge["dst"], edge["kind"]) == (0, 4, "fall_through")


def test_loop_back_edge_points_to_an_earlier_block(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _MCA("m", "()V", _loop_blocks())
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    edges = _cfg(client)["edges"]
    # The back edge 4 -> 0 lands on an earlier block start: the loop.
    assert any(e["src"] == 4 and e["dst"] == 0 and e["dst"] < e["src"] for e in edges), edges
    node_starts = {n["addr"] for n in _cfg(client)["nodes"]}
    assert all(e["dst"] in node_starts for e in edges)


def test_return_block_has_no_out_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _MCA("m", "()V", _conditional_blocks())
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    data = _cfg(client)
    assert not any(e["src"] == 10 for e in data["edges"])
    assert not any(e["src"] == 6 for e in data["edges"])


def test_nodes_carry_block_geometry_and_terminator(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _MCA("m", "()V", _conditional_blocks())
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    entry = _cfg(client)["nodes"][0]
    assert entry["addr"] == 0
    assert entry["end"] == 6
    assert entry["size"] == 6
    assert entry["ninstr"] == 2
    assert entry["terminator"] == "if-eqz"
    assert entry["name"] == "m-BB@0x0"


def test_entry_is_the_lowest_start(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _MCA("m", "()V", _conditional_blocks())
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    assert _cfg(client)["entry"] == 0


def test_nodes_are_sorted_by_addr_regardless_of_input_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocks = _conditional_blocks()
    blocks.reverse()  # feed them out of order
    target = _MCA("m", "()V", blocks)
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    addrs = [n["addr"] for n in _cfg(client)["nodes"]]
    assert addrs == sorted(addrs) == [0, 6, 10]


def test_edges_are_deduplicated_and_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    # Two childs both to the same start with the same kind collapse to one edge.
    dup = _Block("m-BB@0x4", 4, 8, ["return-void"], [])
    b0 = _Block("m-BB@0x0", 0, 4, ["const/4", "goto"], [dup, dup])
    target = _MCA("m", "()V", [b0, dup])
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    edges = _cfg(client)["edges"]
    assert len(edges) == 1
    assert edges == sorted(edges, key=lambda e: (e["src"], e["dst"], e["kind"]))


def test_no_code_method_is_an_empty_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _MCA("m", "()V", [], code=False)
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    data = _cfg(client)
    assert data["has_code"] is False
    assert data["nodes"] == []
    assert data["edges"] == []
    assert data["entry"] is None
    assert data["node_count"] == 0
    assert data["edge_count"] == 0


def test_descriptor_pins_the_overload(monkeypatch: pytest.MonkeyPatch) -> None:
    take_int = _MCA("m", "(I)V", _conditional_blocks())
    take_str = _MCA("m", "(Ljava/lang/String;)V", _loop_blocks())
    client = _client_with([_FakeClass("Lcom/example/App;", [take_int, take_str])], monkeypatch)
    data = _cfg(client, descriptor="(Ljava/lang/String;)V")
    assert data["descriptor"] == "(Ljava/lang/String;)V"
    assert data["overloads"] == 2
    # The loop overload's back edge distinguishes it from the conditional one.
    assert any(e["src"] == 4 and e["dst"] == 0 for e in data["edges"]), data["edges"]


def test_overloads_counts_and_first_is_used_without_a_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _MCA("m", "(I)V", _conditional_blocks())
    second = _MCA("m", "(J)V", _loop_blocks())
    client = _client_with([_FakeClass("Lcom/example/App;", [first, second])], monkeypatch)
    data = _cfg(client)
    assert data["overloads"] == 2
    assert data["descriptor"] == "(I)V"


def test_missing_class_and_method_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _MCA("m", "()V", _conditional_blocks())
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    with pytest.raises(ApkError) as no_class:
        client.method_cfg(_APK, "com.example.Nope", "m")
    assert no_class.value.code == "not_found"
    with pytest.raises(ApkError) as no_method:
        client.method_cfg(_APK, "com.example.App", "ghost")
    assert no_method.value.code == "not_found"


def test_blank_inputs_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _MCA("m", "()V", _conditional_blocks())
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    for cls, method in (("", "m"), ("com.example.App", "")):
        with pytest.raises(ApkError) as err:
            client.method_cfg(_APK, cls, method)
        assert err.value.code == "invalid_params"


def test_blocks_truncated_discloses_and_bounds_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_CFG_BLOCKS", 2)
    target = _MCA("m", "()V", _conditional_blocks())  # 3 blocks
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)
    data = _cfg(client)
    assert data["blocks_total"] == 3
    assert data["blocks_truncated"] is True
    assert data["node_count"] == 2  # kept only the first two by start offset
    # The branch to the dropped block (at 10) survives as an edge endpoint even
    # though its node was trimmed -- the caller sees the graph was cut.
    assert data["node_count"] < data["blocks_total"]


def test_bb_children_tolerates_tuple_and_bare_shapes() -> None:
    child = _Block("c", 4, 8, [], [])
    tuple_parent = _Block("p", 0, 4, [], [child])  # childs -> [(0, 4, child)]
    assert _bb_children(tuple_parent) == [child]

    class _Bare:
        childs = [child]  # a bare block, not a tuple

    assert _bb_children(_Bare()) == [child]

    class _NoChilds:
        childs = None

    assert _bb_children(_NoChilds()) == []


def test_bb_start_end_fall_back_to_attributes() -> None:
    class _AttrBlock:
        start = 16
        end = 24

    assert _bb_start(_AttrBlock()) == 16
    assert _bb_end(_AttrBlock()) == 24


def test_service_wraps_unknown_session_as_failure() -> None:
    service = AnalysisService(Settings.load())
    result = service.apk_method_cfg("no-such-session", "com.example.App", "m")
    assert not result.ok
    assert result.error is not None


def test_docstring_names_the_contract() -> None:
    doc = ApkClient.method_cfg.__doc__ or ""
    for token in ("fall_through", "branch", "terminator", "r2.cfg", "has_code"):
        assert token in doc, token
