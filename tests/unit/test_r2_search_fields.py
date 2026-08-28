"""r2.search must encode a query to an injection-safe byte pattern and map hits."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import (
    _MAX_SEARCH_BYTES,
    _SEARCH_MAXHITS_COMMAND,
    R2Client,
    R2Error,
    _require_allowed_command,
)
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload
from headless_re_mcp.tools.r2 import build_r2_tools


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


def _canned(arr: list[dict[str, Any]], sink: list[list[str]] | None = None) -> Any:
    """A fake R2Client.run that enriches ``arr`` as if /xj had emitted it.

    search() leans on run()'s enrichment (which maps r2 6.x's ``addr`` hit key to
    an ``address``), so the fake reproduces exactly that, and optionally records
    the command list so a test can assert what was actually run.
    """

    def run(binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        if sink is not None:
            sink.append(list(commands))
        return enrich_r2_payload(
            {"raw": json.dumps(arr), "commands": commands}, binary=binary
        )

    return run


def test_r2_search_text_encodes_to_hex_and_maps_hits(tmp_path: Path, monkeypatch: Any) -> None:
    """A text query must become its UTF-8 hex pattern, and each hit map to an addr.

    The point is a pivotable result: r2 finds the exact bytes and every hit comes
    back address-mapped so an agent can r2.read or r2.disasm at it. The query is
    encoded to hex, so the command carries only hex digits (no way to inject r2
    syntax), and the echoed pattern_hex is what a follow-up hex search would use.
    """
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    # "RE_M" -> 0x52 0x45 0x5f 0x4d
    hits = [{"addr": 0x2010, "type": "hexpair", "data": "52455f4d"}]
    seen: list[list[str]] = []
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(hits, seen))
    out = client.search(binary, "RE_M", kind="text")
    assert out["query"] == "RE_M"
    assert out["kind"] == "text"
    assert out["pattern_hex"] == "52455f4d"
    assert out["pattern_len"] == 4
    assert out["count"] == 1
    item = out["items"][0]
    assert item["addr"] == 0x2010
    assert item["type"] == "hexpair"
    assert item["data"] == "52455f4d"
    assert isinstance(item.get("address"), dict)
    assert item["address"].get("va") == 0x2010
    # The command run was the capped-maxhits set then the exact /xj pattern.
    assert seen and seen[0] == [_SEARCH_MAXHITS_COMMAND, "/xj 52455f4d"], seen
    doc = _tool_docstring("r2.search")
    assert "pattern_hex" in doc
    assert "text" in doc and "hex" in doc
    assert "items" in doc


def test_r2_search_aliases_the_r2_5x_offset_hit_key_to_addr(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """r2 5.x names a /xj hit's location ``offset``; 6.x names it ``addr``.

    The contract (and the docstring) promise ``addr`` for every hit so a caller
    can pivot with r2.read/r2.disasm. Without the /xj-scoped alias an r2 5.x hit
    carried only ``offset`` and ``item["addr"]`` KeyError-ed -- the exact drift
    that made the whole native ELF gate red on r2 5.x. The hit must expose both
    the integer ``addr`` and the mapped ``address``.
    """
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    # r2 5.x shape: the location is ``offset``, there is no ``addr`` key.
    hits = [{"offset": 0x2010, "type": "hexpair", "data": "52455f4d"}]
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(hits))
    out = client.search(binary, "RE_M", kind="text")
    item = out["items"][0]
    assert item["addr"] == 0x2010
    assert item["address"].get("va") == 0x2010


def test_r2_search_hex_normalizes_and_absence_is_clean(tmp_path: Path, monkeypatch: Any) -> None:
    """A hex query tolerates spaces/0x, and a not-present pattern is empty, not error.

    "0x DE AD be ef" is the same pattern as "deadbeef"; whitespace and the prefix
    are stripped. A pattern that never occurs yields a clean empty items list with
    count 0 (parsed), which an agent reads as "absent" -- distinct from a fault.
    """
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    seen: list[list[str]] = []
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned([], seen))
    out = client.search(binary, "0x DE AD be ef", kind="hex")
    assert out["pattern_hex"] == "deadbeef"
    assert out["pattern_len"] == 4
    assert out["kind"] == "hex"
    assert out["count"] == 0
    assert out["items"] == []
    assert out["parsed"] is True
    assert seen and seen[0][1] == "/xj deadbeef", seen


def test_r2_search_rejects_bad_query_and_kind(tmp_path: Path) -> None:
    """Bad kind, empty query, odd hex, and an over-long pattern are invalid_params.

    All validated before any r2 spawn, so a caller learns why rather than getting
    an opaque backend error -- and the length cap keeps the whitelisted command
    small.
    """
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    client = R2Client(executable=Path("/nonexistent-r2"))
    with pytest.raises(R2Error) as bad_kind:
        client.search(binary, "abcd", kind="regex")
    assert bad_kind.value.code == "invalid_params"
    with pytest.raises(R2Error) as empty:
        client.search(binary, "", kind="text")
    assert empty.value.code == "invalid_params"
    with pytest.raises(R2Error) as odd:
        client.search(binary, "abc", kind="hex")  # odd-length hex
    assert odd.value.code == "invalid_params"
    with pytest.raises(R2Error) as nonhex:
        client.search(binary, "zz", kind="hex")
    assert nonhex.value.code == "invalid_params"
    with pytest.raises(R2Error) as too_long:
        client.search(binary, "A" * (_MAX_SEARCH_BYTES + 1), kind="text")
    assert too_long.value.code == "invalid_params"


def test_xj_whitelist_requires_whole_bytes() -> None:
    """The command whitelist itself gates /xj to even-length hex, as defense.

    search() only ever builds whole-byte patterns, but the whitelist is the last
    gate: an even-length /xj passes, an odd-length one is refused, and only the
    exact capped-maxhits config command is allowed (a different value is not).
    """
    _require_allowed_command("/xj 52455f4d")
    _require_allowed_command(_SEARCH_MAXHITS_COMMAND)
    with pytest.raises(R2Error):
        _require_allowed_command("/xj 526")  # odd-length hex
    with pytest.raises(R2Error):
        _require_allowed_command("/xj ")  # no pattern
    with pytest.raises(R2Error):
        _require_allowed_command("e search.maxhits=999999")  # not the capped value
