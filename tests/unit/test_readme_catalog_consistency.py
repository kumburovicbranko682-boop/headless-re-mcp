"""README's tool arithmetic must track tools/catalog.py, not history.

The README states three concrete numbers -- the MCP tool total, its
read/write split, and the hostile-input coverage count (total minus the one
deliberate exclusion, ``artifacts.gc``). Nothing recomputed them: adding or
reclassifying a tool silently turned the front page into fiction. Each claim is
located by its own distinctive phrasing, so a reword fails loudly here instead
of the guard going quietly blind.
"""

from __future__ import annotations

import re
from pathlib import Path

from headless_re_mcp.tools.catalog import COMMAND_CATALOG, CommandTransport

README = Path(__file__).resolve().parents[2] / "README.md"


def _catalog_counts() -> tuple[int, int, int]:
    specs = list(COMMAND_CATALOG.for_transport(CommandTransport.MCP))
    write = sum(1 for spec in specs if spec.write)
    return len(specs), len(specs) - write, write


def _single_match(pattern: str, text: str) -> re.Match[str]:
    matches = re.findall(pattern, text)
    assert len(matches) == 1, (
        f"expected exactly one README claim matching {pattern!r}, found {len(matches)}; "
        "if the sentence was reworded, update this guard with it"
    )
    match = re.search(pattern, text)
    assert match is not None
    return match


def test_the_headline_tool_total_matches_the_catalog() -> None:
    total, _read, _write = _catalog_counts()
    text = README.read_text(encoding="utf-8")
    claim = _single_match(r"收成 (\d+) 个受限语义工具", text)
    assert int(claim.group(1)) == total


def test_the_read_write_split_matches_the_catalog() -> None:
    total, read, write = _catalog_counts()
    text = README.read_text(encoding="utf-8")
    claim = _single_match(r"(\d+) 个工具的读写归类（(\d+) 只读 / (\d+) 写）", text)
    assert (int(claim.group(1)), int(claim.group(2)), int(claim.group(3))) == (
        total,
        read,
        write,
    )


def test_the_hostile_input_coverage_count_is_total_minus_the_gc_exclusion() -> None:
    """test_tool_fault_contract covers every bound tool except artifacts.gc."""
    total, _read, _write = _catalog_counts()
    text = README.read_text(encoding="utf-8")
    claim = _single_match(r"(\d+) 个工具（全部 (\d+) 个 MCP 工具", text)
    assert int(claim.group(2)) == total
    assert int(claim.group(1)) == total - 1
