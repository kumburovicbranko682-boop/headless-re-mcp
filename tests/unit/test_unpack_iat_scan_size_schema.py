"""unpack.iat.scan must refuse an oversized search window at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.unpack import build_unpack_tools


def test_unpack_iat_scan_schema_matches_native_search_size_cap() -> None:
    """The catalog accepted an unbounded IAT search window.

    Measured: input schema search_size has no maximum. unpack_iat_scan
    forwards search_size to imports_scan, whose native ReadUnsigned already
    refuses anything above MaxImportScanBytes (16 MiB). A caller that asked
    to scan 2 GiB still occupied a worker until that adapter refuse.
    """
    header = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_internal.h"
    ).read_text(encoding="utf-8")
    assert "MaxImportScanBytes = 16U * 1024U * 1024U" in header
    cap = 16 * 1024 * 1024
    handler = next(
        binding.handler
        for binding in build_unpack_tools(object())  # type: ignore[arg-type]
        if binding.name == "unpack.iat.scan"
    )
    props = input_schema_for(handler)["properties"]
    integer_size = next(
        item for item in props["search_size"]["anyOf"] if item.get("type") == "integer"
    )
    assert integer_size["minimum"] == 1
    assert integer_size["maximum"] == cap
