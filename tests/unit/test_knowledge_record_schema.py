"""knowledge.record must refuse oversized kind/key at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.meta import build_meta_tools


def test_knowledge_record_schema_matches_service_kind_and_key_caps() -> None:
    """The catalog accepted unbounded kind and key strings.

    Measured: input schema kind and key have no maxLength. The service refuses
    kind above 64 characters and key above 256 before the store write. A caller
    that records a multi-kilobyte key still occupies a worker until that check
    runs, and overnight agents retry the same oversized fact as if the tool
    never received it.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_ext.py"
    ).read_text(encoding="utf-8")
    start = source.index("def knowledge_record")
    chunk = source[start : source.index("def knowledge_query", start)]
    assert "len(normalized_kind) > 64" in chunk
    assert "len(normalized_key) > 256" in chunk
    handler = next(
        binding.handler
        for binding in build_meta_tools(object())  # type: ignore[arg-type]
        if binding.name == "knowledge.record"
    )
    props = input_schema_for(handler)["properties"]
    assert props["kind"]["minLength"] == 1
    assert props["kind"]["maxLength"] == 64
    assert props["key"]["minLength"] == 1
    assert props["key"]["maxLength"] == 256
