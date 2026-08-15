"""Thread-context tools must reject IDs outside the native DWORD range."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.dynamic_analysis import build_dynamic_analysis_tools


def test_thread_context_schemas_match_native_tid_bounds() -> None:
    """The catalog accepted thread IDs that the native adapter rejects.

    Measured: both input schemas stopped at a minimum of 1 and had no maximum,
    while both native methods cap ``tid`` at ``DWORD_MAX`` and reject zero.
    Therefore 4,294,967,296 passed validation only to occupy a worker and fail
    at the adapter boundary.
    """
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    for start_marker, end_marker in (
        ("Outcome ReadThreadContext(", "Outcome WriteThreadContext("),
        ("Outcome WriteThreadContext(", "Outcome ReadStack("),
    ):
        start = native.index(start_marker)
        chunk = native[start : native.index(end_marker, start)]
        assert (
            'ReadUnsigned(params, "tid", tid, error, '
            "std::numeric_limits<DWORD>::max())" in chunk
        )
        assert 'InvalidField("tid", "tid must be positive")' in chunk

    tools = build_dynamic_analysis_tools(object())  # type: ignore[arg-type]
    for name in ("threads.context.read", "threads.context.write"):
        handler = next(binding.handler for binding in tools if binding.name == name)
        tid = input_schema_for(handler)["properties"]["tid"]
        assert tid["minimum"] == 1
        assert tid["maximum"] == 0xFFFFFFFF
