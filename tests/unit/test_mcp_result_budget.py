"""MCP must apply the catalog result-byte budget the agent path already uses."""

from __future__ import annotations

import json

from headless_re_mcp.mcp.adapter import apply_result_budget


def test_mcp_adapter_cuts_a_400k_jadx_class_the_agent_path_already_cuts() -> None:
    """Measured: a successful apk.decompile envelope with a 400000-char
    source is 400128 bytes. The catalog budget is 262144. MCP sent the raw
    envelope; the agent path replaced it with a 16494-byte truncated
    summary. Overnight Cursor then holds a whole class in context while
    the same call on the agent path already admitted it would not fit.

    The summary keeps the envelope's ok verdict, so a large but successful
    call is not reported as a failed one just because it was truncated.
    """
    envelope = {
        "ok": True,
        "data": {
            "source": "J" * 400_000,
            "truncated": True,
            "class_name": "com.x.Main",
            "path": "x.java",
        },
        "error": None,
        "meta": {},
    }
    raw = len(json.dumps(envelope, ensure_ascii=False).encode("utf-8"))
    assert raw == 400_128
    assert raw > 262_144

    def fat() -> dict[str, object]:
        return envelope

    out = apply_result_budget(fat, max_bytes=262_144)()
    assert out["truncated"] is True
    assert out["original_bytes"] == raw
    # The success verdict survives truncation: a large decompile is still a
    # success, not a failure invented by the size cap.
    assert out["ok"] is True
    encoded = json.dumps(out, ensure_ascii=False).encode("utf-8")
    assert len(encoded) < 262_144
    assert len(encoded) == 16_494
