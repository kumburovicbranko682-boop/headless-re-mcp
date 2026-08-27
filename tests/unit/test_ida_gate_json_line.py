"""The gate verdict line must survive Unicode line separators in the payload."""

from __future__ import annotations

import json

from headless_re_mcp.backends.ida.gate import _last_json_line


def test_a_unicode_line_separator_in_the_payload_keeps_the_verdict_readable() -> None:
    """A U+2028 / U+0085 / U+2029 inside the worker's JSON must not shred it.

    The gate worker emits one json.dumps(ensure_ascii=False) line, and that
    payload carries text from the analyzed binary: the decompiler preview is
    str(cfunc)[:1000], which quotes string literals found in the sample, and
    the error fields quote exception text. Those separators are above 0x1F, so
    JSON leaves them literal -- yet str.splitlines() treats each as a line
    boundary. The reader therefore cut the single verdict line into fragments
    that no longer parsed, and a gate run that succeeded (exit 0, ok true)
    read back as "worker returned no JSON object": a refusal caused purely by
    the contents of the binary under analysis. Splitting only on the "\\n" the
    worker appends keeps the record whole.
    """
    payload = {
        "ok": True,
        "function_count": 3,
        "decompiler": {
            "available": True,
            "preview": 'v1 = "line1\u2028line2\u0085line3\u2029end";',
        },
    }
    stdout = json.dumps(payload, ensure_ascii=False) + "\n"
    # The hostile characters really are literal in the record, so the read
    # path is what is under test rather than the write path.
    assert "\u2028" in stdout

    assert _last_json_line(stdout) == payload


def test_the_last_object_still_wins_and_noise_is_still_skipped() -> None:
    """The reverse scan semantics are unchanged: last dict wins, noise skipped."""
    text = (
        "IDA console noise\n"
        + json.dumps({"ok": False, "stage": "early"})
        + "\n[1,2,3]\n"
        + json.dumps({"ok": True, "stage": "final"})
        + "\ntrailing garbage\n"
    )

    assert _last_json_line(text) == {"ok": True, "stage": "final"}
    assert _last_json_line("") == {"error": "worker returned no JSON object"}
