"""_last_json_line scans idalib's noisy stdout for the worker's JSON verdict.

The loop exists because idalib prints stray lines around the worker's own
output; every line that is not the worker's JSON must be skipped, whatever
shape it takes.
"""

from __future__ import annotations

from headless_re_mcp.backends.ida.gate import _last_json_line


def test_the_deepest_parseable_object_wins() -> None:
    text = 'noise\n{"ok": true}\nnot json either'
    assert _last_json_line(text) == {"ok": True}


def test_no_json_object_yields_the_error_verdict() -> None:
    assert _last_json_line("only\nnoise\n[1, 2]") == {
        "error": "worker returned no JSON object"
    }


def test_a_line_nested_past_the_recursion_limit_is_skipped_not_fatal() -> None:
    """json.loads raises RecursionError, not JSONDecodeError, on deep nesting.

    The reversed scan meets the deep line first; the old except tuple let the
    RecursionError abandon the scan -- and the worker's real verdict above it
    -- as a raw interpreter error instead of skipping one stray line.
    """
    text = '{"ok": true}\n' + "[" * 20_000
    assert _last_json_line(text) == {"ok": True}
