"""_last_json_line must survive malformed worker output, not raise."""

from __future__ import annotations

from headless_re_mcp.backends.ida.gate import _last_json_line


def test_last_json_line_returns_the_last_json_object() -> None:
    text = 'noise\n{"ok": false}\n{"ok": true, "id": "9"}\n'
    assert _last_json_line(text) == {"ok": True, "id": "9"}


def test_last_json_line_skips_non_json_and_non_object_lines() -> None:
    text = 'garbage\n[1, 2, 3]\n"a string"\n{"ok": true}\n'
    assert _last_json_line(text) == {"ok": True}


def test_last_json_line_reports_when_no_json_object_is_present() -> None:
    assert _last_json_line("not json at all\nstill not\n") == {
        "error": "worker returned no JSON object"
    }


def test_last_json_line_skips_a_deeply_nested_line_instead_of_faulting() -> None:
    """A line of ``[[[...]]]`` blows CPython's recursion limit in json.loads.

    That RecursionError is not a JSONDecodeError, so without an explicit arm it
    escaped the gate as a raw builtin while scanning worker output. The scan
    should skip the pathological line and still find the real object below it.
    """
    nested = ("[" * 100_000) + ("]" * 100_000)
    text = f'{nested}\n{{"ok": true, "id": "7"}}\n'
    assert _last_json_line(text) == {"ok": True, "id": "7"}


def test_last_json_line_reports_when_only_a_deeply_nested_line_is_present() -> None:
    nested = ("[" * 100_000) + ("]" * 100_000)
    assert _last_json_line(nested) == {"error": "worker returned no JSON object"}
