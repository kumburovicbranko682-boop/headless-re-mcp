"""The idalib gate verdict parser must not be fooled by Unicode line separators."""

from __future__ import annotations

import json

from headless_re_mcp.backends.ida.gate import _last_json_line


def test_a_unicode_line_separator_in_the_verdict_keeps_it_readable() -> None:
    """A U+2028/U+2029/U+0085 in the payload must not split the JSON line.

    The worker writes its verdict with ``json.dumps(ensure_ascii=False)``, so a
    Unicode line separator lands in the output literally, and the decompiler
    preview it embeds is lifted straight from the analyzed binary. The client
    used to slice stdout with ``str.splitlines``, which treats those code points
    as line breaks and cut the one JSON line into fragments that each failed
    ``json.loads`` -- so a successful analysis read back as "worker returned no
    JSON object" and its ``ok`` was lost.
    """
    payload = {
        "ok": True,
        "functions": 12,
        "decompiler": {
            "available": True,
            "preview": "if (a)\u2028  return b;\u2029next\u0085tail",
        },
    }
    stdout = "IDA banner\n" + json.dumps(payload, ensure_ascii=False) + "\n"

    verdict = _last_json_line(stdout)

    assert verdict.get("ok") is True
    assert verdict.get("functions") == 12
    assert verdict["decompiler"]["preview"] == payload["decompiler"]["preview"]


def test_the_last_json_object_still_wins_and_noise_is_still_skipped() -> None:
    """Splitting on "\\n" must keep the existing last-object-wins behaviour.

    Real newlines inside the payload are escaped by ``json.dumps``, so each
    verdict is a single "\\n"-terminated line; a trailing carriage return from a
    Windows text-mode write is tolerated by ``json.loads`` as trailing space.
    """
    stdout = (
        "noise before\n"
        '{"ok": false, "attempt": 1}\r\n'
        '{"ok": true, "attempt": 2}\r\n'
        "trailing noise\n"
    )

    assert _last_json_line(stdout) == {"ok": True, "attempt": 2}


def test_no_json_object_reports_the_miss() -> None:
    assert _last_json_line("just banner text\nno json here\n") == {
        "error": "worker returned no JSON object"
    }
