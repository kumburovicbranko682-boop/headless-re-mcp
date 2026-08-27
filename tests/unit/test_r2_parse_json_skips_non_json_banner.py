"""``parse_r2_json`` must step over a bracket-shaped banner, not stop at it.

``parse_r2_json`` scans r2's ``-q0`` output left to right, and at every ``[`` or
``{`` tries ``JSONDecoder.raw_decode`` from that index, returning the first token
that decodes::

    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, _end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            continue
        return value
    return None

The ``except json.JSONDecodeError: continue`` line is the whole point of the
scan, and the two existing ``parse_r2_json`` tests never reach it: their banners
(``"warning stuff"``, ``"Cannot find function"``) contain no bracket at all, so
the first ``[``/``{`` the loop meets is already the real payload and
``raw_decode`` succeeds on the first try. Real r2 output is not that tidy -- it
leads with the interactive prompt ``[0x00000000]>`` (the case the docstring
calls out) and can carry ``{...}``-shaped diagnostics, both of which begin with a
bracket but are not JSON. Those must fail ``raw_decode`` and the scan must keep
going to the array/object that follows.

Delete the ``continue`` (make a decode failure fatal -- return ``None`` or let it
propagate) and the two existing tests stay green while every r2 invocation whose
output opens with the prompt returns ``None``: ``enrich_r2_payload`` then reports
``parsed: False`` with no items on a call that actually succeeded. These pin the
skip directly, with a leading bracket token that is *not* valid JSON.
"""

from __future__ import annotations

import json

from headless_re_mcp.backends.r2.mapping import parse_r2_json


def test_a_leading_r2_prompt_is_skipped_for_the_real_array() -> None:
    """``[0x00000000]>`` opens with ``[`` but is not JSON; the array wins.

    The prompt is the first bracket the scan meets, so a fixture without it
    (both current tests) never exercises the decode-failure path. Here the
    prompt must fail ``raw_decode`` and the loop must advance to the array that
    follows -- otherwise the whole listing is lost.
    """
    payload = [
        {"offset": 0x140001000, "name": "entry0", "size": 16},
        {"offset": 0x140001010, "name": "sub_140001010", "size": 8},
    ]
    raw = "[0x00000000]> \n" + json.dumps(payload)
    parsed = parse_r2_json(raw)
    assert isinstance(parsed, list)
    assert [entry["name"] for entry in parsed] == ["entry0", "sub_140001010"]


def test_a_brace_shaped_diagnostic_is_skipped_for_the_real_object() -> None:
    """A ``{...}`` warning fragment opens with ``{`` yet is not JSON.

    The same decode-failure skip applies to objects: the leading brace token
    must be stepped over so the genuine object after it is what gets returned.
    """
    raw = "{cannot parse header}\n" + json.dumps({"offset": 0x401000, "name": "main"})
    parsed = parse_r2_json(raw)
    assert isinstance(parsed, dict)
    assert parsed["name"] == "main"


def test_the_prompt_alone_yields_no_payload() -> None:
    """A prompt with no JSON after it decodes to nothing, not a bogus value.

    Every bracket in the text fails ``raw_decode``, so the scan falls through
    its loop and returns ``None`` -- it must not salvage the prompt as a value.
    """
    assert parse_r2_json("[0x00000000]> \n[0x00000000]> ") is None


def test_a_broken_leading_array_is_skipped_for_a_later_intact_one() -> None:
    """A truncated ``[`` fragment must not shadow a complete array further on.

    ``[1, 2`` starts an array but never closes, so ``raw_decode`` fails at that
    index; the scan has to keep looking and land on the closed array.
    """
    raw = "note: [1, 2 was dropped\n" + json.dumps([{"offset": 0x1000, "name": "f"}])
    parsed = parse_r2_json(raw)
    assert isinstance(parsed, list)
    assert parsed[0]["name"] == "f"
