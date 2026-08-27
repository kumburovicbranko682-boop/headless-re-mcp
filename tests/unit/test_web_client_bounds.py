"""Device-free coverage for the web backend's capture-time bounding.

``_clip_console_text`` and ``_bounded_metadata`` run inside the CDP event
handlers, so they only execute when a real browser emits a console message
or a network event -- a path the unit suite never drives. Yet they are the
guards that keep a hostile page from parking unbounded strings in the
session ring for its whole lifetime: a page that ``console.log``s a whole
document, or a request with a megabyte-long URL.

These pin their logic without a browser:

- ``_clip_console_text`` picks value > description > type per argument,
  skips non-dict args, stringifies non-strings, and -- the load-bearing
  part -- stops at the byte budget: a single oversized argument is sliced,
  and a run of arguments stops both when the budget is spent exactly and
  when only the join separator would not fit, always reporting truncation.
- ``_bounded_metadata`` coerces None/non-strings, passes short values
  through untruncated, and cuts an oversized value on a UTF-8 boundary so a
  multibyte character is never split into mojibake.
"""

from __future__ import annotations

from headless_re_mcp.backends.web.client import (
    _MAX_CONSOLE_TEXT,
    _bounded_metadata,
    _clip_console_text,
)


def test_clip_joins_console_arguments() -> None:
    text, truncated = _clip_console_text({"args": [{"value": "hello"}, {"value": "world"}]})
    assert text == "hello world"
    assert truncated is False


def test_clip_prefers_value_then_description_then_type() -> None:
    assert _clip_console_text({"args": [{"value": "V", "description": "D", "type": "string"}]}) == (
        "V",
        False,
    )
    assert _clip_console_text({"args": [{"description": "D", "type": "string"}]}) == ("D", False)
    assert _clip_console_text({"args": [{"type": "object"}]}) == ("object", False)
    # An empty description is falsy, so it falls through to the type name.
    empty_desc = {"args": [{"description": "", "type": "number"}]}
    assert _clip_console_text(empty_desc) == ("number", False)


def test_clip_skips_non_dict_args_and_stringifies_values() -> None:
    text, truncated = _clip_console_text({"args": ["bare", 42, {"value": 123}, {"value": "kept"}]})
    assert text == "123 kept"
    assert truncated is False


def test_clip_no_args_is_empty() -> None:
    assert _clip_console_text({}) == ("", False)
    assert _clip_console_text({"args": None}) == ("", False)


def test_clip_slices_a_single_oversized_argument() -> None:
    text, truncated = _clip_console_text({"args": [{"value": "x" * (_MAX_CONSOLE_TEXT + 5000)}]})
    assert truncated is True
    assert text == "x" * _MAX_CONSOLE_TEXT


def test_clip_stops_when_only_the_separator_would_not_fit() -> None:
    # First arg leaves exactly one byte; the second cannot even add its join
    # space, so the budget-1 separator guard trips before it is stored.
    first = "x" * (_MAX_CONSOLE_TEXT - 1)
    text, truncated = _clip_console_text({"args": [{"value": first}, {"value": "second"}]})
    assert text == first
    assert truncated is True


def test_clip_stops_when_the_budget_is_spent_exactly() -> None:
    # First arg consumes the whole budget without tripping the slice branch;
    # the next iteration hits the remaining<=0 guard at the top of the loop.
    first = "x" * _MAX_CONSOLE_TEXT
    text, truncated = _clip_console_text({"args": [{"value": first}, {"value": "second"}]})
    assert text == first
    assert truncated is True


def test_bounded_metadata_passes_short_values_through() -> None:
    assert _bounded_metadata("short", 1024) == ("short", False)


def test_bounded_metadata_coerces_none_and_non_strings() -> None:
    assert _bounded_metadata(None, 1024) == ("", False)
    assert _bounded_metadata(4321, 1024) == ("4321", False)


def test_bounded_metadata_truncates_ascii_over_the_cap() -> None:
    text, truncated = _bounded_metadata("a" * 100, 10)
    assert text == "a" * 10
    assert truncated is True


def test_bounded_metadata_cuts_on_a_utf8_boundary() -> None:
    # Ten euro signs at three bytes each; a 7-byte cap lands mid-character.
    # errors="ignore" must drop the split byte, never emit a partial glyph.
    text, truncated = _bounded_metadata("\u20ac" * 10, 7)
    assert text == "\u20ac\u20ac"
    assert truncated is True
