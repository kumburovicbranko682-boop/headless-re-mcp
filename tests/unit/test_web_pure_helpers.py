"""Pure text-bounding helpers on the web line, pinned without a browser.

Everything the browser hands back is untrusted and potentially huge -- a page
can ``console.log`` an entire document and set a megabyte-long ``<title>`` -- so
three pure helpers bound that text before it lands in the session ring or a
reply. None had a direct test:

* ``_bounded_metadata`` clips a value to a byte cap and reports whether it cut;
* ``_safe_title`` runs a page title through that cap and never propagates a
  failed title read (an empty string instead);
* ``_clip_console_text`` joins console arguments, charging a space between them,
  and stops at ``_MAX_CONSOLE_TEXT`` so one giant ``console.log`` cannot pin the
  ring for the life of the session.
"""

from __future__ import annotations

import pytest

import headless_re_mcp.backends.web.client as web
from headless_re_mcp.backends.web.client import (
    _MAX_METADATA_BYTES,
    _bounded_metadata,
    _clip_console_text,
    _safe_title,
)


def test_bounded_metadata_returns_short_text_unchanged() -> None:
    text, truncated = _bounded_metadata("hello", _MAX_METADATA_BYTES)
    assert text == "hello"
    assert truncated is False


def test_bounded_metadata_clips_over_the_cap_and_flags_it() -> None:
    value = "x" * (_MAX_METADATA_BYTES + 500)
    text, truncated = _bounded_metadata(value, _MAX_METADATA_BYTES)
    assert truncated is True
    assert len(text.encode("utf-8")) <= _MAX_METADATA_BYTES


def test_bounded_metadata_coerces_none_and_non_strings() -> None:
    assert _bounded_metadata(None, _MAX_METADATA_BYTES) == ("", False)
    assert _bounded_metadata(1234, _MAX_METADATA_BYTES) == ("1234", False)


def test_safe_title_bounds_a_title() -> None:
    class _Page:
        def title(self) -> str:
            return "A Normal Title"

    assert _safe_title(_Page()) == "A Normal Title"


def test_safe_title_is_empty_when_the_title_read_fails() -> None:
    """A detached page or a title() that raises must not escape as an exception;
    the caller gets an empty title, not a crash mid-navigation."""

    class _Broken:
        def title(self) -> str:
            raise RuntimeError("execution context was destroyed")

    assert _safe_title(_Broken()) == ""


def test_console_text_is_empty_when_there_are_no_args() -> None:
    assert _clip_console_text({}) == ("", False)
    assert _clip_console_text({"args": None}) == ("", False)


def test_console_text_joins_values_with_a_single_space() -> None:
    result, truncated = _clip_console_text(
        {"args": [{"value": "hello"}, {"value": "world"}]}
    )
    assert result == "hello world"
    assert truncated is False


def test_console_text_skips_non_dict_arguments() -> None:
    result, truncated = _clip_console_text({"args": ["not-a-dict", {"value": "ok"}]})
    assert result == "ok"
    assert truncated is False


def test_console_text_falls_back_from_value_to_description_to_type() -> None:
    """An arg with no ``value`` uses its ``description``; with neither, its
    ``type`` -- so a logged object or ``undefined`` still reads as something."""
    result, _ = _clip_console_text({"args": [{"description": "<Foo object>"}]})
    assert result == "<Foo object>"
    # An empty description falls through to type, not to a blank piece.
    result, _ = _clip_console_text({"args": [{"description": "", "type": "number"}]})
    assert result == "number"
    result, _ = _clip_console_text({"args": [{"type": "undefined"}]})
    assert result == "undefined"


def test_console_text_truncates_one_oversized_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web, "_MAX_CONSOLE_TEXT", 5)
    result, truncated = _clip_console_text({"args": [{"value": "abcdefgh"}]})
    assert result == "abcde"
    assert truncated is True


def test_console_text_flags_more_left_after_an_exact_fill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A first piece that consumes the budget exactly leaves remaining at zero
    without truncating; the next argument then trips the top-of-loop guard."""
    monkeypatch.setattr(web, "_MAX_CONSOLE_TEXT", 5)
    result, truncated = _clip_console_text({"args": [{"value": "abcde"}, {"value": "z"}]})
    assert result == "abcde"
    assert truncated is True


def test_console_text_charges_a_space_between_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The join space counts against the budget: with four chars spent and one
    left, a second argument cannot start, so it stops rather than gluing on."""
    monkeypatch.setattr(web, "_MAX_CONSOLE_TEXT", 5)
    result, truncated = _clip_console_text({"args": [{"value": "abcd"}, {"value": "z"}]})
    assert result == "abcd"
    assert truncated is True
