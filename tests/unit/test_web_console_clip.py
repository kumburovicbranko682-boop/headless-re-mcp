"""_clip_console_text bounds and shapes what a page's console.* lands in the ring.

Every console message a page emits is joined from its CDP argument list and
stored in the console ring for the life of the session. Two things have to hold
and neither was covered beyond a single-argument overflow:

  * the join is size-bounded. A page that ``console.log``s a whole document (or
    thousands of small lines) must not copy the original into the buffer -- each
    argument is clipped against a shared ``_MAX_CONSOLE_TEXT`` budget, the
    inter-argument space counts against that budget too, and any clip flags
    ``truncated`` so a caller never mistakes a cut message for the whole one.
  * the argument shapes CDP actually sends are all resolved. A remote object
    arrives with no ``value`` but a ``description`` (``"<Object>"``); a bare
    ``undefined`` arrives with only a ``type``; a non-dict entry is noise. The
    resolver must prefer value, then description, then type, coerce a non-string
    value, and skip non-dicts -- otherwise a monitored console silently loses
    the objects and the primitives, keeping only plain strings.

These call the pure helper directly -- no browser, no session -- which is
exactly where the join and the budgeting live.
"""

from __future__ import annotations

from headless_re_mcp.backends.web.client import _MAX_CONSOLE_TEXT, _clip_console_text


def _clip(*args: object) -> tuple[str, bool]:
    return _clip_console_text({"args": list(args)})


def test_multiple_arguments_are_joined_with_single_spaces() -> None:
    """console.log('a','b','c') is stored as 'a b c', not concatenated or dropped."""
    text, truncated = _clip({"value": "a"}, {"value": "b"}, {"value": "c"})
    assert text == "a b c"
    assert truncated is False


def test_argument_shapes_resolve_value_then_description_then_type() -> None:
    """CDP sends value, or a description for objects, or only a type for primitives.

    The three shapes coexist in one real console line -- a string, a logged
    object, and an ``undefined`` -- so the resolver's precedence (value >
    description > type) is exercised together, with a non-string value coerced
    to text rather than dropped.
    """
    text, truncated = _clip(
        {"value": "n="},
        {"value": 42},  # non-string value: coerced, not skipped
        {"description": "<Object obj>"},  # remote object: no value, has description
        {"type": "undefined"},  # primitive: neither value nor description
    )
    assert text == "n= 42 <Object obj> undefined"
    assert truncated is False


def test_non_dict_arguments_are_skipped() -> None:
    """A malformed (non-dict) argument is noise and must not break the join.

    Indexing a bare string or int as if it were a CDP arg dict would raise; the
    resolver skips them so a single odd entry cannot lose the whole message.
    """
    text, truncated = _clip("bare-string", 123, {"value": "kept"})
    assert text == "kept"
    assert truncated is False


def test_no_arguments_yields_empty_untruncated_text() -> None:
    """An empty or absent args list is a real (empty) message, not a truncation."""
    assert _clip() == ("", False)
    assert _clip_console_text({}) == ("", False)


def test_the_joined_text_is_bounded_and_flagged_truncated() -> None:
    """A flood of arguments is clipped to the budget and marked truncated.

    Two hundred 100-char arguments far exceed the budget; the result must be
    capped at ``_MAX_CONSOLE_TEXT`` and carry truncated True, so the ring cannot
    be grown past its bound by one chatty console line and a caller knows the
    text was cut.
    """
    text, truncated = _clip(*[{"value": "x" * 100} for _ in range(200)])
    assert len(text) == _MAX_CONSOLE_TEXT
    assert truncated is True


def test_the_inter_argument_space_counts_against_the_budget() -> None:
    """The separator is charged to the budget, so a full first arg cuts the next.

    When the first argument fills all but one byte of the budget, there is no
    room for both the joining space and any of the second argument, so the clip
    stops at the separator and flags truncated -- the space is not free, and
    emitting it would push the stored text one byte over the bound.
    """
    text, truncated = _clip({"value": "y" * (_MAX_CONSOLE_TEXT - 1)}, {"value": "z"})
    assert len(text) == _MAX_CONSOLE_TEXT - 1
    assert truncated is True
    assert "z" not in text  # the second argument never made it past the separator


def test_a_first_argument_that_fills_the_budget_stops_before_the_next() -> None:
    """Once the budget is spent, later arguments are not even inspected.

    The first argument consumes the whole budget, so the loop breaks on the next
    iteration rather than clipping a zero-length slice of the second argument;
    the result is exactly the budget's worth of the first, flagged truncated.
    """
    text, truncated = _clip({"value": "w" * _MAX_CONSOLE_TEXT}, {"value": "second"})
    assert len(text) == _MAX_CONSOLE_TEXT
    assert text == "w" * _MAX_CONSOLE_TEXT
    assert truncated is True
