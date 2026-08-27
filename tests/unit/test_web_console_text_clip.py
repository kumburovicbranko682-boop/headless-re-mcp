"""``_clip_console_text`` renders each CDP console arg and budgets the join.

The console buffer is fed from ``Runtime.consoleAPICalled``, whose ``args`` are
CDP RemoteObjects, not strings. ``_clip_console_text`` turns each into text and
concatenates under a byte budget::

    for argument in params.get("args") or []:
        if remaining <= 0: ...
        if not isinstance(argument, dict): continue
        if "value" in argument:      raw = argument["value"]
        elif argument.get("description"): raw = argument["description"]
        else:                        raw = argument.get("type", "")
        piece = raw if isinstance(raw, str) else str(raw)
        if parts:
            if remaining <= 1: ...
            remaining -= 1              # the joining space costs a byte
        if len(piece) > remaining: piece = piece[:remaining]; ...
        parts.append(piece)

The whole helper is currently untested, and several of its choices only show up
on inputs a naive fixture never produces:

* **Three RemoteObject shapes, in order.** A primitive carries ``value``; an
  object/function carries only ``description`` (``"Array(3)"``, a stack); a bare
  ``undefined``/``null`` carries neither, so its ``type`` is the only text. A
  fixture of string ``value`` args never sees the ``description`` or ``type``
  branch -- drop either and objects log as empty.

* **``"value" in argument`` is membership, not truthiness.** ``console.log(0)`` /
  ``console.log("")`` arrive as ``{"value": 0}`` / ``{"value": ""}``; reading
  them with ``argument.get("value")`` would treat the falsy value as absent and
  fall through to ``description``/``type``, logging ``"number"`` instead of
  ``0``.

* **Non-dict args are skipped, not rendered or crashed on.** A stray non-object
  in ``args`` must be stepped over (``"value" in`` a str is a substring test, and
  ``str.get`` does not exist), not turned into text.

* **The joining space is charged to the budget.** Args are ``" ".join``-ed, and
  the separator costs a byte, so truncation lands mid-join exactly where the cap
  falls -- not one byte late.

These drive the helper directly; the truncation cases shrink ``_MAX_CONSOLE_TEXT``
so the boundary is small and exact.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.web import client as mod
from headless_re_mcp.backends.web.client import _clip_console_text


def test_a_primitive_arg_is_rendered_from_its_value() -> None:
    assert _clip_console_text({"args": [{"type": "string", "value": "hello"}]}) == (
        "hello",
        False,
    )


def test_an_object_arg_falls_back_to_its_description() -> None:
    """No ``value`` on an object; the ``description`` (e.g. ``Array(3)``) is the text."""
    assert _clip_console_text(
        {"args": [{"type": "object", "description": "Array(3)"}]}
    ) == ("Array(3)", False)


def test_a_bare_undefined_arg_falls_back_to_its_type() -> None:
    """Neither value nor description: the type name is all there is to show."""
    assert _clip_console_text({"args": [{"type": "undefined"}]}) == ("undefined", False)


def test_a_non_string_value_is_stringified() -> None:
    assert _clip_console_text({"args": [{"type": "number", "value": 42}]}) == ("42", False)


def test_a_falsy_value_is_still_used_not_treated_as_absent() -> None:
    """``console.log(0)`` must render ``0``, not the type -- membership, not truthiness.

    Reading the arg with ``.get("value")`` would see ``0`` as absent and fall
    through to ``type``, logging ``number``. The ``in`` check keeps the real
    value.
    """
    assert _clip_console_text({"args": [{"type": "number", "value": 0}]}) == ("0", False)
    # An empty-string value is likewise used (then joined), not skipped.
    assert _clip_console_text(
        {"args": [{"type": "string", "value": ""}, {"value": "b"}]}
    ) == (" b", False)


def test_non_dict_args_are_skipped() -> None:
    assert _clip_console_text({"args": ["not-a-dict", {"value": "ok"}]}) == ("ok", False)


def test_multiple_args_are_space_joined() -> None:
    assert _clip_console_text(
        {"args": [{"value": "a"}, {"value": "b"}, {"value": "c"}]}
    ) == ("a b c", False)


def test_no_args_is_empty_and_untruncated() -> None:
    assert _clip_console_text({}) == ("", False)
    assert _clip_console_text({"args": []}) == ("", False)


def test_a_single_oversized_value_is_sliced_to_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mod, "_MAX_CONSOLE_TEXT", 5)
    assert _clip_console_text({"args": [{"value": "abcdefgh"}]}) == ("abcde", True)


def test_the_joining_space_is_charged_against_the_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """First arg fills 3 of 5; the space costs 1, leaving 1 for the second arg.

    So the second three-char arg is sliced to a single char. If the separator
    were free, the second arg would keep two chars and the cut would land late.
    """
    monkeypatch.setattr(mod, "_MAX_CONSOLE_TEXT", 5)
    assert _clip_console_text({"args": [{"value": "abc"}, {"value": "xyz"}]}) == (
        "abc x",
        True,
    )


def test_a_second_arg_is_dropped_when_the_cap_is_already_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the first arg exactly fills the cap, the separator alone trips truncation."""
    monkeypatch.setattr(mod, "_MAX_CONSOLE_TEXT", 5)
    assert _clip_console_text({"args": [{"value": "abcde"}, {"value": "zzz"}]}) == (
        "abcde",
        True,
    )
