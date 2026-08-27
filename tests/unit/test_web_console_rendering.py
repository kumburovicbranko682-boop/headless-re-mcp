"""Console-rendering contract: CDP RemoteObject args -> readable, JS-faithful text.

These are the always-on guards for the console fix. The live gate proves the
whole path against a real Chromium, but it only runs where Playwright and a
browser are installed; the unit suite runs everywhere, so the exact rendering
contract is pinned here too, driven by synthetic-but-real CDP
``Runtime.consoleAPICalled`` shapes.

Two things are locked down:

  * ``_js_console_scalar`` maps a JS boolean or ``null`` back to its JS spelling
    with identity checks, so ``true``/``false``/``null`` no longer read as
    Python's ``True``/``False``/``None`` -- while the string ``"True"`` and the
    number ``0`` are left untouched (``0`` is not the boolean ``false``); and
  * ``_clip_console_text`` picks a RemoteObject's ``value`` first, then its
    ``description`` (objects/functions), then its ``type`` (``undefined``),
    joins args with single spaces, skips non-dict args, and stops at
    ``_MAX_CONSOLE_TEXT`` reporting truncation.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_CONSOLE_TEXT,
    _clip_console_text,
    _js_console_scalar,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (True, "true"),
        (False, "false"),
        (None, "null"),
        # A string that happens to spell a Python bool is data, not a boolean:
        # identity checks leave it exactly as logged.
        ("True", "True"),
        ("false", "false"),
        ("hello", "hello"),
        # Numbers already render faithfully; 0 must not collapse to "false".
        (0, "0"),
        (1, "1"),
        (42, "42"),
        (3.5, "3.5"),
    ],
)
def test_js_console_scalar_maps_js_primitives(raw: object, expected: str) -> None:
    assert _js_console_scalar(raw) == expected


def _console_params(*args: dict[str, object]) -> dict[str, object]:
    """A Runtime.consoleAPICalled params dict carrying these RemoteObject args."""
    return {"type": "log", "args": list(args)}


def test_clip_console_text_renders_js_primitives_with_js_spelling() -> None:
    # The exact RemoteObject shapes CDP delivers for console.log(
    #   "s", 42, true, false, null, undefined):
    params = _console_params(
        {"type": "string", "value": "s"},
        {"type": "number", "value": 42},
        {"type": "boolean", "value": True},
        {"type": "boolean", "value": False},
        {"type": "object", "subtype": "null", "value": None},
        {"type": "undefined"},
    )
    text, truncated = _clip_console_text(params)
    assert text == "s 42 true false null undefined"
    assert truncated is False
    # The bug's signature must be absent.
    assert "True" not in text and "False" not in text and "None" not in text


def test_clip_console_text_prefers_value_then_description_then_type() -> None:
    params = _console_params(
        # value present -> value wins even when a description is also there.
        {"type": "number", "value": 7, "description": "7"},
        # no value, object -> description (what CDP gives for {a:1} / arrays).
        {"type": "object", "className": "Object", "description": "Object"},
        # neither value nor description -> the type name (undefined).
        {"type": "undefined"},
    )
    text, truncated = _clip_console_text(params)
    assert text == "7 Object undefined"
    assert truncated is False


def test_clip_console_text_zero_is_not_the_boolean_false() -> None:
    params = _console_params(
        {"type": "number", "value": 0},
        {"type": "boolean", "value": False},
    )
    text, _ = _clip_console_text(params)
    # Two distinct tokens: the number 0 and the boolean false, not "false false".
    assert text == "0 false"


def test_clip_console_text_skips_non_dict_args() -> None:
    # CDP always sends dict args, but the renderer defends against a stray
    # non-dict rather than crashing the capture callback.
    params: dict[str, object] = {
        "type": "log",
        "args": [{"type": "string", "value": "keep"}, "not-a-remote-object", 123],
    }
    text, truncated = _clip_console_text(params)
    assert text == "keep"
    assert truncated is False


def test_clip_console_text_truncates_an_oversized_argument() -> None:
    huge = "x" * (_MAX_CONSOLE_TEXT + 100)
    params = _console_params({"type": "string", "value": huge})
    text, truncated = _clip_console_text(params)
    assert truncated is True
    assert len(text) <= _MAX_CONSOLE_TEXT


def test_clip_console_text_handles_no_args() -> None:
    text, truncated = _clip_console_text({"type": "log"})
    assert text == ""
    assert truncated is False
