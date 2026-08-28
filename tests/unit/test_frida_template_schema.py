"""frida.hook.template must refuse unknown names at the tool schema."""

from __future__ import annotations

import re

from headless_re_mcp.backends.frida import HOOK_TEMPLATE_NAMES
from headless_re_mcp.backends.frida.client import _HOOK_TEMPLATES
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.frida import build_frida_tools


def _template_pattern() -> str:
    handler = next(
        binding.handler
        for binding in build_frida_tools(object())  # type: ignore[arg-type]
        if binding.name == "frida.hook.template"
    )
    return str(input_schema_for(handler)["properties"]["template"]["pattern"])


def test_hook_template_names_view_matches_the_canned_dict() -> None:
    """HOOK_TEMPLATE_NAMES is the ordered public view of _HOOK_TEMPLATES.

    The names view is the single source the schema derives from; if it drifted
    from the dict the schema would accept or reject the wrong set, so pin it to
    the dict's keys in order.
    """
    assert tuple(_HOOK_TEMPLATES) == HOOK_TEMPLATE_NAMES
    # The default template the tool ships must be a real one.
    assert "noop" in HOOK_TEMPLATE_NAMES


def test_frida_hook_template_schema_accepts_exactly_the_canned_names() -> None:
    """The tool schema pattern must enumerate exactly the client's templates.

    The names once lived in three places -- the _HOOK_TEMPLATES dict, a
    hand-written schema regex, and this test's own hardcoded tuple -- and the
    old test only checked its four names were a subset of the dict and equalled
    the regex. That missed the dangerous drift: a template added to the dict but
    not the regex is silently rejected at the schema before the client is ever
    reached, and the subset check still passed. Now the schema derives its
    pattern from the dict, so assert the pattern is exactly the one built from
    the live template names -- add a template and this stays green; desync the
    two and it fails.
    """
    expected = "^(" + "|".join(re.escape(name) for name in tuple(_HOOK_TEMPLATES)) + ")$"
    pattern = _template_pattern()
    assert pattern == expected

    # And the pattern must actually admit every canned name and reject others,
    # not merely string-match the expected regex.
    compiled = re.compile(pattern)
    for name in _HOOK_TEMPLATES:
        assert compiled.match(name), f"schema rejects a real template: {name}"
    assert not compiled.match("android_paste_arbitrary_js")
    assert not compiled.match("noop_extra")
