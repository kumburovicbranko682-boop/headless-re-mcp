"""workspace.mode.set must refuse unknown profiles at the tool schema."""

from __future__ import annotations

import re

from headless_re_mcp.core.workspace import PROFILES
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.workspace import build_workspace_tools


def _profile_pattern() -> str:
    handler = next(
        binding.handler
        for binding in build_workspace_tools(object())  # type: ignore[arg-type]
        if binding.name == "workspace.mode.set"
    )
    return str(input_schema_for(handler)["properties"]["profile"]["pattern"])


def test_workspace_mode_set_schema_accepts_exactly_the_known_profiles() -> None:
    """The tool schema pattern must enumerate exactly core.workspace.PROFILES.

    The profile names once lived in three places -- the PROFILES tuple, a
    hand-written schema regex, and this test's own hardcoded copies -- and the
    old test string-matched the exact tuple literal and asserted the exact
    regex independently. That missed the drift that matters: a profile added to
    PROFILES but not the regex is silently rejected at the schema before the
    service ever normalizes it, and the two independent assertions could each be
    "fixed" without the schema being updated. Now the schema derives its pattern
    from PROFILES, so pin the pattern to the one built from the live tuple -- add
    a profile and this stays green; desync the two and it fails.
    """
    expected = "^(" + "|".join(re.escape(profile) for profile in PROFILES) + ")$"
    pattern = _profile_pattern()
    assert pattern == expected

    # And it must actually admit every known profile and reject others, not just
    # string-match the expected regex.
    compiled = re.compile(pattern)
    for profile in PROFILES:
        assert compiled.match(profile), f"schema rejects a real profile: {profile}"
    assert not compiled.match("nonsense")
    assert not compiled.match("fullish")
