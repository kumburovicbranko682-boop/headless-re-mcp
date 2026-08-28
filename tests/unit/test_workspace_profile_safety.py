"""No workspace profile may hide a control/core tool or use a dot-less prefix.

A profile trims the MCP surface by dotted-name prefix (``core/workspace.py``).
Two invariants keep that trim from cutting into the bone, and neither was pinned:

1. The profile switcher itself -- ``workspace.mode.get`` *and*
   ``workspace.mode.set`` -- plus the always-core session / observability /
   artifact commands must survive *every* profile. Hide ``workspace.mode.set``
   and an MCP client that switched into, say, the ``pe`` profile has no in-band
   way back to ``full``: it is locked into a narrowed surface with no command to
   widen it again. ``test_workspace_profiles`` only checked ``workspace.mode.get``
   in the ``pe`` profile; ``.set``, and every other profile, went unguarded.

2. Every excluded prefix must end in ``.``. Matching is ``str.startswith`` over
   the raw prefix, so a dot-less ``web`` would also swallow a future
   ``webhook.*`` tool, and a short prefix could reach a core name outright. The
   trailing dot is exactly what keeps ``device.`` from hiding ``devices.*`` and
   bounds each prefix to its own domain.

The always-visible names are cross-checked against the real catalog first, so a
rename cannot let the visibility assertions pass on a tool that no longer exists.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.core.workspace import PROFILES, excluded_prefixes, is_tool_visible
from headless_re_mcp.tools.catalog import CommandCatalog

# Tools that must never be trimmed by any profile: the profile switcher (or a
# client can lock itself into a narrowed surface) plus a spread of core
# session / observability / artifact / knowledge commands every workflow needs.
_ALWAYS_VISIBLE = (
    "workspace.mode.get",
    "workspace.mode.set",
    "session.create",
    "session.close",
    "audit.list",
    "timeline.list",
    "meta.metrics",
    "artifacts.list",
    "knowledge.query",
)


def test_the_always_visible_tools_are_real_tools() -> None:
    """Non-vacuity: pin that each guarded name is an actually-declared tool, so a
    rename cannot make the visibility checks below pass on a name nobody serves."""
    catalog = CommandCatalog()
    missing = [name for name in _ALWAYS_VISIBLE if catalog.get(name) is None]
    assert missing == [], f"these guarded tool names are not in the catalog: {missing}"


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("tool", _ALWAYS_VISIBLE)
def test_core_and_control_tools_survive_every_profile(tool: str, profile: str) -> None:
    assert is_tool_visible(tool, profile), (
        f"{tool} is hidden by the {profile!r} profile; a trimmed surface must keep "
        "the profile switcher and the core session/observability tools, or a client "
        "cannot widen its own surface again"
    )


@pytest.mark.parametrize("profile", PROFILES)
def test_every_excluded_prefix_ends_with_a_dot(profile: str) -> None:
    for prefix in excluded_prefixes(profile):
        assert prefix.endswith("."), (
            f"the {profile!r} profile excludes {prefix!r}, which has no trailing dot: "
            "str.startswith would over-match sibling names (e.g. 'web' swallowing "
            "'webhook.*') and could reach a core tool"
        )
