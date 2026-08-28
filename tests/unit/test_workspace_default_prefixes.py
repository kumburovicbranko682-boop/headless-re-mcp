"""excluded_prefixes falls back to hiding nothing for an unmapped profile.

The four shipped profiles are each handled explicitly. The trailing return is
the safety net: if a new profile is added to PROFILES but nobody wires its
prefixes, the surface must default to showing every tool rather than raising
mid-request. Pin that by extending PROFILES with an unmapped name.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.core import workspace


def test_excluded_prefixes_hides_nothing_for_an_unmapped_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(workspace, "PROFILES", (*workspace.PROFILES, "experimental"))
    assert workspace.excluded_prefixes("experimental") == ()
    assert workspace.is_tool_visible("apk.open", "experimental") is True
