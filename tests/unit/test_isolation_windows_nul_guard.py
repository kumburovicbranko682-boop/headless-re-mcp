"""The Windows command splitter's NUL sentinel must be collision-proof."""

from __future__ import annotations

import pytest

from headless_re_mcp.core import isolation


def test_a_command_containing_nul_is_refused_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The splitter protects backslashes by swapping them for NUL and back. A
    # NUL already present in the operator's command would be turned into a
    # backslash it never contained -- so it is refused up front.
    monkeypatch.setattr(isolation, "is_windows_host", lambda: True)

    with pytest.raises(ValueError, match="must not contain NUL"):
        isolation._split_command("revert.ps1 \x00 --force")


def test_windows_paths_keep_their_backslashes_through_the_split(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation, "is_windows_host", lambda: True)

    parts = isolation._split_command('C:\\vm\\revert.ps1 "-Name clean snapshot"')

    assert parts == ("C:\\vm\\revert.ps1", "-Name clean snapshot")
