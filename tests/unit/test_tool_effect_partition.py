"""The tool effect sets must be a clean partition, not merely sum to 265.

``tools/catalog.py`` declares every tool's effect in exactly one of
``_READ_ONLY_NAMES`` / ``_STATE_CHANGE_NAMES`` / ``_FILE_WRITE_NAMES``, and
``_declared_spec`` resolves a name by checking the sets in that order. The
import-time guard only compares the union's size against 265, and a union
deduplicates: move a mutating tool by pasting its name into the read-only set
and forgetting to delete the old entry, and -- as soon as any other name is
dropped, keeping the count at 265 -- the guard still passes while the tool
silently resolves to read_only. That strips its write guard and confirmation
prompt, which is the dangerous direction. Pin the partition property itself so
that this drift fails in CI with the offending names spelled out, instead of
surviving until someone notices a mutating tool auto-executing.
"""

from __future__ import annotations

from headless_re_mcp.tools import catalog


def test_tool_effect_sets_are_pairwise_disjoint() -> None:
    """A name present in two effect sets resolves to whichever is checked first.

    The overlap itself is the bug: ``_declared_spec`` cannot represent "both",
    so a duplicated name is silently downgraded to the earlier set. Name the
    offenders so the failure is actionable.
    """
    conflicting = sorted(
        (catalog._READ_ONLY_NAMES & catalog._STATE_CHANGE_NAMES)
        | (catalog._READ_ONLY_NAMES & catalog._FILE_WRITE_NAMES)
        | (catalog._STATE_CHANGE_NAMES & catalog._FILE_WRITE_NAMES)
    )
    assert conflicting == [], f"tools classified with conflicting effects: {conflicting}"


def test_tool_effect_set_sizes_sum_to_the_union() -> None:
    """The three set sizes must sum to the union's 265: nothing hides in a dedup.

    The import-time guard checks only ``len(union) == 265``; this pins the
    stronger property that no duplicate is being cancelled out by an omission.
    """
    effect_total = (
        len(catalog._READ_ONLY_NAMES)
        + len(catalog._STATE_CHANGE_NAMES)
        + len(catalog._FILE_WRITE_NAMES)
    )
    assert effect_total == len(catalog._ALL_TOOL_NAMES) == 265
