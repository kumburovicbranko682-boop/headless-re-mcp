"""A mostly-unresolved import table blocks rebuild, except for half-sparse layouts.

An IAT where more than half the slots never resolved is not a rebuild
candidate: stitching it into the header would produce an import directory that
mostly points at garbage, and the loader would reject or crash the dump. The
one deliberate carve-out is the half_sparse layout, where a large unresolved
tail is the expected shape rather than evidence of a bad scan.
"""

from __future__ import annotations

from headless_re_mcp.unpack.iat_rank import _rebuild_block_reason


def test_a_majority_unresolved_table_blocks_the_rebuild() -> None:
    reason = _rebuild_block_reason(
        layout="dense",
        api=12,
        ime_only=False,
        unresolved_ratio=0.51,
    )

    assert reason == "unresolved_ratio_high"


def test_a_half_sparse_layout_tolerates_a_high_unresolved_ratio() -> None:
    # The same ratio that blocks a dense table is the expected shape for
    # half_sparse, so no reason is returned and the rebuild may proceed.
    reason = _rebuild_block_reason(
        layout="half_sparse",
        api=12,
        ime_only=False,
        unresolved_ratio=0.9,
    )

    assert reason is None
