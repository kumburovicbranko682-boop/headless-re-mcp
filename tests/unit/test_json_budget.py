"""The encoded-size text bounder keeps a big field from being nuked in transit."""

from __future__ import annotations

import json

from headless_re_mcp.agent.context import bounded_tool_result
from headless_re_mcp.backends.common.json_budget import (
    RESULT_BUDGET_BYTES,
    fit_json_list,
    fit_json_text,
)
from headless_re_mcp.backends.jsre.client import _bounded_output
from headless_re_mcp.tools.catalog import ResourcePolicy


def test_budget_constant_tracks_the_catalog_policy() -> None:
    """The helper's budget must equal the transport's default, or it is wrong.

    The whole point is to stay under what the transport enforces; if the two
    drift, a client trims to a ceiling nobody checks against.
    """
    assert ResourcePolicy().max_result_bytes == RESULT_BUDGET_BYTES


def test_fit_returns_text_unchanged_when_it_fits() -> None:
    text = "clean output"
    inline, original_bytes, truncated = fit_json_text(text)
    assert inline == text
    assert original_bytes == len(text.encode("utf-8"))
    assert truncated is False


def test_fit_trims_escape_heavy_text_to_the_encoded_budget() -> None:
    # Each unit is 3 raw chars but 5 encoded (\" and \n), so a raw-byte cap
    # would undercount; the encoded bound must catch it.
    body = 'a"\n' * 20_000  # 60000 raw bytes
    inline, original_bytes, truncated = fit_json_text(body, budget=4096, reserve=1024)
    assert truncated is True
    assert original_bytes == len(body.encode("utf-8"))
    assert len(inline) < len(body)
    encoded = len(json.dumps(inline, ensure_ascii=False).encode("utf-8"))
    assert encoded <= 4096 - 1024


def test_fit_never_splits_a_multibyte_character() -> None:
    # All 2-byte chars: a prefix cut must still decode cleanly.
    body = "é" * 10_000
    inline, _original, truncated = fit_json_text(body, budget=1024, reserve=256)
    assert truncated is True
    assert set(inline) <= {"é"}  # no U+FFFD / broken bytes
    inline.encode("utf-8")  # would raise on a lone surrogate


def test_bounded_output_result_survives_the_transport_budget() -> None:
    """A megabyte of tool output must come back cleanly truncated, not summarised.

    Feeds a 1 MiB body through the same helper js.deobfuscate uses and confirms
    the transport (bounded_tool_result) passes it through intact -- the ``code``
    field present and no ``summary`` -- instead of discarding the whole envelope.
    Before the encoded-size bound, a 400 KB inline field always tripped the net.
    """
    huge = "function f(){ return 'x'; }\n" * 40_000  # ~1 MiB
    result = _bounded_output(huge, "code", include_bytes=True)
    assert result["truncated"] is True
    assert result["bytes"] == len(huge.encode("utf-8"))

    bounded, truncated = bounded_tool_result(result, max_bytes=RESULT_BUDGET_BYTES)
    assert truncated is False, "client output should already fit the transport budget"
    assert "summary" not in bounded
    assert "code" in bounded
    assert bounded["truncated"] is True


def test_fit_list_returns_all_items_when_they_fit() -> None:
    items = ["a/b/C.java", "a/b/D.java", "a/e/F.java"]
    kept, dropped, truncated = fit_json_list(items)
    assert kept == items
    assert dropped == 0
    assert truncated is False


def test_fit_list_drops_trailing_items_to_the_encoded_budget() -> None:
    """A listing that sums past the budget must come back shortened, not nuked.

    Each path is short, but 4000 of them encode well past a small budget; the
    count cap alone would not catch that. Confirm fit_json_list keeps a leading
    run whose encoded array fits, drops the rest, and flags it -- so the caller
    can page past ``kept`` instead of losing the whole listing to a summary.
    """
    items = [f"sources/com/example/pkg{i:04d}/GeneratedClass{i:04d}.java" for i in range(4000)]
    kept, dropped, truncated = fit_json_list(items, budget=4096, reserve=1024)
    assert truncated is True
    assert 0 < len(kept) < len(items)
    assert dropped == len(items) - len(kept)
    assert kept == items[: len(kept)]  # order preserved, leading run
    encoded = len(json.dumps(kept, ensure_ascii=False).encode("utf-8"))
    assert encoded <= 4096 - 1024
    # One more element would have overflowed the target.
    over = len(json.dumps(items[: len(kept) + 1], ensure_ascii=False).encode("utf-8"))
    assert over > 4096 - 1024


def test_fit_list_can_drop_everything_when_even_one_item_overflows() -> None:
    kept, dropped, truncated = fit_json_list(["x" * 5000], budget=512, reserve=256)
    assert kept == []
    assert dropped == 1
    assert truncated is True
