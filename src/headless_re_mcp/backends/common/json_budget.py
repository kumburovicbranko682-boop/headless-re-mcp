"""Bound a large text field by its JSON-encoded size, not its raw byte count.

A tool result is JSON-encoded before it crosses the MCP / agent boundary, and
both transports (``agent.context.bounded_tool_result`` and
``mcp.adapter.apply_result_budget``) replace the *whole* result with a ~16 KiB
summary once the encoded form exceeds ``ResourcePolicy.max_result_bytes`` --
discarding every useful field, not just the oversized one. A client that caps
its inline text by raw UTF-8 byte count cannot prevent that: JSON escaping
(``\\"``, ``\\\\``, ``\\n``, control chars -> ``\\uXXXX``) inflates the encoded
size, so a 400 KB ``source`` or ``code`` field is 500+ KB encoded and always
trips the net. Bound by the encoded size instead, under the same budget, so a
large-but-bounded output comes back cleanly truncated with its other fields
intact rather than nuked to a summary.
"""

from __future__ import annotations

import json

# Mirrors ``tools.catalog.ResourcePolicy.max_result_bytes``. Kept as a plain int
# so this leaf helper does not import the tools layer; ``test_json_budget`` pins
# the two together so they cannot drift.
RESULT_BUDGET_BYTES = 262_144
# Headroom left for the result's other fields (a truncated flag, a byte count,
# ``exit_code`` / ``tool_failed``, a bounded ``stderr`` of up to 8000 chars that
# can encode to ~48 KiB of ``\\uXXXX`` in the worst case, path strings) plus the
# JSON structure, so the *whole* encoded result stays under the budget -- not
# only the text value this helper trims.
_FIELD_RESERVE_BYTES = 64 * 1024


def _encoded_len(text: str) -> int:
    """Bytes ``json.dumps`` would emit for ``text`` as a JSON string value."""
    return len(json.dumps(text, ensure_ascii=False).encode("utf-8"))


def fit_json_text(
    text: str,
    *,
    budget: int | None = None,
    reserve: int | None = None,
) -> tuple[str, int, bool]:
    """Longest prefix of ``text`` whose JSON-encoded value fits the budget.

    Returns ``(inline, original_bytes, truncated)``. ``original_bytes`` is the
    full UTF-8 size before any trimming, so a caller can still report how much
    the real output was. ``truncated`` says whether ``inline`` is shorter than
    ``text``. ``budget`` / ``reserve`` default to the module constants, read at
    call time so a deployment (or a test) can override them.
    """
    effective_budget = RESULT_BUDGET_BYTES if budget is None else budget
    effective_reserve = _FIELD_RESERVE_BYTES if reserve is None else reserve
    original_bytes = len(text.encode("utf-8", errors="replace"))
    target = max(0, effective_budget - effective_reserve)
    # The encoded length is always >= the character count, so any text longer
    # than ``target`` characters cannot fit and must be trimmed; capping the
    # search there keeps a multi-megabyte capture from being re-encoded whole.
    hi = min(len(text), target)
    if hi == len(text) and _encoded_len(text) <= target:
        return text, original_bytes, False
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _encoded_len(text[:mid]) <= target:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo], original_bytes, lo < len(text)
