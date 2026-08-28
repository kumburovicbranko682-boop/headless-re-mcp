"""Every non-PE backend error code must be in the canonical taxonomy.

An agent routes on ``error.code``: it retries some, surfaces others, and has a
default arm for the rest. ``backend_error_as_rpc`` and ``_failure`` also derive
``retryable`` from the code. So a code that is a typo (``not_fund``) or a one-off
synonym (``bad_request`` for ``invalid_params``) is not a cosmetic slip -- it
escapes ``_RETRYABLE_BACKEND_CODES`` (a transient fault then reads as permanent)
and falls into the agent's catch-all, which is exactly the silent misroute an
unattended run cannot notice.

The eight non-PE backends already share one taxonomy -- backend_error,
capability_unavailable, invalid_params, invalid_state, not_found,
permission_denied, timeout, too_large -- and ``results._NON_PE_BACKEND_ERROR_CODES``
is its single source of truth. This guard pins it: it AST-scans every non-PE
backend ``client.py`` for the literal code passed to a backend error class and
fails if one is outside the canonical set. It is fail-closed the other way too --
a canonical code that no backend raises must be dropped, so the taxonomy tracks
real usage rather than accreting dead entries -- and it checks the retryable set
is a subset, so a retryable code can never be one the taxonomy does not name.

Dynamic re-raises (``ApkError(exc.code, ...)`` passing a jadx/apktool code
through) carry a first arg that is not a literal; those are skipped because the
code they forward was itself minted at a literal raise the scan already checks.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp
from headless_re_mcp.core.results import (
    _NON_PE_BACKEND_ERROR_CODES,
    _RETRYABLE_BACKEND_CODES,
)

_NON_PE_BACKENDS = frozenset(
    {"web", "proxy", "adb", "frida", "apk", "jsre", "jadx", "apktool"}
)

# The backend error classes whose first positional arg is the routing code.
_ERROR_CLASSES = frozenset(
    {
        "WebError",
        "ProxyError",
        "AdbError",
        "FridaError",
        "ApkError",
        "JadxError",
        "ApktoolError",
        "JsReError",
    }
)


def _backends_dir() -> Path:
    return Path(headless_re_mcp.__file__).parent / "backends"


def _raised_codes() -> dict[str, set[str]]:
    """backend -> the set of literal error codes raised in its client.py."""
    found: dict[str, set[str]] = {}
    for path in sorted(_backends_dir().glob("*/client.py")):
        backend = path.parent.name
        if backend not in _NON_PE_BACKENDS:
            continue
        codes: set[str] = set()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Name) or func.id not in _ERROR_CLASSES:
                continue
            if not node.args:
                continue
            first = node.args[0]
            # Only literal codes are checkable; a dynamic passthrough
            # (ApkError(exc.code, ...)) forwards a code minted elsewhere.
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                codes.add(first.value)
        found[backend] = codes
    return found


def test_scan_reaches_the_backend_error_raises() -> None:
    """Non-vacuity: the scan must see the core codes raised across most backends,
    or a broken enumeration would let the taxonomy check pass on an empty set.
    """
    raised = _raised_codes()
    union = set().union(*raised.values()) if raised else set()
    # The four codes every backend has, seen somewhere in the scan.
    assert {"invalid_params", "not_found", "backend_error", "capability_unavailable"} <= union, (
        f"the error-raise scan looks broken, saw {sorted(union)}"
    )
    # And it must reach raises in most of the backends, not just one file.
    backends_that_raise = {b for b, codes in raised.items() if codes}
    assert len(backends_that_raise) >= 6, (
        f"only {sorted(backends_that_raise)} raise literal codes; scan looks broken"
    )


def test_every_raised_code_is_canonical() -> None:
    raised = _raised_codes()
    rogue = sorted(
        (backend, code)
        for backend, codes in raised.items()
        for code in codes
        if code not in _NON_PE_BACKEND_ERROR_CODES
    )
    assert rogue == [], (
        "these non-PE backends raise a code outside "
        "results._NON_PE_BACKEND_ERROR_CODES, so an agent routing on code would "
        "misroute it (and it would read as a permanent failure); fix the typo or "
        f"add the code to the canonical taxonomy with intent: {rogue}"
    )


def test_no_canonical_code_is_unused() -> None:
    """Fail-closed the other way: a canonical code raised by no backend is dead
    taxonomy. Dropping it keeps the set a live record of the codes actually in
    use, the same anti-rot rule the paging guard's allowlist holds.
    """
    raised = _raised_codes()
    union = set().union(*raised.values()) if raised else set()
    unused = sorted(_NON_PE_BACKEND_ERROR_CODES - union)
    assert unused == [], (
        "these canonical codes are raised by no non-PE backend; drop them from "
        f"results._NON_PE_BACKEND_ERROR_CODES or they rot into noise: {unused}"
    )


def test_retryable_codes_are_a_subset_of_the_taxonomy() -> None:
    assert _RETRYABLE_BACKEND_CODES <= _NON_PE_BACKEND_ERROR_CODES, (
        "a retryable backend code is not in the canonical taxonomy: "
        f"{sorted(_RETRYABLE_BACKEND_CODES - _NON_PE_BACKEND_ERROR_CODES)}"
    )
