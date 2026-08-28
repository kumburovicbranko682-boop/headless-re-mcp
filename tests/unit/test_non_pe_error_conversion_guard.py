"""A non-PE backend error must never be re-wrapped in a way that drops retryable.

The non-PE backends raise their own error classes (WebError / AdbError /
FridaError / ...), none of which carry a ``retryable`` field. The one correct
way to turn one into the caller's envelope is ``backend_error_as_rpc`` (directly
or via a module's ``_as_rpc``), which derives ``retryable`` from the code so a
transient ``timeout`` is not reported as permanent. The tempting wrong way is to
hand-roll it inline: ``XdbgRpcError(exc.code, exc.message, details=...)``. That
call takes the constructor default ``retryable=False``, so the error surfaces as
a permanent failure an unattended caller will not retry.

This is not hypothetical. The first pass fixed the six ``_as_rpc`` converters,
but the optional-backend Frida methods in ``service_ext`` had their own inline
``except FridaError`` blocks doing exactly this re-wrap -- the same bug, on a
second surface, invisible to the converter tests. This guard scans every core
service module for that shape at its source and fails if any ``except`` handler
binding a non-PE backend error re-wraps it through ``XdbgRpcError(exc.code, ...)``
instead of the helper. A source scan (not a behavioral test) is what catches
the *next* hand-rolled conversion the moment it lands, without a bespoke test
per method.

r2 / ghidra / windbg re-wrap the same way in ``service_ext``, but those are the
PE-adjacent native line, out of this contract's scope, so only the non-PE error
classes are policed here.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp

# The eight non-PE backend error classes (kept in step with the taxonomy guard).
_NON_PE_ERROR_CLASSES = frozenset(
    {
        "WebError",
        "AdbError",
        "FridaError",
        "ProxyError",
        "ApkError",
        "JadxError",
        "ApktoolError",
        "JsReError",
    }
)


def _core_dir() -> Path:
    return Path(headless_re_mcp.__file__).parent / "core"


def _caught_names(handler: ast.ExceptHandler) -> set[str]:
    """The exception class names an ``except`` clause binds (Name or tuple)."""
    node = handler.type
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple):
        return {elt.id for elt in node.elts if isinstance(elt, ast.Name)}
    return set()


def _is_rewrap_call(node: ast.AST, exc_name: str) -> bool:
    """True for ``XdbgRpcError(<exc_name>.code, ...)`` -- the flag-dropping form."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not (isinstance(func, ast.Name) and func.id == "XdbgRpcError"):
        return False
    if not node.args:
        return False
    first = node.args[0]
    return (
        isinstance(first, ast.Attribute)
        and first.attr == "code"
        and isinstance(first.value, ast.Name)
        and first.value.id == exc_name
    )


def _scan() -> tuple[list[tuple[str, str, int]], set[str]]:
    """Return (violations, modules_with_non_pe_handlers).

    A violation is (module, error_class, lineno) for a re-wrap of a bound non-PE
    error. The second value proves the scan actually reached non-PE handlers.
    """
    violations: list[tuple[str, str, int]] = []
    seen_modules: set[str] = set()
    for path in sorted(_core_dir().glob("service*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for handler in ast.walk(tree):
            if not isinstance(handler, ast.ExceptHandler):
                continue
            non_pe = _caught_names(handler) & _NON_PE_ERROR_CLASSES
            if not non_pe:
                continue
            exc_name = handler.name
            if exc_name is None:
                continue
            seen_modules.add(path.stem)
            for stmt in handler.body:
                for sub in ast.walk(stmt):
                    if _is_rewrap_call(sub, exc_name):
                        violations.append((path.stem, sorted(non_pe)[0], sub.lineno))
    return violations, seen_modules


def test_scan_reaches_the_known_non_pe_handlers() -> None:
    """Non-vacuity: a broken scan that matched nothing would pass every other
    assertion here, so pin that the well-known non-PE handlers are actually seen."""
    _, seen = _scan()
    expected = {"service_web", "service_frida", "service_apk", "service_ext"}
    assert expected <= seen, f"the except-handler scan looks broken, saw {sorted(seen)}"


def test_no_non_pe_error_is_rewrapped_dropping_retryable() -> None:
    """Every ``except`` binding a non-PE backend error must convert it through
    ``backend_error_as_rpc`` / ``_as_rpc``, never the inline
    ``XdbgRpcError(exc.code, ...)`` re-wrap that resets retryable to False."""
    violations, _ = _scan()
    assert violations == [], (
        "these except-handlers re-wrap a non-PE backend error inline via "
        "XdbgRpcError(exc.code, ...), dropping retryable (a timeout would read "
        "as permanent); route them through backend_error_as_rpc instead: "
        f"{violations}"
    )
