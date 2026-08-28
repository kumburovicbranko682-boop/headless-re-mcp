"""Every dynamic Markdown heading in the report renderer must be sanitized.

Two fixes landed for the same bug, one after another: the H1 title and then the
``### {kind}`` finding-group heading each interpolated caller/finding text
straight into an ATX heading, bypassing ``_cell``. A value carrying a newline
split the ``#``/``###`` line and injected arbitrary document structure after it,
and an unbounded one grew the persisted report without limit. Both were fixed by
routing the value through ``_inline`` / ``_heading`` (newline-to-space + clip);
every other value already flows through ``_cell`` inside ``_table``.

This pins that invariant so a third heading cannot ship raw. It parses
``reporting.py`` and, for every f-string whose literal text begins with a
Markdown ATX ``#`` heading, requires each interpolated slot to be a call to
``_inline`` / ``_heading`` (the sanitizers) or ``len`` (a count, always an int) --
directly, or via a local ``name = _heading(...)`` assignment. A bare name,
attribute, or subscript in a heading slot is exactly the shape both bugs had, so
it fails here at the layer the report is rendered.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp

_SAFE_HEADING_CALLS = frozenset({"_inline", "_heading", "len"})


def _reporting_tree() -> ast.AST:
    path = Path(headless_re_mcp.__file__).parent / "reporting.py"
    return ast.parse(path.read_text(encoding="utf-8"))


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _enclosing_func(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = parents.get(cur)
    return None


def _is_heading_fstring(node: ast.JoinedStr) -> bool:
    """True when the f-string's leading literal is a Markdown ATX heading.

    A heading always starts with a constant ``"# "`` / ``"### "``; if the first
    part is a slot it is not one of these, so only the constant-led case counts.
    """
    first = node.values[0] if node.values else None
    return (
        isinstance(first, ast.Constant)
        and isinstance(first.value, str)
        and first.value.lstrip().startswith("#")
    )


def _resolve(expr: ast.expr, fn: ast.FunctionDef | ast.AsyncFunctionDef | None) -> ast.expr:
    """Follow a simple ``name = <expr>`` assignment within ``fn`` once.

    Lets a slot written as ``{heading}`` be judged by what ``heading`` was
    assigned (``_heading(...)``), the one indirection the renderer uses.
    """
    if isinstance(expr, ast.Name) and fn is not None:
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == expr.id for target in node.targets
            ):
                return node.value
    return expr


def _is_safe_slot(expr: ast.expr, fn: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
    resolved = _resolve(expr, fn)
    return (
        isinstance(resolved, ast.Call)
        and isinstance(resolved.func, ast.Name)
        and resolved.func.id in _SAFE_HEADING_CALLS
    )


def _heading_slots() -> list[tuple[str, list[ast.expr]]]:
    """(rendered f-string, its interpolated slots) for every heading f-string."""
    tree = _reporting_tree()
    found: list[tuple[str, list[ast.expr]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr) and _is_heading_fstring(node):
            slots = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
            found.append((ast.unparse(node), slots))
    return found


def test_scan_reaches_the_known_headings() -> None:
    """Non-vacuity: the title and finding-kind headings must both be in the scan,
    or a broken detector would let the safety check pass on an empty set."""
    rendered = [text for text, _ in _heading_slots()]
    assert any(text.startswith("f'# ") or text.startswith('f"# ') for text in rendered), rendered
    assert any("###" in text for text in rendered), rendered
    # Both dynamic headings interpolate something -- a scan that found only
    # constant headings ("## Session") would be missing the risky ones.
    assert any(slots for _, slots in _heading_slots()), "no interpolated heading slots found"


def test_every_dynamic_heading_slot_is_sanitized() -> None:
    tree = _reporting_tree()
    parents = _parents(tree)
    fn_by_node: dict[int, ast.FunctionDef | ast.AsyncFunctionDef | None] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr) and _is_heading_fstring(node):
            fn_by_node[id(node)] = _enclosing_func(node, parents)

    offenders: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.JoinedStr) and _is_heading_fstring(node)):
            continue
        fn = fn_by_node[id(node)]
        for slot in (v.value for v in node.values if isinstance(v, ast.FormattedValue)):
            if not _is_safe_slot(slot, fn):
                offenders.append(f"{ast.unparse(node)!r}: slot {ast.unparse(slot)!r}")
    assert offenders == [], (
        "these report headings interpolate a value that is not routed through "
        "_inline / _heading (or a len() count), so a newline in it would inject a "
        "heading and an unbounded value would bloat the persisted report -- the "
        f"exact bug fixed for the title and kind headings: {offenders}"
    )
