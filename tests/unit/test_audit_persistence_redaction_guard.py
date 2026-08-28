"""Every audit persistence path must redact secrets, or delegate to one that does.

The audit log is durable: rows survive the process and are read back by
``audit.list``. Callers already hand-pick secret-free ``params_summary`` dicts
(``{"serial": serial}``, ``{"template": template}`` ...), but the guarantee that
a credential never lands on disk in the clear rests on every ``append_audit``
implementation running ``redact_audit_payload`` (which is just ``redact``, the
same masker the timeline uses) over both the params and the result before it
persists them. Today the SQLite store and the in-memory repository each do this
and the repository facade delegates to the store -- but that is discipline, not
a mechanism. A new store backend, or a facade that grew a direct write, could
persist raw payloads and no test would notice until a token showed up in a dump.

This pins the invariant structurally, the sibling of the adb shell-command
allowlist: every non-stub ``append_audit`` in the persistence layer must either
pass BOTH ``params_summary`` and ``result_summary`` through ``redact`` /
``redact_audit_payload``, or delegate to another ``append_audit`` (which
transitively redacts). Protocol stubs (a bare ``...`` body) are exempt because
they persist nothing. A companion check pins that ``redact_audit_payload`` really
is ``redact`` underneath, so the audit path cannot silently diverge from the
timeline's masker.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp

_REDACTORS = frozenset({"redact", "redact_audit_payload"})
_AUDIT_PAYLOADS = frozenset({"params_summary", "result_summary"})


def _persistence_sources() -> dict[str, str]:
    root = Path(headless_re_mcp.__file__).parent
    paths = [root / "core" / "repository.py", root / "core" / "store" / "sqlite_store.py"]
    return {str(path): path.read_text(encoding="utf-8") for path in paths}


def _funcs_named(tree: ast.AST, name: str) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]


def _is_stub(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A Protocol/ABC body: only a docstring, ``...`` and/or ``pass``."""
    for stmt in fn.body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        return False
    return True


def _redacted_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Argument names passed to a redact-family call anywhere in the body."""
    names: set[str] = set()
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _REDACTORS
        ):
            names.update(arg.id for arg in node.args if isinstance(arg, ast.Name))
    return names


def _delegates(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether the body forwards to another ``.append_audit(...)``."""
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "append_audit"
        for node in ast.walk(fn)
    )


def _classify() -> dict[tuple[str, int], str]:
    """(file, lineno) -> one of 'stub' / 'redacts' / 'delegates' / 'UNSAFE'."""
    verdict: dict[tuple[str, int], str] = {}
    for path, source in _persistence_sources().items():
        tree = ast.parse(source)
        for fn in _funcs_named(tree, "append_audit"):
            key = (Path(path).name, fn.lineno)
            if _is_stub(fn):
                verdict[key] = "stub"
            elif _redacted_names(fn) >= _AUDIT_PAYLOADS:
                verdict[key] = "redacts"
            elif _delegates(fn):
                verdict[key] = "delegates"
            else:
                verdict[key] = "UNSAFE"
    return verdict


def test_scan_reaches_both_a_redactor_and_a_delegator() -> None:
    """Non-vacuity: the scan must find the real implementations, so a broken
    walk cannot let the safety check below pass on an empty set."""
    verdicts = list(_classify().values())
    assert verdicts.count("redacts") >= 2, (
        f"expected the store + in-memory redactors, saw {verdicts}"
    )
    assert "delegates" in verdicts, f"expected the facade delegator, saw {verdicts}"
    assert "stub" in verdicts, f"expected the Protocol stub, saw {verdicts}"


def test_every_audit_persistence_path_redacts_or_delegates() -> None:
    unsafe = sorted(key for key, verdict in _classify().items() if verdict == "UNSAFE")
    assert unsafe == [], (
        "these append_audit implementations neither redact both params_summary and "
        "result_summary nor delegate to one that does, so a credential could be "
        f"persisted to the durable audit log in the clear: {unsafe}"
    )


def test_redact_audit_payload_is_the_redact_masker_underneath() -> None:
    """The audit redactor must not diverge from the timeline's ``redact``.

    ``redact_audit_payload`` exists to keep a stable mask; if it stopped calling
    ``redact`` it could quietly weaken to a no-op while every ``append_audit``
    still looked like it was redacting.
    """
    sources = _persistence_sources()
    store = next(src for path, src in sources.items() if path.endswith("sqlite_store.py"))
    fns = _funcs_named(ast.parse(store), "redact_audit_payload")
    assert len(fns) == 1, "expected exactly one redact_audit_payload definition"
    calls_redact = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "redact"
        for node in ast.walk(fns[0])
    )
    assert calls_redact, "redact_audit_payload must delegate to redact"
