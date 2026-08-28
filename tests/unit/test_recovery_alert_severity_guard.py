"""A recovery alert must be emitted at ``severity="info"``, never warning.

``record_alert`` defaults ``severity`` to ``"warning"`` because most alerts are
bad news an operator should see. A *recovery* is the opposite: it says a
previously-failing subsystem is working again, which ``test_watchdog`` puts
plainly -- "recovery is reported at info: it is a fact to record, not a page."
The whole codebase follows that: ``backend_recovered``,
``session_health_recovered``, ``artifact_usage_measurement_recovered`` and
``event_drain_recovered`` all pass ``severity="info"`` explicitly.

``artifact_collection_recovered`` did not -- it took the default warning, so an
operator alerting on ``severity>=warning`` was paged when artifact collection
*recovered*. It slipped in because the one test on it only asserted the alert
*kind*, never its severity. This scans every ``record_alert`` / ``_alert`` call
in the package whose kind literal ends in ``_recovered`` and fails unless it
passes ``severity="info"``, so the next recovery alert added anywhere cannot
quietly reintroduce the warning-level page. The convention is one-directional:
a non-recovery alert may still legitimately be info (``provider_retry`` is), so
only ``*_recovered`` kinds are policed here.

A source scan, not a behavioural test: the alerts fan out across core/, agent/
and top-level modules and are emitted from failure paths that are awkward to
drive, so pinning the shape at its source is what catches a new one the moment
it lands.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp

# Both spellings that ultimately reach ``record_alert``: the free function and
# the watchdog's ``self._alert`` forwarder (which shares the warning default).
_ALERT_CALL_NAMES = frozenset({"record_alert", "_alert"})


def _package_dir() -> Path:
    return Path(headless_re_mcp.__file__).parent


def _alert_kind(node: ast.Call) -> str | None:
    """The literal alert kind if this is an alert call with a string-literal kind."""
    func = node.func
    is_alert = (isinstance(func, ast.Name) and func.id in _ALERT_CALL_NAMES) or (
        isinstance(func, ast.Attribute) and func.attr in _ALERT_CALL_NAMES
    )
    if not is_alert or not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _severity_literal(node: ast.Call) -> str | None:
    """The ``severity=`` keyword's literal value, or None when absent/non-literal.

    ``severity`` is keyword-only on both ``record_alert`` and ``_alert``, so a
    missing keyword means the ``"warning"`` default -- reported here as None so a
    recovery alert that forgot it counts as a violation, exactly like the bug.
    """
    for keyword in node.keywords:
        if keyword.arg == "severity":
            value = keyword.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
            return None
    return None


def _scan() -> tuple[list[tuple[str, str, int, str | None]], set[str]]:
    """Return (violations, recovery_kinds_seen).

    A violation is (module, kind, lineno, severity) for a ``*_recovered`` alert
    not emitted at info. The second value proves the scan reached real recovery
    alerts, so a scan that matched nothing cannot pass silently.
    """
    violations: list[tuple[str, str, int, str | None]] = []
    recovery_kinds: set[str] = set()
    for path in sorted(_package_dir().rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kind = _alert_kind(node)
            if kind is None or not kind.endswith("_recovered"):
                continue
            recovery_kinds.add(kind)
            if _severity_literal(node) != "info":
                violations.append((path.stem, kind, node.lineno, _severity_literal(node)))
    return violations, recovery_kinds


def test_scan_reaches_the_known_recovery_alerts() -> None:
    """Non-vacuity: a scan that matched nothing would pass the guard below, so
    pin that the well-known recovery alerts are actually seen at their source."""
    _, seen = _scan()
    expected = {
        "backend_recovered",
        "session_health_recovered",
        "artifact_collection_recovered",
        "artifact_usage_measurement_recovered",
        "event_drain_recovered",
    }
    assert expected <= seen, f"the recovery-alert scan looks broken, saw {sorted(seen)}"


def test_every_recovery_alert_is_reported_at_info() -> None:
    """A ``*_recovered`` alert must pass ``severity="info"`` -- recovery is a fact
    to record, not a warning-level page. The default warning is for the failure."""
    violations, _ = _scan()
    assert violations == [], (
        "these recovery alerts are not emitted at info, so an operator alerting on "
        "warnings is paged when the subsystem recovers; add severity=\"info\" like "
        f"every other *_recovered alert: {violations}"
    )
