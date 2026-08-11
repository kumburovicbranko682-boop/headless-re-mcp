"""Every tool must answer hostile input with an envelope, never an exception.

Clients treat the ok/error envelope as the contract, so a handler that raises
turns a bad argument into a transport-level failure and loses the structured
error the caller needs to react to. Checking this per tool by hand does not
scale to two hundred of them, so the whole surface is exercised at once.
"""

from __future__ import annotations

import contextlib
import io
from typing import Any

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import CommandCatalog

# Excluded because hostile arguments would still do real work rather than fail on
# a bad session. Kept to the minimum: doctor and capabilities.* also touch the
# host but are read-only, so they stay in the probe even though they are slow.
UNSAFE_TO_PROBE = {"artifacts.gc"}

DUMMY: dict[str, Any] = {
    "string": "\u0000nonexistent",
    "integer": 0,
    "number": 0.0,
    "boolean": False,
    "array": [],
    "object": {},
}


def _hostile_arguments(schema: dict[str, Any]) -> dict[str, Any]:
    arguments: dict[str, Any] = {}
    properties = schema.get("properties") or {}
    for name in schema.get("required") or []:
        prop = properties.get(name) or {}
        kind = prop.get("type")
        if isinstance(kind, list):
            kind = kind[0]
        if name == "session_id":
            arguments[name] = "does-not-exist"
        elif kind in DUMMY:
            arguments[name] = DUMMY[kind]
        elif prop.get("enum"):
            arguments[name] = prop["enum"][0]
        else:
            arguments[name] = "does-not-exist"
    return arguments


def test_every_tool_answers_hostile_input_with_an_error_envelope() -> None:
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
        probed = 0
        raised: list[str] = []
        malformed: list[str] = []
        for binding in bindings:
            if binding.name in UNSAFE_TO_PROBE:
                continue
            probed += 1
            spec = catalog.get(binding.name)
            arguments = _hostile_arguments((spec.input_schema if spec else None) or {})
            try:
                # Handlers may log or print while failing; that is not the subject.
                with (
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    result = binding.handler(**arguments)
            except BaseException as exc:  # noqa: BLE001 - this is what we measure
                raised.append(f"{binding.name}: {type(exc).__name__}: {exc}")
                continue
            if not isinstance(result, dict) or "ok" not in result:
                malformed.append(binding.name)
        bound = {binding.name for binding in bindings}
    finally:
        analysis.close_all()

    # A name that no longer exists would silently stop excluding anything, and
    # the comment above would quietly become false.
    assert not UNSAFE_TO_PROBE - bound, UNSAFE_TO_PROBE - bound
    assert probed == len(bound) - len(UNSAFE_TO_PROBE)
    assert raised == [], raised
    assert malformed == [], malformed
