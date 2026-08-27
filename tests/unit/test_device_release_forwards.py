"""device.release_forwards exposes the forward-table reclaim as a tool.

The backend's release_forwards() was only reachable internally (close_all and
the idle sweep), so a long-lived agent holding a live Android session could
hit the _MAX_FORWARDS cap with no way to reclaim a slot short of tearing every
session down. The backend bookkeeping itself is pinned in
test_adb_forward_bookkeeping.py; what is pinned here is the tool exposure: it
exists, is a write (it mutates the adb server's forward table), takes no
argument, and passes the backend's removed/failed/count report through
faithfully.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import CommandCatalog


def test_release_forwards_is_a_write_tool_with_no_required_args() -> None:
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bind_all_tools(analysis, catalog)
        spec = catalog.get("device.release_forwards")
        assert spec is not None
        # It removes forwards on the adb server, so it must be a write: in
        # restricted mode it has to refuse, not silently tear forwards down.
        assert spec.write is True
        # Process-wide by design -- no serial, no required argument.
        schema = spec.input_schema or {}
        assert not (schema.get("required") or [])
    finally:
        analysis.close_all()


def test_release_forwards_tool_reports_the_backend_result(monkeypatch: Any) -> None:
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        report = {
            "removed": [{"serial": "emulator-5554", "local": "tcp:5000"}],
            "failed": [{"serial": "emulator-5554", "local": "tcp:5001", "error": "offline"}],
            "count": 1,
        }
        monkeypatch.setattr(analysis._adb_backend, "release_forwards", lambda: report)
        bindings = {binding.name: binding for binding in bind_all_tools(analysis, catalog)}
        payload = bindings["device.release_forwards"].handler()
        assert payload["ok"] is True
        data = payload["data"]
        assert data["count"] == 1
        assert data["removed"][0]["local"] == "tcp:5000"
        # count is what was actually torn down, not what was attempted: the
        # slot whose removal failed is reported, not counted as removed.
        assert data["failed"][0]["local"] == "tcp:5001"
    finally:
        analysis.close_all()
