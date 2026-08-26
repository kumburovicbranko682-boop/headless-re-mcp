"""The Web write adapter is the only guard between /api/write and the facade.

The route whitelists an action and checks confirm, then hands off to
WebCommandAdapter.invoke_write, which is where the real classification lives:
it must refuse anything that is not a WEB-transport write, require a session id
for the session-scoped writes, and treat artifacts.gc as the one write that
takes a byte budget instead. Only the route-level behaviors were tested; the
adapter's own error contract -- especially the session_id_required path -- was
not.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.commands import COMMAND_CATALOG, CommandTransport
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.commands import WebCommandAdapter


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides)


@pytest.fixture
def full_access_catalog() -> object:
    """invoke_write reads the shared catalog's write_allowed; pin it open here."""
    previous = COMMAND_CATALOG.write_allowed
    COMMAND_CATALOG.write_allowed = True
    try:
        yield COMMAND_CATALOG
    finally:
        COMMAND_CATALOG.write_allowed = previous


def test_write_methods_are_exactly_the_web_write_names(full_access_catalog: object) -> None:
    service = AnalysisService(_settings(Path("/tmp")))  # never invoked
    try:
        adapter = WebCommandAdapter(service)
        assert adapter.write_methods == COMMAND_CATALOG.write_names(CommandTransport.WEB)
    finally:
        service.close_all()


def test_a_session_scoped_write_requires_a_session_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, full_access_catalog: object
) -> None:
    service = AnalysisService(_settings(tmp_path))
    try:
        calls: list[str] = []
        monkeypatch.setattr(
            service,
            "close_session",
            lambda sid: calls.append(sid) or Result(ok=True, data={"id": sid}),
        )
        adapter = WebCommandAdapter(service)

        # Missing session id is a ValueError the route renders as 400.
        with pytest.raises(ValueError, match="session_id_required"):
            adapter.invoke_write("session.close", {"confirm": True})
        assert calls == [], "the service must not be touched without a session id"

        # With one, the service method is called with exactly that id.
        result = adapter.invoke_write("session.close", {"session_id": "s1"})
        assert result.ok is True
        assert calls == ["s1"]
    finally:
        service.close_all()


def test_artifacts_gc_takes_a_byte_budget_and_no_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, full_access_catalog: object
) -> None:
    service = AnalysisService(_settings(tmp_path))
    try:
        seen: dict[str, int] = {}

        def fake_gc(*, max_total_bytes: int) -> Result:
            seen["bytes"] = max_total_bytes
            return Result(ok=True, data={"collected": 0})

        monkeypatch.setattr(service, "artifacts_gc", fake_gc)
        adapter = WebCommandAdapter(service)
        result = adapter.invoke_write("artifacts.gc", {"confirm": True, "max_total_bytes": 4096})
        assert result.ok is True
        assert seen["bytes"] == 4096
    finally:
        service.close_all()


def test_unknown_and_non_write_actions_are_refused(
    tmp_path: Path, full_access_catalog: object
) -> None:
    service = AnalysisService(_settings(tmp_path))
    try:
        adapter = WebCommandAdapter(service)
        # A name that is not in the catalog at all.
        with pytest.raises(KeyError):
            adapter.invoke_write("not.a.real.tool", {"confirm": True})
        # A real tool that is read-only must not be reachable as a write, even
        # though it exists -- classification, not mere existence, gates this.
        with pytest.raises(KeyError):
            adapter.invoke_write("artifacts.list", {"confirm": True, "session_id": "s1"})
    finally:
        service.close_all()


def test_a_read_only_catalog_refuses_before_touching_the_service(tmp_path: Path) -> None:
    """write_allowed=False must fail closed with PermissionError, not run."""
    previous = COMMAND_CATALOG.write_allowed
    COMMAND_CATALOG.write_allowed = False
    service = AnalysisService(_settings(tmp_path, local_full_access=False))
    try:
        adapter = WebCommandAdapter(service)
        with pytest.raises(PermissionError):
            adapter.invoke_write("artifacts.gc", {"confirm": True, "max_total_bytes": 1024})
    finally:
        COMMAND_CATALOG.write_allowed = previous
        service.close_all()
