"""Agent-driven page actions must leave an audit trail -- minus the secrets.

The console is an Agent workbench, and its session timeline is the record of
what the agent did. Before this, only web.open / web.close / web.screenshot /
web.har.export reached the timeline, so a multi-step flow the agent actually
drove -- navigate, click, fill a field, wait for the result -- left no trace:
the transcript showed the tool calls, but the durable per-session log did not,
so anything reading the timeline after the fact (the console's activity strip,
an audit) saw a browser that opened and did nothing.

These pin that navigate/click/type/wait now record a timeline entry with their
identifying fields, that web.type records the selector and length but never the
typed text (a filled password or token must not leak into the audit log any
more than into the result), that a failed action records nothing, and that a
timeline-write failure cannot turn an action that already happened into a
failed tool call. A fake backend stands in for the browser so the service-level
wiring is what is exercised, without Playwright.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


class _FakeWeb:
    """Returns what the real backend returns, without a browser."""

    def __init__(self, *, click_fails: bool = False) -> None:
        self._click_fails = click_fails

    def navigate(self, session_id: str, url: str, *, timeout: float = 30.0) -> dict[str, Any]:
        return {"url": url, "title": "T"}

    def click(self, session_id: str, selector: str, *, timeout: float = 5.0) -> dict[str, Any]:
        if self._click_fails:
            raise WebError("backend_error", "element is not visible", selector=selector)
        return {"clicked": True, "selector": selector, "url": "https://app/next", "title": "T"}

    def type_text(
        self, session_id: str, selector: str, text: str, *, timeout: float = 5.0
    ) -> dict[str, Any]:
        return {"typed": True, "selector": selector, "length": len(text)}

    def wait_selector(
        self, session_id: str, selector: str, *, state: str = "visible", timeout: float = 5.0
    ) -> dict[str, Any]:
        return {"waited": True, "selector": selector, "state": state}

    def close(self, session_id: str) -> dict[str, Any]:
        return {"closed": False}

    def close_all(self) -> None:
        return None


def _service(tmp_path: Path, **web_kwargs: Any) -> tuple[AnalysisService, str]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._web_backend = _FakeWeb(**web_kwargs)  # type: ignore[assignment]
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"]


def _events(service: AnalysisService, session_id: str, name: str) -> list[dict[str, Any]]:
    page = service.repository.list_timeline(session_id)
    return [item for item in page["events"] if item.get("event") == name]


def test_page_actions_land_in_the_timeline_in_order_with_their_fields(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path)
    try:
        assert service.web_navigate(session_id, "https://example.com/next").ok
        assert service.web_click(session_id, "#login").ok
        assert service.web_type(session_id, "#password", "hunter2-secret").ok
        assert service.web_wait(session_id, "#dashboard", state="visible").ok

        page = service.repository.list_timeline(session_id)
        driven = [
            item for item in page["events"]
            if item.get("event") in {"web.navigate", "web.click", "web.type", "web.wait"}
        ]
        assert [item["event"] for item in driven] == [
            "web.navigate",
            "web.click",
            "web.type",
            "web.wait",
        ]
        by_event = {item["event"]: item.get("details", {}) for item in driven}
        assert by_event["web.navigate"]["url"] == "https://example.com/next"
        assert by_event["web.click"]["selector"] == "#login"
        assert by_event["web.click"]["url"] == "https://app/next"
        assert by_event["web.wait"] == {"selector": "#dashboard", "state": "visible"}
    finally:
        service.close_all()


def test_type_records_selector_and_length_but_never_the_typed_text(tmp_path: Path) -> None:
    """A filled password/token must not leak into the durable audit log."""
    service, session_id = _service(tmp_path)
    try:
        secret = "hunter2-do-not-log"
        assert service.web_type(session_id, "#password", secret).ok

        entry = _events(service, session_id, "web.type")[0]
        assert entry["details"] == {"selector": "#password", "length": len(secret)}
        # The secret is nowhere in the serialized entry -- not in details, not
        # in the message, not smuggled into any other field.
        assert secret not in json.dumps(entry)
    finally:
        service.close_all()


def test_a_failed_action_records_no_timeline_entry(tmp_path: Path) -> None:
    """The trail is of what happened; a refused click did not happen."""
    service, session_id = _service(tmp_path, click_fails=True)
    try:
        result = service.web_click(session_id, "#login")
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
        assert _events(service, session_id, "web.click") == []
    finally:
        service.close_all()


def test_a_timeline_write_failure_does_not_fail_the_action(tmp_path: Path) -> None:
    """The click already happened in the browser; losing its log entry is the
    lesser harm, so a timeline write that raises must not flip the tool result
    to an error.
    """
    service, session_id = _service(tmp_path)
    try:
        def explode(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("timeline volume went away")

        service.repository.append_timeline = explode  # type: ignore[method-assign]
        result = service.web_click(session_id, "#login")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["clicked"] is True
    finally:
        service.close_all()
