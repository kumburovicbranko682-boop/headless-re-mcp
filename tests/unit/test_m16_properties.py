from __future__ import annotations

import pytest
from pydantic import ValidationError

from headless_re_mcp.core.events import (
    DEBUG_EVENT_CAPACITY,
    DebugEventProtocolError,
    parse_debug_event_batch,
)
from headless_re_mcp.core.models import ModuleSelector
from headless_re_mcp.workflows.engine import WorkflowState, cancel_workflow_navigation


def _empty_batch(*, cursor: int = 0, latest: int = 0) -> dict[str, object]:
    oldest = 0 if latest == 0 else max(1, latest - DEBUG_EVENT_CAPACITY + 1)
    dropped_total = 0 if latest == 0 else max(0, latest - DEBUG_EVENT_CAPACITY)
    return {
        "cursor": cursor,
        "next_cursor": cursor,
        "oldest_sequence": oldest,
        "latest_sequence": latest,
        "dropped": 0,
        "dropped_total": dropped_total,
        "capacity": DEBUG_EVENT_CAPACITY,
        "has_more": False,
        "count": 0,
        "events": [],
    }


def test_event_batch_cursor_property() -> None:
    batch = parse_debug_event_batch(_empty_batch(), requested_cursor=0, requested_limit=8)
    assert batch.cursor == 0
    with pytest.raises(DebugEventProtocolError):
        parse_debug_event_batch(_empty_batch(cursor=1), requested_cursor=0, requested_limit=8)


def test_module_selector_path_normalization() -> None:
    sel = ModuleSelector(path=r"C:\Windows\System32\ntdll.dll")
    assert sel.path is not None
    assert sel.path.strip() == sel.path
    with pytest.raises(ValidationError):
        ModuleSelector(path="   ")


def test_workflow_cancel_without_navigation() -> None:
    state = WorkflowState()
    transition = cancel_workflow_navigation(state)
    assert isinstance(transition.state, WorkflowState)
    assert transition.state.navigation is None
