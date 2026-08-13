"""Aggregate live workflow monitor snapshots for the local web console."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


def _safe_data(result: Any) -> JsonObject | None:
    if result is None or not getattr(result, "ok", False):
        return None
    data = getattr(result, "data", None)
    return data if isinstance(data, dict) else None


def _safe_error(result: Any) -> JsonObject | None:
    err = getattr(result, "error", None)
    if err is None:
        return None
    return {
        "code": getattr(err, "code", None),
        "message": getattr(err, "message", str(err)),
    }


def _timeline_tail(service: AnalysisService, session_id: str, limit: int) -> Any:
    """The newest `limit` timeline entries.

    timeline.list pages from the oldest entry, which is right for a caller
    walking the history and wrong for a monitor: asking for offset 0 every frame
    showed the first 48 things the session ever did and never moved, so a live
    view stopped being live as soon as a session got busy.

    Two reads rather than one, and only once a session is past the window: the
    total comes back with the first page, and a short session needs no second.
    """
    head = service.timeline_list(session_id, offset=0, limit=limit)
    data = _safe_data(head)
    if not isinstance(data, dict):
        return head
    total = data.get("total")
    if not isinstance(total, int) or total <= limit:
        return head
    return service.timeline_list(session_id, offset=total - limit, limit=limit)


def build_monitor_snapshot(
    service: AnalysisService,
    session_id: str,
    *,
    timeline_limit: int = 48,
    events_limit: int = 24,
) -> JsonObject:
    """Build a single monitor frame from AnalysisService (best-effort sections)."""
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    session_result = service.get_session(session_id)
    session_data = _safe_data(session_result)
    if session_data is None:
        return {
            "ok": False,
            "generated_at": now,
            "session_id": session_id,
            "error": _safe_error(session_result)
            or {"code": "session_unavailable", "message": "session not found"},
        }

    dynamic = service.dynamic_state(session_id)
    workflow = service.workflow_status(session_id)
    unpack = service.unpack_status(session_id)
    timeline = _timeline_tail(service, session_id, timeline_limit)
    artifacts = service.artifacts_list(session_id=session_id, offset=0, limit=12)

    events_payload: JsonObject | None = None
    events_error: JsonObject | None = None
    try:
        events = service.dynamic_events(session_id, limit=events_limit, timeout=0.05)
        events_payload = _safe_data(events)
        if events_payload is None:
            events_error = _safe_error(events)
    except BaseException as exc:  # pragma: no cover - defensive
        events_error = {"code": "events_unavailable", "message": str(exc)}

    dynamic_data = _safe_data(dynamic) or {}
    workflow_data = _safe_data(workflow)
    unpack_data = _safe_data(unpack)
    timeline_data = _safe_data(timeline) or {}
    artifacts_data = _safe_data(artifacts) or {}

    session_obj = session_data.get("session") if isinstance(session_data.get("session"), dict) else session_data
    workflow_obj = None
    if isinstance(workflow_data, dict):
        workflow_obj = workflow_data.get("workflow") or workflow_data
    unpack_obj = None
    if isinstance(unpack_data, dict):
        unpack_obj = unpack_data.get("unpack") or unpack_data

    stage = None
    if isinstance(unpack_obj, dict):
        stage = unpack_obj.get("stage") or unpack_obj.get("status") or unpack_obj.get("state")
    recoverability = None
    if isinstance(unpack_obj, dict):
        recoverability = unpack_obj.get("recoverability") or unpack_obj.get(
            "recoverability_hint"
        )

    return {
        "ok": True,
        "generated_at": now,
        "session_id": session_id,
        "session": session_obj,
        "dynamic": {
            "state": dynamic_data.get("state"),
            "debugging": dynamic_data.get("debugging"),
            "running": dynamic_data.get("running"),
            "process_id": dynamic_data.get("process_id") or dynamic_data.get("debuggee_pid"),
            "debuggee_pid": dynamic_data.get("debuggee_pid"),
            "debugger_pid": dynamic_data.get("debugger_pid"),
            "thread_id": dynamic_data.get("thread_id"),
            "raw": dynamic_data,
            "error": None if dynamic_data else _safe_error(dynamic),
        },
        "workflow": {
            "present": workflow_obj is not None,
            "data": workflow_obj,
            "error": None if workflow_obj is not None else _safe_error(workflow),
        },
        "unpack": {
            "present": unpack_obj is not None,
            "stage": stage,
            "recoverability": recoverability,
            "data": unpack_obj,
            "error": None if unpack_obj is not None else _safe_error(unpack),
        },
        "timeline": {
            "items": timeline_data.get("items")
            or timeline_data.get("events")
            or timeline_data.get("entries")
            or [],
            "count": timeline_data.get("count"),
            "error": None
            if (timeline_data.get("items") is not None or timeline_data.get("events") is not None
                or timeline_data.get("entries") is not None
                or not _safe_error(timeline))
            else _safe_error(timeline),
        },
        "events": {
            "items": (events_payload or {}).get("events") or [],
            "next_cursor": (events_payload or {}).get("next_cursor"),
            "error": events_error,
        },
        "artifacts": {
            "items": artifacts_data.get("artifacts") or artifacts_data.get("items") or [],
            "count": artifacts_data.get("count"),
        },
        "claims_universal_unpack": False,
    }
