"""Aggregate live workflow monitor snapshots for the local web console."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from headless_re_mcp.core.models import BackendKind
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


def _event_tail(
    service: AnalysisService,
    session_id: str,
    limit: int,
) -> tuple[JsonObject | None, JsonObject | None]:
    """The newest events, read without consuming anybody's.

    dynamic_events reads through the session's one consumer cursor and advances
    it, so every frame drawn here took events the agent would then never be
    handed. No gap is reported either, because the cursor moved legitimately:
    the agent cannot tell it lost anything, and it only happens while somebody
    is watching.

    The durable log takes its cursor as an argument and keeps none of its own,
    so tailing it is a read and nothing else. Reaching for the runtime is the
    price of that -- the service surface only offers the consuming call.
    """
    runtime = service._runtime_owner.get(session_id, BackendKind.X64DBG)
    log = getattr(runtime, "event_log", None) if runtime is not None else None
    if log is None:
        return None, {
            "code": "events_unavailable",
            "message": "session has no durable debugger event log",
        }
    try:
        latest = int(log.latest_sequence)
        window_start = max(0, latest - limit)
        batch = log.read_after(window_start, limit=limit).batch
    except BaseException as exc:  # noqa: BLE001 - a frame has to render regardless
        return None, {"code": "events_unavailable", "message": str(exc)}
    return {
        "events": [event.to_dict() for event in batch.events],
        "next_cursor": batch.next_cursor,
        # latest_sequence is the stream's high-water mark: how many events this
        # session emitted, of which the frame shows only the newest window.
        # Surfacing just the events read as the whole stream on a busy session.
        "total": batch.latest_sequence,
        # window_start > 0 means the read began past sequence 1, so older events
        # exist before this frame.
        "truncated": window_start > 0,
        # Events overwritten in the native ring before drain could copy them are
        # gone, not merely off-window. A panel that hid this drew a clean stream
        # over a hole.
        "dropped_total": batch.dropped_total,
    }, None


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

    session_obj = session_data.get("session") if isinstance(session_data.get("session"), dict) else session_data
    target = session_obj.get("target") if isinstance(session_obj, dict) else None
    state = session_obj.get("state") if isinstance(session_obj, dict) else None
    closed = state in {"closed", "closing", "failed"}
    pe_live = target == "pe" and not closed

    dynamic = service.dynamic_state(session_id) if pe_live else None
    workflow = service.workflow_status(session_id) if pe_live else None
    unpack = service.unpack_status(session_id) if pe_live else None
    web = service.web_status(session_id) if target == "web" and not closed else None
    timeline = _timeline_tail(service, session_id, timeline_limit)
    artifacts = service.artifacts_list(session_id=session_id, offset=0, limit=12)

    if pe_live:
        events_payload, events_error = _event_tail(service, session_id, events_limit)
    else:
        events_payload, events_error = {"events": [], "next_cursor": 0}, None

    dynamic_data = _safe_data(dynamic) or {}
    workflow_data = _safe_data(workflow)
    unpack_data = _safe_data(unpack)
    web_data = _safe_data(web) or {}
    timeline_data = _safe_data(timeline) or {}
    artifacts_data = _safe_data(artifacts) or {}
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
            "state": dynamic_data.get("state") if pe_live else state,
            "debugging": dynamic_data.get("debugging"),
            "running": dynamic_data.get("running"),
            "process_id": dynamic_data.get("process_id") or dynamic_data.get("debuggee_pid"),
            "debuggee_pid": dynamic_data.get("debuggee_pid"),
            "debugger_pid": dynamic_data.get("debugger_pid"),
            "thread_id": dynamic_data.get("thread_id"),
            "raw": dynamic_data,
            "error": None if (pe_live is False or dynamic_data) else _safe_error(dynamic),
        },
        "web": {
            "open": bool(web_data.get("open")),
            "opening": bool(web_data.get("opening")),
            "url": web_data.get("url") or web_data.get("locator"),
            "title": web_data.get("title"),
            "locator": web_data.get("locator"),
            "error": None if web_data or web is None else _safe_error(web),
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
            "total": (events_payload or {}).get("total", 0),
            "truncated": bool((events_payload or {}).get("truncated", False)),
            "dropped_total": (events_payload or {}).get("dropped_total", 0),
            "error": events_error,
        },
        "artifacts": {
            "items": artifacts_data.get("artifacts") or artifacts_data.get("items") or [],
            "count": artifacts_data.get("count"),
        },
        "claims_universal_unpack": False,
    }
