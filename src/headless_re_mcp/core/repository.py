"""Persistence port and SQLite-backed unit-of-work boundary."""

from __future__ import annotations

import shutil
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any, Protocol
from uuid import uuid4

from headless_re_mcp.core.models import Result, Session
from headless_re_mcp.core.store import SessionStore
from headless_re_mcp.core.store.sqlite_store import (
    AUDIT_RETAINED_ROWS,
    CLOSED_SESSION_RETAINED,
    KNOWLEDGE_RETAINED_PER_SESSION,
    encode_knowledge_value,
)
from headless_re_mcp.core.store.timeline import (
    append_session_timeline,
    list_session_timeline,
    session_timeline_path,
)

JsonObject = dict[str, Any]


class AnalysisRepository(Protocol):
    """Persistence operations used by application services."""

    @contextmanager
    def transaction(self) -> Iterator[AnalysisRepository]: ...

    def note_session_created(
        self,
        binary: str,
        result: Result[JsonObject],
    ) -> None: ...

    def note_session_closed(
        self,
        session_id: str,
        session: Session | None,
        result: Result[JsonObject],
    ) -> None: ...

    def record_backend(
        self,
        session_id: str,
        kind: str,
        **fields: object,
    ) -> None: ...

    def list_backends(self, session_id: str | None = None) -> list[JsonObject]: ...

    def append_timeline(
        self,
        session_id: str,
        event: str,
        message: str,
        **details: object,
    ) -> None: ...

    def register_artifact(self, **fields: Any) -> JsonObject: ...

    def list_artifacts(
        self,
        session_id: str | None = None,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> JsonObject: ...

    def describe_artifact(self, artifact_id: str) -> JsonObject | None: ...

    def gc_artifacts(self, *, max_total_bytes: int) -> JsonObject: ...

    def list_timeline(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject: ...

    def list_unclean_sessions(
        self, *, offset: int = 0, limit: int = 100
    ) -> tuple[list[JsonObject], int]: ...

    def peek_session(self, session_id: str) -> JsonObject | None: ...

    def append_audit(
        self,
        *,
        session_id: str | None,
        action: str,
        params_summary: JsonObject,
        ok: bool,
        result_summary: JsonObject,
    ) -> None: ...

    def list_audit(
        self,
        session_id: str | None = None,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> JsonObject: ...

    def record_knowledge(
        self,
        *,
        session_id: str,
        kind: str,
        key: str,
        value: JsonObject,
    ) -> JsonObject: ...

    def list_knowledge(
        self,
        session_id: str,
        *,
        kind: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject: ...

    def persist_unpack_state(
        self,
        session_id: str,
        *,
        write: Callable[[Path], object],
    ) -> None: ...


class SqliteAnalysisRepository:
    """Serialize related store and timeline effects behind one application boundary."""

    def __init__(self, artifact_root: Path, store: SessionStore | None = None) -> None:
        self.artifact_root = artifact_root.expanduser().resolve()
        self.store = store or SessionStore(self.artifact_root / "meta" / "sessions.db")
        self._lock = RLock()
        self.store.mark_unclean_open_sessions()

    @contextmanager
    def transaction(self) -> Iterator[AnalysisRepository]:
        with self._lock:
            yield self

    def note_session_created(self, binary: str, result: Result[JsonObject]) -> None:
        if not result.ok or result.data is None:
            return
        session = result.data.get("session")
        if not isinstance(session, dict):
            return
        session_id = str(session["id"])
        with self.transaction():
            self.store.upsert_session(
                session_id=session_id,
                binary=str(session.get("binary") or binary),
                sha256=str(session.get("sha256") or ""),
                architecture=str(session.get("architecture") or ""),
                state=str(session.get("state") or "created"),
                closed_cleanly=False,
            )
            self.append_timeline(session_id, "session.created", "session created")
            self.append_audit(
                session_id=session_id,
                action="session.create",
                params_summary={"binary": binary},
                ok=True,
                result_summary={"session_id": session_id},
            )

    def note_session_closed(
        self,
        session_id: str,
        session: Session | None,
        result: Result[JsonObject],
    ) -> None:
        if session is None:
            # Closing something the registry does not hold must not create it.
            # Measured: session.close on a never-seen id wrote sessions/<id>/
            # timeline.jsonl and a failed sqlite row, after which timeline.list
            # answered ok (one "close failed" event) and sessions.unclean
            # offered the ghost as leftover work. Closing an evicted real
            # session then blanked its binary and marked it unclean.
            existing = self.store.get_session(session_id)
            if existing is None or not result.ok:
                return
            with self.transaction():
                self.store.upsert_session(
                    session_id=session_id,
                    binary=str(existing.get("binary") or ""),
                    sha256=str(existing.get("sha256") or ""),
                    architecture=str(existing.get("architecture") or ""),
                    state="closed",
                    closed_cleanly=True,
                )
                self.append_timeline(session_id, "session.closed", "session closed", ok=True)
                self.append_audit(
                    session_id=session_id,
                    action="session.close",
                    params_summary={},
                    ok=True,
                    result_summary={"ok": True},
                )
            return
        with self.transaction():
            self.store.upsert_session(
                session_id=session_id,
                binary=str(session.locator or session.binary or ""),
                sha256=session.sha256 or "",
                architecture=session.architecture.value if session.architecture else "",
                state=session.state.value,
                closed_cleanly=bool(result.ok),
            )
            self.append_timeline(
                session_id,
                "session.closed",
                "session closed" if result.ok else "session close failed",
                ok=bool(result.ok),
            )
            self.append_audit(
                session_id=session_id,
                action="session.close",
                params_summary={},
                ok=bool(result.ok),
                result_summary={"ok": bool(result.ok)},
            )

    def record_backend(self, session_id: str, kind: str, **fields: object) -> None:
        pid = fields.get("pid")
        with self.transaction():
            self.store.upsert_backend(
                session_id=session_id,
                kind=kind,
                worker_id=str(fields.get("worker_id") or "") or None,
                pid=pid if isinstance(pid, int) else None,
                endpoint=str(fields.get("endpoint") or "") or None,
            )

    def list_backends(self, session_id: str | None = None) -> list[JsonObject]:
        return self.store.list_backends(session_id)

    def append_timeline(
        self,
        session_id: str,
        event: str,
        message: str,
        **details: object,
    ) -> None:
        with self.transaction():
            append_session_timeline(
                session_timeline_path(self.artifact_root, session_id),
                event=event,
                message=message,
                details=dict(details),
            )

    def register_artifact(self, **fields: Any) -> JsonObject:
        with self.transaction():
            return self.store.register_artifact(**fields)

    def list_artifacts(
        self,
        session_id: str | None = None,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> JsonObject:
        return self.store.list_artifacts(session_id, offset=offset, limit=limit)

    def describe_artifact(self, artifact_id: str) -> JsonObject | None:
        return self.store.describe_artifact(artifact_id)

    def gc_artifacts(self, *, max_total_bytes: int) -> JsonObject:
        with self.transaction():
            return self.store.gc_artifacts(max_total_bytes=max_total_bytes)

    def list_timeline(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        return list_session_timeline(
            session_timeline_path(self.artifact_root, session_id),
            offset=offset,
            limit=limit,
        )

    def list_unclean_sessions(
        self, *, offset: int = 0, limit: int = 100
    ) -> tuple[list[JsonObject], int]:
        return self.store.list_unclean_sessions(offset=offset, limit=limit)

    def peek_session(self, session_id: str) -> JsonObject | None:
        """Stored session row, even when this process no longer has it live."""
        return self.store.get_session(session_id)

    def check_writable(self) -> None:
        """Raise unless the store would accept a write; used by the readiness probe."""
        self.store.check_writable()

    def persist_unpack_state(
        self,
        session_id: str,
        *,
        write: Callable[[Path], object],
    ) -> None:
        directory = self.artifact_root / "unpack" / session_id / "session"
        with self.transaction():
            write(directory)

    def append_audit(
        self,
        *,
        session_id: str | None,
        action: str,
        params_summary: JsonObject,
        ok: bool,
        result_summary: JsonObject,
    ) -> None:
        with self.transaction():
            self.store.append_audit(
                session_id=session_id,
                action=action,
                params_summary=params_summary,
                ok=ok,
                result_summary=result_summary,
            )

    def list_audit(
        self,
        session_id: str | None = None,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> JsonObject:
        return self.store.list_audit(session_id, offset=offset, limit=limit)

    def record_knowledge(
        self,
        *,
        session_id: str,
        kind: str,
        key: str,
        value: JsonObject,
    ) -> JsonObject:
        with self.transaction():
            return self.store.record_knowledge(
                session_id=session_id,
                kind=kind,
                key=key,
                value=value,
            )

    def list_knowledge(
        self,
        session_id: str,
        *,
        kind: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        return self.store.list_knowledge(
            session_id,
            kind=kind,
            offset=offset,
            limit=limit,
        )


class InMemoryAnalysisRepository:
    """Deterministic repository fake with the same observable contract as SQLite.

    It is intentionally a production module rather than a test-only mock so custom
    application compositions can exercise the repository port without inheriting a
    ``SessionStore`` compatibility dependency.
    """

    def __init__(self, artifact_root: Path) -> None:
        self.artifact_root = artifact_root.expanduser().resolve()
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self.retained_knowledge_per_session = KNOWLEDGE_RETAINED_PER_SESSION
        self.retained_closed_sessions = CLOSED_SESSION_RETAINED
        self._sessions: dict[str, JsonObject] = {}
        self._backends: dict[tuple[str, str], JsonObject] = {}
        self._artifacts: dict[str, JsonObject] = {}
        self._timeline: dict[str, list[JsonObject]] = {}
        self._audit: list[JsonObject] = []
        self._knowledge: dict[tuple[str, str, str], JsonObject] = {}

    @contextmanager
    def transaction(self) -> Iterator[AnalysisRepository]:
        with self._lock:
            yield self

    def note_session_created(self, binary: str, result: Result[JsonObject]) -> None:
        if not result.ok or result.data is None:
            return
        session = result.data.get("session")
        if not isinstance(session, dict):
            return
        now = datetime.now(UTC).isoformat()
        session_id = str(session["id"])
        with self.transaction():
            self._sessions[session_id] = {
                "id": session_id,
                "binary": str(session.get("binary") or binary),
                "sha256": str(session.get("sha256") or ""),
                "architecture": str(session.get("architecture") or ""),
                "state": str(session.get("state") or "created"),
                "created_at": now,
                "updated_at": now,
                "closed_cleanly": 0,
            }
            self.append_timeline(session_id, "session.created", "session created")
            self.append_audit(
                session_id=session_id,
                action="session.create",
                params_summary={"binary": binary},
                ok=True,
                result_summary={"session_id": session_id},
            )

    def note_session_closed(
        self,
        session_id: str,
        session: Session | None,
        result: Result[JsonObject],
    ) -> None:
        now = datetime.now(UTC).isoformat()
        if session is None:
            existing = self._sessions.get(session_id)
            if existing is None or not result.ok:
                return
            with self.transaction():
                self._sessions[session_id] = {
                    **existing,
                    "state": "closed",
                    "updated_at": now,
                    "closed_cleanly": 1,
                }
                self.append_timeline(session_id, "session.closed", "session closed", ok=True)
                self.append_audit(
                    session_id=session_id,
                    action="session.close",
                    params_summary={},
                    ok=True,
                    result_summary={"ok": True},
                )
                self._trim_closed_sessions()
            return
        with self.transaction():
            existing = self._sessions.get(session_id, {})
            self._sessions[session_id] = {
                "id": session_id,
                "binary": str(session.locator or session.binary or ""),
                "sha256": session.sha256 or "",
                "architecture": session.architecture.value if session.architecture else "",
                "state": session.state.value,
                "created_at": str(existing.get("created_at") or now),
                "updated_at": now,
                "closed_cleanly": 1 if result.ok else 0,
            }
            self.append_timeline(
                session_id,
                "session.closed",
                "session closed" if result.ok else "session close failed",
                ok=bool(result.ok),
            )
            self.append_audit(
                session_id=session_id,
                action="session.close",
                params_summary={},
                ok=bool(result.ok),
                result_summary={"ok": bool(result.ok)},
            )
            if result.ok:
                self._trim_closed_sessions()

    def _trim_closed_sessions(self) -> None:
        keep = max(0, int(self.retained_closed_sessions))
        closed = [
            sid
            for sid, row in self._sessions.items()
            if int(row.get("closed_cleanly") or 0) == 1
        ]
        closed.sort(
            key=lambda sid: (str(self._sessions[sid].get("updated_at") or ""), sid),
            reverse=True,
        )
        for sid in closed[keep:]:
            self._sessions.pop(sid, None)
            self._timeline.pop(sid, None)
            for knowledge_key in [
                key for key in self._knowledge if key[0] == sid
            ]:
                self._knowledge.pop(knowledge_key, None)
            for backend_key in [item for item in self._backends if item[0] == sid]:
                self._backends.pop(backend_key, None)
            path = session_timeline_path(self.artifact_root, sid)
            with suppress(OSError):
                if path.is_file():
                    path.unlink()
            parent = path.parent
            if parent != self.artifact_root:
                with suppress(OSError):
                    parent.rmdir()
            events = self.artifact_root / "debug-events" / sid
            if Path(sid).name == sid and events.is_dir():
                with suppress(OSError):
                    shutil.rmtree(events)

    def record_backend(self, session_id: str, kind: str, **fields: object) -> None:
        with self.transaction():
            self._backends[(session_id, kind)] = {
                "session_id": session_id,
                "kind": kind,
                "worker_id": str(fields.get("worker_id") or "") or None,
                "pid": fields.get("pid") if isinstance(fields.get("pid"), int) else None,
                "endpoint": str(fields.get("endpoint") or "") or None,
            }

    def list_backends(self, session_id: str | None = None) -> list[JsonObject]:
        with self._lock:
            values = [dict(item) for item in self._backends.values()]
        if session_id is not None:
            values = [item for item in values if item["session_id"] == session_id]
        return sorted(values, key=lambda item: (str(item["session_id"]), str(item["kind"])))

    def append_timeline(
        self,
        session_id: str,
        event: str,
        message: str,
        **details: object,
    ) -> None:
        with self.transaction():
            self._timeline.setdefault(session_id, []).append(
                {
                    "at": datetime.now(UTC).isoformat(),
                    "event": event,
                    "message": message,
                    "details": dict(details),
                }
            )

    def register_artifact(self, **fields: Any) -> JsonObject:
        path = Path(fields["path"])
        item: JsonObject = {
            "id": uuid4().hex,
            "session_id": str(fields["session_id"]),
            "kind": str(fields["kind"]),
            "path": str(path),
            "size": int(fields.get("size", path.stat().st_size if path.is_file() else 0)),
            "sha256": str(fields["sha256"]),
            "source": str(fields["source"]),
            "created_at": datetime.now(UTC).isoformat(),
        }
        with self.transaction():
            self._artifacts[str(item["id"])] = item
        return dict(item)

    def list_artifacts(
        self,
        session_id: str | None = None,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> JsonObject:
        limit = max(1, min(int(limit), 256))
        offset = max(0, int(offset))
        with self._lock:
            items = [dict(item) for item in self._artifacts.values()]
        if session_id is not None:
            items = [item for item in items if item["session_id"] == session_id]
        items.sort(key=lambda item: str(item["created_at"]), reverse=True)
        total = len(items)
        page = items[offset : offset + limit]
        return {
            "artifacts": page,
            "count": len(page),
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(page) < total,
        }

    def describe_artifact(self, artifact_id: str) -> JsonObject | None:
        with self._lock:
            item = self._artifacts.get(artifact_id)
            return None if item is None else dict(item)

    def gc_artifacts(self, *, max_total_bytes: int) -> JsonObject:
        with self.transaction():
            ordered = sorted(self._artifacts.values(), key=lambda item: str(item["created_at"]))
            total = sum(int(item["size"]) for item in ordered)
            removed: list[str] = []
            skipped: list[JsonObject] = []
            # Same newest-file skip as SessionStore: collection now also runs
            # right after registration, and a single dump larger than the
            # budget would otherwise delete the file its caller is about to
            # return the path of.
            for item in ordered[:-1]:
                if total <= max_total_bytes:
                    break
                path = Path(str(item["path"]))
                size = int(item["size"])
                if path.is_file():
                    try:
                        path.unlink()
                    except OSError as exc:
                        skipped.append(
                            {"id": str(item["id"]), "reason": f"{type(exc).__name__}: {exc}"}
                        )
                        continue
                artifact_id = str(item["id"])
                self._artifacts.pop(artifact_id, None)
                removed.append(artifact_id)
                total -= size
        return {
            "removed": removed,
            "count": len(removed),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "bytes_remaining_estimate": max(0, total),
        }

    def list_timeline(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        with self._lock:
            events = [dict(item) for item in self._timeline.get(session_id, [])]
        total = len(events)
        page = events[offset : offset + limit]
        return {
            "events": page,
            "count": len(page),
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(page) < total,
        }

    def list_unclean_sessions(
        self, *, offset: int = 0, limit: int = 100
    ) -> tuple[list[JsonObject], int]:
        with self._lock:
            items = [dict(item) for item in self._sessions.values() if not item["closed_cleanly"]]
        ordered = sorted(items, key=lambda item: str(item["updated_at"]), reverse=True)
        window = max(1, min(int(limit), 1000))
        start = max(0, int(offset))
        return ordered[start : start + window], len(ordered)

    def peek_session(self, session_id: str) -> JsonObject | None:
        with self._lock:
            row = self._sessions.get(session_id)
            return dict(row) if row is not None else None

    def append_audit(
        self,
        *,
        session_id: str | None,
        action: str,
        params_summary: JsonObject,
        ok: bool,
        result_summary: JsonObject,
    ) -> None:
        redacted = {
            key: ("***" if "token" in key.casefold() or "password" in key.casefold() else value)
            for key, value in params_summary.items()
        }
        with self.transaction():
            self._audit.append(
                {
                    "id": uuid4().hex,
                    "session_id": session_id,
                    "at": datetime.now(UTC).isoformat(),
                    "action": action,
                    "params_summary": redacted,
                    "ok": 1 if ok else 0,
                    "result_summary": dict(result_summary),
                }
            )
            keep = max(1, int(AUDIT_RETAINED_ROWS))
            if len(self._audit) > keep:
                self._audit = self._audit[-keep:]

    def list_audit(
        self,
        session_id: str | None = None,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> JsonObject:
        limit = max(1, min(int(limit), 256))
        offset = max(0, int(offset))
        with self._lock:
            entries = [dict(item) for item in self._audit]
        if session_id is not None:
            entries = [item for item in entries if item["session_id"] == session_id]
        entries.sort(key=lambda item: str(item["at"]), reverse=True)
        total = len(entries)
        page = entries[offset : offset + limit]
        return {
            "entries": page,
            "count": len(page),
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(page) < total,
        }

    def record_knowledge(
        self,
        *,
        session_id: str,
        kind: str,
        key: str,
        value: JsonObject,
    ) -> JsonObject:
        now = datetime.now(UTC).isoformat()
        encode_knowledge_value(value)
        with self._lock:
            existing = self._knowledge.get((session_id, kind, key))
            created_at = str(existing["created_at"]) if existing is not None else now
            self._knowledge[(session_id, kind, key)] = {
                "session_id": session_id,
                "kind": kind,
                "key": key,
                "value": value,
                "created_at": created_at,
                "updated_at": now,
            }
            keep = max(1, int(self.retained_knowledge_per_session))
            owned = [
                item
                for item in self._knowledge.values()
                if str(item["session_id"]) == session_id
            ]
            if len(owned) > keep:
                owned.sort(
                    key=lambda item: (
                        str(item["updated_at"]),
                        str(item["kind"]),
                        str(item["key"]),
                    ),
                    reverse=True,
                )
                for item in owned[keep:]:
                    self._knowledge.pop(
                        (str(item["session_id"]), str(item["kind"]), str(item["key"])),
                        None,
                    )
        return {
            "session_id": session_id,
            "kind": kind,
            "key": key,
            "created_at": created_at,
            "updated_at": now,
            "replaced": existing is not None,
        }

    def list_knowledge(
        self,
        session_id: str,
        *,
        kind: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        with self._lock:
            entries = [
                dict(item)
                for item in self._knowledge.values()
                if item["session_id"] == session_id
                and (kind is None or item["kind"] == kind)
            ]
        entries.sort(key=lambda item: (str(item["kind"]), str(item["key"])))
        total = len(entries)
        page = entries[offset : offset + limit]
        kinds: dict[str, int] = {}
        for item in page:
            name = str(item["kind"])
            kinds[name] = kinds.get(name, 0) + 1
        return {
            "session_id": session_id,
            "entries": page,
            "count": len(page),
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(page) < total,
            "kinds": kinds,
        }

    def persist_unpack_state(
        self,
        session_id: str,
        *,
        write: Callable[[Path], object],
    ) -> None:
        with self.transaction():
            write(self.artifact_root / "unpack" / session_id / "session")
