from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

JsonObject = dict[str, Any]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  binary TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  architecture TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_cleanly INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS backends (
  session_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  worker_id TEXT,
  pid INTEGER,
  endpoint TEXT,
  PRIMARY KEY (session_id, kind)
);
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id TEXT PRIMARY KEY,
  session_id TEXT,
  at TEXT NOT NULL,
  action TEXT NOT NULL,
  params_summary TEXT NOT NULL,
  ok INTEGER NOT NULL,
  result_summary TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS knowledge (
  session_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (session_id, kind, key)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at);
CREATE INDEX IF NOT EXISTS idx_knowledge_session ON knowledge(session_id, kind);
"""

# The audit log is the only table with no natural end: sessions and artifacts are
# bounded by what the operator opens and by artifacts.gc, but a long-lived server
# appends here forever. Trimming is amortised over a batch of writes rather than
# run per insert, so the bound is approximate by design.
AUDIT_RETAINED_ROWS = 50_000
AUDIT_TRIM_INTERVAL = 256


class SessionStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self.audit_retained_rows = AUDIT_RETAINED_ROWS
        self.audit_trim_interval = AUDIT_TRIM_INTERVAL
        self._audit_writes = 0
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a connection for one operation and close it again.

        ``with sqlite3.connect(...)`` is a transaction scope, not a connection
        scope, so the previous form left every handle to be reclaimed whenever
        the interpreter got around to it. That is a file handle per call on a
        database a long-lived server writes to constantly.
        """
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def upsert_session(
        self,
        *,
        session_id: str,
        binary: str,
        sha256: str,
        architecture: str,
        state: str,
        closed_cleanly: bool | None = None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT id FROM sessions WHERE id=?", (session_id,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO sessions(id,binary,sha256,architecture,state,created_at,updated_at,closed_cleanly)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    (
                        session_id,
                        binary,
                        sha256,
                        architecture,
                        state,
                        now,
                        now,
                        1 if closed_cleanly else 0,
                    ),
                )
            else:
                if closed_cleanly is None:
                    conn.execute(
                        "UPDATE sessions SET binary=?, sha256=?, architecture=?, state=?, updated_at=? WHERE id=?",
                        (binary, sha256, architecture, state, now, session_id),
                    )
                else:
                    conn.execute(
                        "UPDATE sessions SET binary=?, sha256=?, architecture=?, state=?, updated_at=?, closed_cleanly=? WHERE id=?",
                        (
                            binary,
                            sha256,
                            architecture,
                            state,
                            now,
                            1 if closed_cleanly else 0,
                            session_id,
                        ),
                    )
            conn.commit()

    def mark_unclean_open_sessions(self) -> int:
        """On startup, ensure previously open sessions stay marked unclean."""
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE sessions SET closed_cleanly=0, updated_at=? "
                "WHERE closed_cleanly!=1 OR state NOT IN ('closed','failed')",
                (datetime.now(UTC).isoformat(),),
            )
            conn.commit()
            return int(cur.rowcount or 0)

    def list_unclean_sessions(self) -> list[JsonObject]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE closed_cleanly=0 ORDER BY updated_at DESC"
            ).fetchall()
            return [dict(row) for row in rows]

    def upsert_backend(
        self,
        *,
        session_id: str,
        kind: str,
        worker_id: str | None = None,
        pid: int | None = None,
        endpoint: str | None = None,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO backends(session_id,kind,worker_id,pid,endpoint) VALUES(?,?,?,?,?) "
                "ON CONFLICT(session_id, kind) DO UPDATE SET "
                "worker_id=excluded.worker_id, pid=excluded.pid, endpoint=excluded.endpoint",
                (session_id, kind, worker_id, pid, endpoint),
            )
            conn.commit()

    def list_backends(self, session_id: str | None = None) -> list[JsonObject]:
        with self._lock, self._connect() as conn:
            if session_id:
                rows = conn.execute(
                    "SELECT * FROM backends WHERE session_id=? ORDER BY kind",
                    (session_id,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM backends ORDER BY session_id, kind").fetchall()
            return [dict(row) for row in rows]

    def register_artifact(
        self,
        *,
        session_id: str,
        kind: str,
        path: str | Path,
        sha256: str,
        source: str,
        size: int | None = None,
    ) -> JsonObject:
        artifact_path = Path(path)
        resolved = str(artifact_path)
        file_size = size if size is not None else (
            artifact_path.stat().st_size if artifact_path.is_file() else 0
        )
        artifact_id = uuid4().hex
        created = datetime.now(UTC).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO artifacts(id,session_id,kind,path,size,sha256,source,created_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (artifact_id, session_id, kind, resolved, int(file_size), sha256, source, created),
            )
            conn.commit()
        return {
            "id": artifact_id,
            "session_id": session_id,
            "kind": kind,
            "path": resolved,
            "size": int(file_size),
            "sha256": sha256,
            "source": source,
            "created_at": created,
        }

    def list_artifacts(self, session_id: str | None = None, *, offset: int = 0, limit: int = 50) -> JsonObject:
        limit = max(1, min(int(limit), 256))
        offset = max(0, int(offset))
        with self._lock, self._connect() as conn:
            if session_id:
                total = conn.execute(
                    "SELECT COUNT(*) AS c FROM artifacts WHERE session_id=?", (session_id,)
                ).fetchone()["c"]
                rows = conn.execute(
                    "SELECT * FROM artifacts WHERE session_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (session_id, limit, offset),
                ).fetchall()
            else:
                total = conn.execute("SELECT COUNT(*) AS c FROM artifacts").fetchone()["c"]
                rows = conn.execute(
                    "SELECT * FROM artifacts ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        items = [dict(row) for row in rows]
        return {
            "artifacts": items,
            "count": len(items),
            "total": int(total),
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(items) < int(total),
        }

    def describe_artifact(self, artifact_id: str) -> JsonObject | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            return dict(row) if row else None

    def append_audit(
        self,
        *,
        session_id: str | None,
        action: str,
        params_summary: JsonObject,
        ok: bool,
        result_summary: JsonObject,
    ) -> None:
        # Never persist secrets
        redacted = {
            key: ("***" if "token" in key.casefold() or "password" in key.casefold() else value)
            for key, value in params_summary.items()
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO audit(id,session_id,at,action,params_summary,ok,result_summary)"
                " VALUES(?,?,?,?,?,?,?)",
                (
                    uuid4().hex,
                    session_id,
                    datetime.now(UTC).isoformat(),
                    action,
                    json.dumps(redacted, ensure_ascii=False)[:4000],
                    1 if ok else 0,
                    json.dumps(result_summary, ensure_ascii=False)[:4000],
                ),
            )
            self._audit_writes += 1
            if self._audit_writes >= self.audit_trim_interval:
                self._audit_writes = 0
                # Ordered the same way list_audit reads, so what survives is what
                # a caller would have been able to see.
                conn.execute(
                    "DELETE FROM audit WHERE id IN ("
                    " SELECT id FROM audit ORDER BY at DESC, id DESC LIMIT -1 OFFSET ?)",
                    (self.audit_retained_rows,),
                )
            conn.commit()

    def list_audit(
        self,
        session_id: str | None = None,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> JsonObject:
        limit = max(1, min(int(limit), 256))
        offset = max(0, int(offset))
        with self._lock, self._connect() as conn:
            if session_id:
                total = conn.execute(
                    "SELECT COUNT(*) AS c FROM audit WHERE session_id=?", (session_id,)
                ).fetchone()["c"]
                rows = conn.execute(
                    "SELECT * FROM audit WHERE session_id=? ORDER BY at DESC LIMIT ? OFFSET ?",
                    (session_id, limit, offset),
                ).fetchall()
            else:
                total = conn.execute("SELECT COUNT(*) AS c FROM audit").fetchone()["c"]
                rows = conn.execute(
                    "SELECT * FROM audit ORDER BY at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            for key in ("params_summary", "result_summary"):
                raw = item.get(key)
                if isinstance(raw, str):
                    with suppress(json.JSONDecodeError):
                        item[key] = json.loads(raw)
            items.append(item)
        return {
            "entries": items,
            "count": len(items),
            "total": int(total),
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(items) < int(total),
        }

    def record_knowledge(
        self,
        *,
        session_id: str,
        kind: str,
        key: str,
        value: JsonObject,
    ) -> JsonObject:
        """Insert or update one analysis fact, keeping the original created_at."""
        now = datetime.now(UTC).isoformat()
        payload = json.dumps(value, ensure_ascii=False)[:8000]
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT created_at FROM knowledge WHERE session_id=? AND kind=? AND key=?",
                (session_id, kind, key),
            ).fetchone()
            created_at = row["created_at"] if row is not None else now
            conn.execute(
                "INSERT INTO knowledge(session_id,kind,key,value,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?)"
                " ON CONFLICT(session_id,kind,key) DO UPDATE SET"
                " value=excluded.value, updated_at=excluded.updated_at",
                (session_id, kind, key, payload, created_at, now),
            )
            conn.commit()
        return {
            "session_id": session_id,
            "kind": kind,
            "key": key,
            "created_at": created_at,
            "updated_at": now,
            "replaced": row is not None,
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
        with self._lock, self._connect() as conn:
            if kind:
                total = conn.execute(
                    "SELECT COUNT(*) AS c FROM knowledge WHERE session_id=? AND kind=?",
                    (session_id, kind),
                ).fetchone()["c"]
                rows = conn.execute(
                    "SELECT * FROM knowledge WHERE session_id=? AND kind=?"
                    " ORDER BY kind ASC, key ASC LIMIT ? OFFSET ?",
                    (session_id, kind, limit, offset),
                ).fetchall()
            else:
                total = conn.execute(
                    "SELECT COUNT(*) AS c FROM knowledge WHERE session_id=?",
                    (session_id,),
                ).fetchone()["c"]
                rows = conn.execute(
                    "SELECT * FROM knowledge WHERE session_id=?"
                    " ORDER BY kind ASC, key ASC LIMIT ? OFFSET ?",
                    (session_id, limit, offset),
                ).fetchall()
        entries: list[JsonObject] = []
        kinds: dict[str, int] = {}
        for row in rows:
            item = dict(row)
            raw = item.get("value")
            if isinstance(raw, str):
                with suppress(json.JSONDecodeError):
                    item["value"] = json.loads(raw)
            name = str(item["kind"])
            kinds[name] = kinds.get(name, 0) + 1
            entries.append(item)
        return {
            "session_id": session_id,
            "entries": entries,
            "count": len(entries),
            "total": int(total),
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(entries) < int(total),
            "kinds": kinds,
        }

    def gc_artifacts(self, *, max_total_bytes: int) -> JsonObject:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT id, path, size FROM artifacts ORDER BY created_at ASC"
            ).fetchall()
            total = sum(int(row["size"]) for row in rows)
            removed: list[str] = []
            for row in rows:
                if total <= max_total_bytes:
                    break
                path = Path(row["path"])
                size = int(row["size"])
                if path.is_file():
                    path.unlink(missing_ok=True)
                conn.execute("DELETE FROM artifacts WHERE id=?", (row["id"],))
                removed.append(row["id"])
                total -= size
            conn.commit()
        return {"removed": removed, "count": len(removed), "bytes_remaining_estimate": max(0, total)}
