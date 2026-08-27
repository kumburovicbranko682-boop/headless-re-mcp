from __future__ import annotations

import json
import shutil
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from headless_re_mcp.core.store.timeline import session_timeline_path
from headless_re_mcp.redaction import redact

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

# Knowledge is upserted per (kind, key), so a session that records every
# function as a new key never stops. 800 small facts were 201 KB and still
# climbing; each value may be 8000 characters. Query is already paged; the
# table itself was not.
KNOWLEDGE_RETAINED_PER_SESSION = 10_000

# The in-memory registry keeps 64 closed sessions. The sqlite row was never
# collected, so every session ever opened stayed in the database after the
# registry had forgotten it. Measured at 800 closed rows: 225 KB and still
# climbing, plus every knowledge fact those sessions recorded.
CLOSED_SESSION_RETAINED = 64

# The in-memory repository keeps each session's timeline as a Python list and,
# unlike its audit log and knowledge table, never trimmed it: every lifecycle
# event and tool note appended for the life of the process. The file-backed
# timeline caps itself at 10,000 lines; the in-memory port bounds the same way
# so a long-lived composition using it does not grow one list per session
# without end.
TIMELINE_RETAINED_PER_SESSION = 10_000

# A knowledge value is stored as JSON text. The bound used to be applied by
# slicing the serialised form, which stops it being JSON: the write answered
# successfully and the next read returned a string fragment. Refuse instead.
KNOWLEDGE_VALUE_MAX_CHARS = 8000
AUDIT_TRIM_INTERVAL = 256
AUDIT_JSON_MAX_CHARS = 4000


def encode_audit_json(value: JsonObject, *, limit: int = AUDIT_JSON_MAX_CHARS) -> str:
    """Keep audit cells valid JSON even when the row is size-capped."""
    encoded = json.dumps(value, ensure_ascii=False)
    cap = max(1, int(limit))
    if len(encoded) <= cap:
        return encoded
    wrapper = {"truncated": True, "chars": len(encoded), "preview": ""}
    smallest = json.dumps(wrapper, ensure_ascii=False)
    if len(smallest) > cap:
        # Even the metadata envelope cannot fit. Preserve valid JSON rather
        # than slicing through a quoted string or escape sequence.
        return "{}" if cap >= 2 else "0"

    low = 0
    high = len(encoded)
    best = smallest
    while low <= high:
        midpoint = (low + high) // 2
        wrapper["preview"] = encoded[:midpoint]
        candidate = json.dumps(wrapper, ensure_ascii=False)
        if len(candidate) <= cap:
            best = candidate
            low = midpoint + 1
        else:
            high = midpoint - 1
    return best


def encode_knowledge_value(value: JsonObject) -> str:
    """Serialize a finding, or refuse rather than cut it into non-JSON."""
    payload = json.dumps(value, ensure_ascii=False)
    if len(payload) > KNOWLEDGE_VALUE_MAX_CHARS:
        raise ValueError(
            f"value serialises to {len(payload)} chars, over the "
            f"{KNOWLEDGE_VALUE_MAX_CHARS} a finding may hold; record the bulk as an "
            "artifact and keep the reference here"
        )
    return payload


def redact_audit_payload(value: JsonObject) -> JsonObject:
    """Return an audit-safe copy while preserving the historical mask."""
    redacted = redact(value, mask="***")
    return redacted if isinstance(redacted, dict) else {}


class SessionStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self.audit_retained_rows = AUDIT_RETAINED_ROWS
        self.audit_trim_interval = AUDIT_TRIM_INTERVAL
        self.retained_knowledge_per_session = KNOWLEDGE_RETAINED_PER_SESSION
        self.retained_closed_sessions = CLOSED_SESSION_RETAINED
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
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
        except sqlite3.OperationalError:
            # The artifact root went away under a running service: a disk
            # cleanup, a scanner quarantine, a volume that came back unmounted.
            # Without this every later call fails for the life of the process,
            # because nothing recreates the directory the database lives in.
            # Rebuilt rather than checked up front, so the ordinary call pays
            # nothing for a case that should never happen twice.
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.executescript(_SCHEMA)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _prune_emptied_parent(self, path: Path) -> None:
        """Remove the per-session directory a collected artifact leaves behind.

        Measured over 150 sessions with one capture each: collection reclaimed
        the files and left 142 empty directories, one per session, which every
        disk-usage walk then has to visit for the life of the artifact root.
        ``rmdir`` refuses a directory that still holds anything, which is
        exactly the guard this needs, and every writer here creates its
        directory before use, so a pruned one comes back on demand.
        """
        parent = path.parent
        # Never the database's own directory, and never the artifact root.
        if parent in {self.db_path.parent, self.db_path.parent.parent}:
            return
        with suppress(OSError):
            parent.rmdir()

    def _collectable_artifact_path(self, path: Path) -> bool:
        """Only artifact payloads may be unlinked; metadata is never collectible."""
        root = self.db_path.parent.parent.resolve()
        try:
            relative = path.expanduser().resolve().relative_to(root)
        except (OSError, ValueError):
            return False
        return bool(relative.parts) and relative.parts[0] != "meta"

    def check_writable(self) -> None:
        """Raise unless the database would accept a write right now.

        It has to dirty a page to find out. Measured against a read-only file:
        ``BEGIN IMMEDIATE`` succeeds, with or without a rollback, because SQLite
        defers the refusal until something actually writes -- so the obvious
        probe reports a database that accepts nothing as healthy. Creating a
        table inside a transaction that is then rolled back does raise, and
        leaves the schema exactly as it found it.
        """
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("CREATE TABLE _writable_probe(x)")
            finally:
                conn.execute("ROLLBACK")

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
            if closed_cleanly:
                self._trim_closed_sessions(conn)
            conn.commit()

    def _trim_closed_sessions(self, conn: sqlite3.Connection) -> None:
        """Drop the oldest cleanly-closed sessions, and the facts they stored.

        Unclean rows stay: sessions.unclean is how an operator finds work that
        was open when the process died. Artifacts stay too -- artifacts.gc
        owns the files, and deleting the row without the file would leak both.
        """
        keep = max(0, int(self.retained_closed_sessions))
        rows = conn.execute(
            "SELECT id FROM sessions WHERE closed_cleanly=1"
            " ORDER BY updated_at DESC, id DESC LIMIT -1 OFFSET ?",
            (keep,),
        ).fetchall()
        ids = [str(row["id"]) for row in rows]
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        conn.execute(f"DELETE FROM knowledge WHERE session_id IN ({placeholders})", ids)
        conn.execute(f"DELETE FROM backends WHERE session_id IN ({placeholders})", ids)
        conn.execute(f"DELETE FROM sessions WHERE id IN ({placeholders})", ids)
        for session_id in ids:
            self._forget_closed_session_files(session_id)

    def _forget_closed_session_files(self, session_id: str) -> None:
        """Remove the timeline a closed session leaves under the artifact root.

        Measured at 250 closed sessions: 250 directories and 60 KB of
        timeline.jsonl still on disk after the sqlite rows were gone. The file
        is rewritten in place for the life of the session, then nobody reads it.
        """
        if self.db_path.parent.name != "meta":
            return
        # A stored id is always a uuid, but cleanup must never be the thing
        # that follows a traversing id out of the root, and the inline check
        # this replaces (``Path(id).name != id``) was not that guard: ".."
        # passes it, and <root>/debug-events/.. below is the artifact root
        # itself, so the rmtree would have taken every artifact and this
        # database with it. session_timeline_path already refuses everything
        # that is not one ordinary path component (and a symlinked session
        # dir); skip what it refuses rather than raise, because this runs
        # inside the trim on session close and one poisoned row must not fail
        # every later clean close.
        try:
            path = session_timeline_path(self.db_path.parent.parent, session_id)
        except ValueError:
            return
        with suppress(OSError):
            if path.is_file():
                path.unlink()
        self._prune_emptied_parent(path)
        events = self.db_path.parent.parent / "debug-events" / session_id
        with suppress(OSError):
            if events.is_dir():
                shutil.rmtree(events)

    def get_session(self, session_id: str) -> JsonObject | None:
        """The stored row, or None if this id was never created."""
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            return dict(row) if row is not None else None

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

    def list_unclean_sessions(
        self, *, offset: int = 0, limit: int = 100
    ) -> tuple[list[JsonObject], int]:
        """A page of sessions that were never closed, newest first, plus the total.

        Paged like every other listing here. Nothing clears these rows, and a
        service that is hard-killed with sessions open adds one per session, so
        the answer grows for as long as the deployment runs: measured at 3000
        of them, an unpaged reply was 993 KiB -- returned by the very tool a
        caller reaches for right after a crash.
        """
        # id breaks ties on updated_at. mark_unclean_open_sessions stamps every
        # session it flips with one timestamp, so a crash leaves a whole batch
        # tied -- exactly the rows this lists -- and paging them by updated_at
        # alone skipped and repeated sessions across the windows.
        window = max(1, min(int(limit), 1000))
        start = max(0, int(offset))
        with self._lock, self._connect() as conn:
            total = int(
                conn.execute("SELECT COUNT(*) FROM sessions WHERE closed_cleanly=0").fetchone()[0]
            )
            rows = conn.execute(
                "SELECT * FROM sessions WHERE closed_cleanly=0"
                " ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?",
                (window, start),
            ).fetchall()
            return [dict(row) for row in rows], total

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
        if artifact_path.is_file():
            file_size = artifact_path.stat().st_size
        else:
            file_size = int(size) if size is not None else 0
        if file_size < 0:
            raise ValueError("artifact size cannot be negative")
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
        # id breaks ties on created_at. Without it the order among artifacts
        # registered in the same instant is undefined across the LIMIT/OFFSET
        # windows this pages in, so a tie straddling a page boundary dropped a
        # row from one page and repeated another on the next -- and a coarse
        # clock or a burst of captures makes those ties ordinary.
        limit = max(1, min(int(limit), 256))
        offset = max(0, int(offset))
        with self._lock, self._connect() as conn:
            if session_id:
                total = conn.execute(
                    "SELECT COUNT(*) AS c FROM artifacts WHERE session_id=?", (session_id,)
                ).fetchone()["c"]
                rows = conn.execute(
                    "SELECT * FROM artifacts WHERE session_id=? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                    (session_id, limit, offset),
                ).fetchall()
            else:
                total = conn.execute("SELECT COUNT(*) AS c FROM artifacts").fetchone()["c"]
                rows = conn.execute(
                    "SELECT * FROM artifacts ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
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
        # Never persist secrets, including nested provider payloads and results.
        redacted_params = redact_audit_payload(params_summary)
        redacted_result = redact_audit_payload(result_summary)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO audit(id,session_id,at,action,params_summary,ok,result_summary)"
                " VALUES(?,?,?,?,?,?,?)",
                (
                    uuid4().hex,
                    session_id,
                    datetime.now(UTC).isoformat(),
                    action,
                    encode_audit_json(redacted_params),
                    1 if ok else 0,
                    encode_audit_json(redacted_result),
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
        # id breaks ties on `at`, so the page window is stable and -- the point
        # the trim above already assumes -- reads in the same order the trim
        # deletes by (`at DESC, id DESC`). Without it the reader and the trim
        # disagreed on which rows sit at the retention boundary, so a paged
        # audit could skip or repeat an entry the moment two shared a timestamp.
        limit = max(1, min(int(limit), 256))
        offset = max(0, int(offset))
        with self._lock, self._connect() as conn:
            if session_id:
                total = conn.execute(
                    "SELECT COUNT(*) AS c FROM audit WHERE session_id=?", (session_id,)
                ).fetchone()["c"]
                rows = conn.execute(
                    "SELECT * FROM audit WHERE session_id=? ORDER BY at DESC, id DESC LIMIT ? OFFSET ?",
                    (session_id, limit, offset),
                ).fetchall()
            else:
                total = conn.execute("SELECT COUNT(*) AS c FROM audit").fetchone()["c"]
                rows = conn.execute(
                    "SELECT * FROM audit ORDER BY at DESC, id DESC LIMIT ? OFFSET ?",
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
        payload = encode_knowledge_value(value)
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
            keep = max(1, int(self.retained_knowledge_per_session))
            conn.execute(
                "DELETE FROM knowledge WHERE rowid IN ("
                "  SELECT rowid FROM knowledge WHERE session_id=?"
                "  ORDER BY updated_at DESC, kind DESC, key DESC LIMIT -1 OFFSET ?"
                ")",
                (session_id, keep),
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
        """Collect oldest-first until the budget is met, skipping what is in use.

        A file another handle still holds -- a trace the debugger is writing, a
        dump being copied -- cannot be unlinked on Windows. Letting that error
        out of the loop was doubly wrong: collection always starts at the oldest
        artifact, so one stuck file stopped every later one from ever being
        collected and the budget quietly went unenforced (``maybe_collect``
        swallows the failure, so nothing said so); and any file already deleted
        in that pass had its row rolled back with the transaction, leaving rows
        that point at nothing and keep counting against the budget forever.

        Skipping keeps the row, so the artifact stays readable if the handle was
        the only problem and is collected on a later pass.
        """
        if type(max_total_bytes) is not int or max_total_bytes < 1:
            raise ValueError("max_total_bytes must be a positive integer")
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT id, path, size FROM artifacts ORDER BY created_at ASC"
            ).fetchall()
            total = sum(int(row["size"]) for row in rows)
            removed: list[str] = []
            skipped: list[JsonObject] = []
            invalid_paths: list[str] = []
            # The newest artifact is never collected. Collection now also runs
            # right after registration, and a single dump larger than the whole
            # budget would otherwise delete the file its caller is about to
            # return the path of.
            for row in rows[:-1]:
                if total <= max_total_bytes:
                    break
                path = Path(row["path"])
                size = int(row["size"])
                if not self._collectable_artifact_path(path):
                    # A corrupted or manually edited row must never turn GC
                    # into an arbitrary-file unlink primitive. Drop only the
                    # untrusted metadata and leave the referenced path alone.
                    conn.execute("DELETE FROM artifacts WHERE id=?", (row["id"],))
                    invalid_paths.append(row["id"])
                    total -= size
                    continue
                if path.is_file():
                    try:
                        path.unlink()
                    except OSError as exc:
                        skipped.append({"id": row["id"], "reason": f"{type(exc).__name__}: {exc}"})
                        continue
                    self._prune_emptied_parent(path)
                conn.execute("DELETE FROM artifacts WHERE id=?", (row["id"],))
                removed.append(row["id"])
                total -= size
            conn.commit()
        return {
            "removed": removed,
            "count": len(removed),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "invalid_paths": invalid_paths,
            "invalid_path_count": len(invalid_paths),
            "bytes_remaining_estimate": max(0, total),
        }
