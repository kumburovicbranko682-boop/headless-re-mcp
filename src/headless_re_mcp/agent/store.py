"""Independent transactional SQLite repository for Agent state."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any

from headless_re_mcp.agent.models import (
    RUN_TRANSITIONS,
    TERMINAL_RUN_STATUSES,
    AgentMessage,
    AgentRun,
    AgentThread,
    RunEvent,
    RunStatus,
)
from headless_re_mcp.agent.redaction import redact

JsonObject = dict[str, Any]


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def canonical_args_sha256(arguments: JsonObject) -> str:
    encoded = json.dumps(arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AgentStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._init_schema()
        self.interrupt_incomplete_runs()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
                yield con
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
            finally:
                con.close()

    def _init_schema(self) -> None:
        script = """
        CREATE TABLE IF NOT EXISTS threads(
          id TEXT PRIMARY KEY, title TEXT NOT NULL, session_id TEXT,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages(
          id TEXT PRIMARY KEY, thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
          role TEXT NOT NULL, content TEXT NOT NULL, run_id TEXT, tool_call_id TEXT,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS messages_thread_idx ON messages(thread_id, created_at, id);
        CREATE TABLE IF NOT EXISTS runs(
          id TEXT PRIMARY KEY, thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
          status TEXT NOT NULL, provider_profile TEXT NOT NULL, model TEXT,
          cancel_requested INTEGER NOT NULL DEFAULT 0, error TEXT,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deadline_at TEXT
        );
        CREATE INDEX IF NOT EXISTS runs_thread_idx ON runs(thread_id, created_at, id);
        CREATE TABLE IF NOT EXISTS tool_calls(
          id TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          name TEXT NOT NULL, arguments_json TEXT NOT NULL, args_sha256 TEXT NOT NULL,
          effects_json TEXT NOT NULL, status TEXT NOT NULL, approved INTEGER,
          consumed_at TEXT, result_json TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          PRIMARY KEY(run_id, id)
        );
        CREATE TABLE IF NOT EXISTS run_events(
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          seq INTEGER NOT NULL, type TEXT NOT NULL, data_json TEXT NOT NULL,
          created_at TEXT NOT NULL, PRIMARY KEY(run_id, seq)
        );
        """
        with self._lock:
            con = self._connect()
            try:
                con.executescript(script)
            finally:
                con.close()

    def create_thread(self, *, title: str = "New analysis", session_id: str | None = None) -> AgentThread:
        thread_id = uuid.uuid4().hex
        now = utc_now()
        with self.transaction() as con:
            con.execute("INSERT INTO threads VALUES(?,?,?,?,?)", (thread_id, title[:200], session_id, now, now))
        return AgentThread(thread_id, title[:200], session_id, now, now)

    def list_threads(self, *, limit: int = 100) -> list[AgentThread]:
        with self._connect() as con:
            rows = con.execute("SELECT * FROM threads ORDER BY updated_at DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall()
        return [AgentThread(**dict(row)) for row in rows]

    def get_thread(self, thread_id: str) -> AgentThread | None:
        with self._connect() as con:
            row = con.execute("SELECT * FROM threads WHERE id=?", (thread_id,)).fetchone()
        return AgentThread(**dict(row)) if row else None

    def add_message(self, thread_id: str, role: str, content: str, *, run_id: str | None = None, tool_call_id: str | None = None) -> AgentMessage:
        if len(content.encode("utf-8")) > 1_048_576:
            raise ValueError("message exceeds 1 MiB")
        message_id = uuid.uuid4().hex
        now = utc_now()
        with self.transaction() as con:
            if con.execute("SELECT 1 FROM threads WHERE id=?", (thread_id,)).fetchone() is None:
                raise KeyError(thread_id)
            con.execute("INSERT INTO messages VALUES(?,?,?,?,?,?,?)", (message_id, thread_id, role, content, run_id, tool_call_id, now))
            con.execute("UPDATE threads SET updated_at=? WHERE id=?", (now, thread_id))
        return AgentMessage(message_id, thread_id, role, content, run_id, tool_call_id, now)

    def list_messages(self, thread_id: str, *, limit: int = 500) -> list[AgentMessage]:
        with self._connect() as con:
            rows = con.execute("SELECT * FROM messages WHERE thread_id=? ORDER BY created_at,id LIMIT ?", (thread_id, max(1, min(limit, 2000)))).fetchall()
        return [AgentMessage(**dict(row)) for row in rows]

    def create_run(self, thread_id: str, *, provider_profile: str, model: str | None, deadline_seconds: float) -> AgentRun:
        if self.get_thread(thread_id) is None:
            raise KeyError(thread_id)
        run_id = uuid.uuid4().hex
        now_dt = datetime.now(UTC)
        now = now_dt.isoformat()
        deadline = (now_dt + timedelta(seconds=max(1.0, min(deadline_seconds, 3600.0)))).isoformat()
        with self.transaction() as con:
            con.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,?)", (run_id, thread_id, RunStatus.QUEUED.value, provider_profile, model, 0, None, now, now, deadline))
            self._append_event_tx(con, run_id, "run.started", {"status": RunStatus.QUEUED.value})
        run = self.get_run(run_id)
        assert run is not None
        return run

    @staticmethod
    def _run_from_row(row: sqlite3.Row) -> AgentRun:
        data = dict(row)
        data["status"] = RunStatus(data["status"])
        data["cancel_requested"] = bool(data["cancel_requested"])
        return AgentRun(**data)

    def get_run(self, run_id: str) -> AgentRun | None:
        with self._connect() as con:
            row = con.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._run_from_row(row) if row else None

    def transition(self, run_id: str, target: RunStatus, *, error: str | None = None) -> AgentRun:
        with self.transaction() as con:
            row = con.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                raise KeyError(run_id)
            current = RunStatus(row["status"])
            if target != current and target not in RUN_TRANSITIONS[current]:
                raise ValueError(f"illegal run transition: {current.value}->{target.value}")
            now = utc_now()
            con.execute("UPDATE runs SET status=?,error=?,updated_at=? WHERE id=?", (target.value, error, now, run_id))
        run = self.get_run(run_id)
        assert run is not None
        return run

    def append_event(self, run_id: str, event_type: str, data: JsonObject) -> RunEvent:
        with self.transaction() as con:
            return self._append_event_tx(con, run_id, event_type, data)

    def _append_event_tx(self, con: sqlite3.Connection, run_id: str, event_type: str, data: JsonObject) -> RunEvent:
        row = con.execute("SELECT COALESCE(MAX(seq),0)+1 AS seq FROM run_events WHERE run_id=?", (run_id,)).fetchone()
        seq = int(row["seq"])
        created = utc_now()
        safe = redact(data)
        con.execute("INSERT INTO run_events VALUES(?,?,?,?,?)", (run_id, seq, event_type, json.dumps(safe, ensure_ascii=False, default=str), created))
        return RunEvent(run_id, seq, event_type, safe, created)

    def list_events(self, run_id: str, *, after: int = 0, limit: int = 1000) -> list[RunEvent]:
        with self._connect() as con:
            rows = con.execute("SELECT * FROM run_events WHERE run_id=? AND seq>? ORDER BY seq LIMIT ?", (run_id, max(0, after), max(1, min(limit, 5000)))).fetchall()
        return [RunEvent(str(row["run_id"]), int(row["seq"]), str(row["type"]), json.loads(row["data_json"]), str(row["created_at"])) for row in rows]

    def propose_tool_call(self, run_id: str, tool_call_id: str, name: str, arguments: JsonObject, effects: list[str]) -> JsonObject:
        args_hash = canonical_args_sha256(arguments)
        now = utc_now()
        with self.transaction() as con:
            safe_arguments = redact(arguments)
            con.execute("INSERT INTO tool_calls(id,run_id,name,arguments_json,args_sha256,effects_json,status,approved,consumed_at,result_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,NULL,NULL,NULL,?,?)", (tool_call_id, run_id, name, json.dumps(safe_arguments, ensure_ascii=False, sort_keys=True), args_hash, json.dumps(effects), "proposed", now, now))
        return {"id": tool_call_id, "run_id": run_id, "name": name, "arguments": arguments, "args_sha256": args_hash, "effects": effects, "status": "proposed"}

    def decide_tool_call(self, run_id: str, tool_call_id: str, args_sha256: str, *, approved: bool) -> JsonObject:
        with self.transaction() as con:
            row = con.execute("SELECT * FROM tool_calls WHERE id=? AND run_id=?", (tool_call_id, run_id)).fetchone()
            if row is None:
                raise KeyError(tool_call_id)
            if str(row["args_sha256"]) != args_sha256:
                raise ValueError("approval arguments hash mismatch")
            if row["approved"] is not None or row["consumed_at"] is not None:
                raise ValueError("approval already decided or consumed")
            status = "approved" if approved else "rejected"
            con.execute(
                "UPDATE tool_calls SET approved=?,status=?,updated_at=? "
                "WHERE id=? AND run_id=?",
                (1 if approved else 0, status, utc_now(), tool_call_id, run_id),
            )
        return self.get_tool_call(run_id, tool_call_id)

    def consume_approval(self, run_id: str, tool_call_id: str, args_sha256: str) -> bool:
        with self.transaction() as con:
            run = con.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()
            if run is None or RunStatus(run["status"]) in TERMINAL_RUN_STATUSES:
                return False
            row = con.execute("SELECT * FROM tool_calls WHERE id=? AND run_id=?", (tool_call_id, run_id)).fetchone()
            if row is None or str(row["args_sha256"]) != args_sha256 or row["consumed_at"] is not None:
                return False
            if row["approved"] != 1:
                return False
            con.execute(
                "UPDATE tool_calls SET consumed_at=?,status='executing',updated_at=? "
                "WHERE id=? AND run_id=?",
                (utc_now(), utc_now(), tool_call_id, run_id),
            )
            return True

    def get_tool_call(self, run_id: str, tool_call_id: str) -> JsonObject:
        with self._connect() as con:
            row = con.execute("SELECT * FROM tool_calls WHERE id=? AND run_id=?", (tool_call_id, run_id)).fetchone()
        if row is None:
            raise KeyError(tool_call_id)
        data = dict(row)
        data["arguments"] = json.loads(data.pop("arguments_json"))
        data["effects"] = json.loads(data.pop("effects_json"))
        data["result"] = json.loads(data.pop("result_json")) if data.get("result_json") else None
        data.pop("result_json", None)
        data["approved"] = None if data["approved"] is None else bool(data["approved"])
        return data

    def complete_tool_call(self, run_id: str, tool_call_id: str, result: JsonObject, *, ok: bool) -> None:
        safe = redact(result)
        encoded = json.dumps(safe, ensure_ascii=False, default=str)
        if len(encoded.encode("utf-8")) > 262_144:
            safe = {"truncated": True, "summary": encoded[:16_384], "original_bytes": len(encoded.encode("utf-8"))}
            encoded = json.dumps(safe, ensure_ascii=False)
        with self.transaction() as con:
            con.execute("UPDATE tool_calls SET status=?,result_json=?,updated_at=? WHERE id=? AND run_id=?", ("completed" if ok else "failed", encoded, utc_now(), tool_call_id, run_id))

    def request_cancel(self, run_id: str) -> AgentRun:
        with self.transaction() as con:
            row = con.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                raise KeyError(run_id)
            if RunStatus(row["status"]) not in TERMINAL_RUN_STATUSES:
                con.execute("UPDATE runs SET cancel_requested=1,updated_at=? WHERE id=?", (utc_now(), run_id))
        run = self.get_run(run_id)
        assert run is not None
        return run

    def interrupt_incomplete_runs(self) -> int:
        active = tuple(status.value for status in RunStatus if status not in TERMINAL_RUN_STATUSES)
        placeholders = ",".join("?" for _ in active)
        with self.transaction() as con:
            rows = con.execute(f"SELECT id FROM runs WHERE status IN ({placeholders})", active).fetchall()
            now = utc_now()
            for row in rows:
                run_id = str(row["id"])
                con.execute("UPDATE runs SET status=?,error=?,updated_at=? WHERE id=?", (RunStatus.INTERRUPTED.value, "service_restarted", now, run_id))
                self._append_event_tx(con, run_id, "run.failed", {"status": RunStatus.INTERRUPTED.value, "error": "service_restarted"})
        return len(rows)
