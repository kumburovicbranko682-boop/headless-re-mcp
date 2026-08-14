"""Independent transactional SQLite repository for Agent state."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any

from headless_re_mcp.agent.models import (
    RUN_TRANSITIONS,
    TERMINAL_MISSION_STATUSES,
    TERMINAL_RUN_STATUSES,
    AgentMessage,
    AgentMission,
    AgentRun,
    AgentThread,
    MissionStatus,
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


# Finished work has no natural end: every completed mission leaves a thread,
# its runs, events and messages behind. Measured at 250 tiny missions: 459 KB
# and still climbing, about 1.8 KB each with almost no tool output. A real
# analysis is larger, and nothing deleted a thread once its mission ended.
_RETAINED_FINISHED_THREADS = 2_000
_FINISHED_TRIM_INTERVAL = 32

# A live thread is not collected by the finished-thread trim. list_messages
# already only reads the newest 2000, but add_message kept writing past that:
# 1500 messages of 200 bytes each were 831 KB and still climbing, and each
# message may be up to 1 MiB. The orchestrator never sees the dropped prefix,
# so keeping it only grows the file.
_RETAINED_MESSAGES_PER_THREAD = 2_000

# Each streamed token is a run_events row. 2000 deltas of 20 bytes were 414 KB
# and still climbing. A live mission keeps every run until it finishes, and
# list_events already only pages 5000 at a time, so the prefix nobody can
# page in one reply is only growing the file.
_RETAINED_EVENTS_PER_RUN = 5_000

# A single event had no size cap. One 2 MiB delta made the database 2.16 MB;
# the same payload in a message is refused at 1 MiB and a tool result is cut
# at 256 KiB. SSE then tries to send the whole thing in one frame.
_EVENT_DATA_MAX_BYTES = 65_536


class AgentStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self.journal_mode = "unknown"
        self._enable_wal()
        self._init_schema()
        self.retained_finished_threads = _RETAINED_FINISHED_THREADS
        self.finished_trim_interval = _FINISHED_TRIM_INTERVAL
        self.retained_messages_per_thread = _RETAINED_MESSAGES_PER_THREAD
        self.retained_events_per_run = _RETAINED_EVENTS_PER_RUN
        self.event_data_max_bytes = _EVENT_DATA_MAX_BYTES
        self._finished_writes = 0
        # Deliberately not recovering here. Opening a database is what a
        # diagnostic script, a second tool or a test does, and recovery rewrites
        # every non-terminal run and requeues every RUNNING mission -- so merely
        # looking at the state of a live service destroyed the work it was doing.
        # The process taking ownership calls recover_after_restart() itself.

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        # foreign_keys and busy_timeout are per-connection, so they belong here.
        # journal_mode does not: it is a property of the database file, applied
        # once by _enable_wal. Re-asserting it per connection was not measurably
        # slower, but it did mean nothing ever checked whether WAL was actually
        # in force -- see _enable_wal for why that matters.
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _enable_wal(self) -> None:
        """Put the database file in WAL mode, once, and check that it took.

        WAL is what lets readers run while a write is in flight, and this store
        is read by SSE streams while the orchestrator writes to it. It is not
        available on every filesystem: on a network share the pragma is accepted
        and silently ignored, leaving the database in rollback-journal mode
        where every read blocks every write. Setting it on each connection hid
        that -- the failure looked identical to success. The mode is read back
        here so `journal_mode` reports what the database is actually doing.
        """
        connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
        finally:
            connection.close()
        self.journal_mode = mode.lower()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """One write transaction, and the real reason if it fails.

        The rollback used to run whatever went wrong. When the failure was
        BEGIN itself -- which is what a full disk looks like: "disk I/O error"
        -- there was no transaction to roll back, so ROLLBACK raised
        "cannot rollback - no transaction is active" and that replaced the
        original exception. The incident an operator reads then describes the
        cleanup rather than the disk, and points nowhere near the cause.
        """
        with self._lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
            except BaseException:
                con.close()
                raise
            try:
                yield con
                con.execute("COMMIT")
            except BaseException:
                # A rollback that cannot run must not become the error report.
                with suppress(sqlite3.Error):
                    con.execute("ROLLBACK")
                raise
            finally:
                con.close()

    @contextmanager
    def _reading(self) -> Iterator[sqlite3.Connection]:
        """Open a connection for one read and close it again.

        The connection is autocommit, so a read needs no transaction scope, but
        it does need closing: ``with sqlite3.connect(...)`` would leave the
        handle for the interpreter to reclaim whenever it noticed.
        """
        con = self._connect()
        try:
            yield con
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
        CREATE TABLE IF NOT EXISTS missions(
          id TEXT PRIMARY KEY, thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
          objective TEXT NOT NULL, status TEXT NOT NULL,
          provider_profile TEXT, model TEXT,
          max_runs INTEGER NOT NULL, runs_used INTEGER NOT NULL DEFAULT 0,
          last_run_id TEXT, error TEXT,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS missions_status_idx ON missions(status, created_at, id);
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
        with self._reading() as con:
            rows = con.execute("SELECT * FROM threads ORDER BY updated_at DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall()
        return [AgentThread(**dict(row)) for row in rows]

    def get_thread(self, thread_id: str) -> AgentThread | None:
        with self._reading() as con:
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
            keep = max(1, int(self.retained_messages_per_thread))
            con.execute(
                "DELETE FROM messages WHERE id IN ("
                "  SELECT id FROM messages WHERE thread_id=?"
                "  ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?"
                ")",
                (thread_id, keep),
            )
        return AgentMessage(message_id, thread_id, role, content, run_id, tool_call_id, now)

    def list_messages(self, thread_id: str, *, limit: int = 500) -> list[AgentMessage]:
        """The most recent `limit` messages, oldest first.

        The window has to be the recent end. Taking the oldest `limit` instead
        froze a long thread at its five-hundredth message: the orchestrator
        rebuilt the same ancient conversation for the provider on every run and
        never saw a later turn, and the scheduler could not find the completion
        marker its own run had just written, so it burned each mission's whole
        budget and reported an objective that had in fact been met as
        "not met within N runs". Both are silent on a thread that only grows.
        """
        capped = max(1, min(limit, 2000))
        with self._reading() as con:
            rows = con.execute(
                "SELECT * FROM ("
                "  SELECT * FROM messages WHERE thread_id=?"
                "  ORDER BY created_at DESC, id DESC LIMIT ?"
                ") ORDER BY created_at, id",
                (thread_id, capped),
            ).fetchall()
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
        with self._reading() as con:
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
        encoded = json.dumps(safe, ensure_ascii=False, default=str)
        limit = max(1024, int(self.event_data_max_bytes))
        if len(encoded.encode("utf-8")) > limit:
            original = len(encoded.encode("utf-8"))
            safe = {
                "truncated": True,
                "summary": encoded[:4096],
                "original_bytes": original,
            }
            encoded = json.dumps(safe, ensure_ascii=False)
        con.execute("INSERT INTO run_events VALUES(?,?,?,?,?)", (run_id, seq, event_type, encoded, created))
        keep = max(1, int(self.retained_events_per_run))
        con.execute(
            "DELETE FROM run_events WHERE run_id=? AND seq IN ("
            "  SELECT seq FROM run_events WHERE run_id=?"
            "  ORDER BY seq DESC LIMIT -1 OFFSET ?"
            ")",
            (run_id, run_id, keep),
        )
        return RunEvent(run_id, seq, event_type, safe, created)

    def list_events(self, run_id: str, *, after: int = 0, limit: int = 1000) -> list[RunEvent]:
        with self._reading() as con:
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
        with self._reading() as con:
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

    def recover_after_restart(self) -> int:
        """Adopt whatever the previous process left behind. Call once, on startup.

        Destructive by design: every non-terminal run is declared dead and every
        RUNNING mission goes back to the queue. That is right for a process
        taking over an abandoned database and wrong for anything else, so it is
        not part of opening one.
        """
        active = tuple(status.value for status in RunStatus if status not in TERMINAL_RUN_STATUSES)
        placeholders = ",".join("?" for _ in active)
        with self.transaction() as con:
            rows = con.execute(f"SELECT id FROM runs WHERE status IN ({placeholders})", active).fetchall()
            now = utc_now()
            for row in rows:
                run_id = str(row["id"])
                con.execute("UPDATE runs SET status=?,error=?,updated_at=? WHERE id=?", (RunStatus.INTERRUPTED.value, "service_restarted", now, run_id))
                self._append_event_tx(con, run_id, "run.failed", {"status": RunStatus.INTERRUPTED.value, "error": "service_restarted"})
            # A mission is durable across restarts by design: its run was killed,
            # not its objective. Returning it to PENDING is what lets the
            # scheduler pick the work back up instead of losing it, which is the
            # difference between surviving a restart and needing a human.
            con.execute(
                "UPDATE missions SET status=?,updated_at=? WHERE status=?",
                (MissionStatus.PENDING.value, now, MissionStatus.RUNNING.value),
            )
        return len(rows)

    # ---- missions -------------------------------------------------------

    @staticmethod
    def _mission_from_row(row: sqlite3.Row) -> AgentMission:
        data = dict(row)
        data["status"] = MissionStatus(data["status"])
        return AgentMission(**data)

    def create_mission(
        self,
        thread_id: str,
        objective: str,
        *,
        provider_profile: str | None = None,
        model: str | None = None,
        max_runs: int = 8,
    ) -> AgentMission:
        if self.get_thread(thread_id) is None:
            raise KeyError(thread_id)
        text = objective.strip()
        if not text:
            raise ValueError("mission objective must not be empty")
        mission_id = uuid.uuid4().hex
        now = utc_now()
        bounded = max(1, min(int(max_runs), 128))
        with self.transaction() as con:
            con.execute(
                "INSERT INTO missions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    mission_id, thread_id, text[:8000], MissionStatus.PENDING.value,
                    provider_profile, model, bounded, 0, None, None, now, now,
                ),
            )
        mission = self.get_mission(mission_id)
        assert mission is not None
        return mission

    def get_mission(self, mission_id: str) -> AgentMission | None:
        with self._reading() as con:
            row = con.execute("SELECT * FROM missions WHERE id=?", (mission_id,)).fetchone()
        return None if row is None else self._mission_from_row(row)

    def list_missions(self, *, status: MissionStatus | None = None, limit: int = 100) -> list[AgentMission]:
        bounded = max(1, min(limit, 500))
        with self._reading() as con:
            if status is None:
                rows = con.execute("SELECT * FROM missions ORDER BY created_at DESC, id DESC LIMIT ?", (bounded,)).fetchall()
            else:
                rows = con.execute("SELECT * FROM missions WHERE status=? ORDER BY created_at DESC, id DESC LIMIT ?", (status.value, bounded)).fetchall()
        return [self._mission_from_row(row) for row in rows]

    def claim_next_mission(self) -> AgentMission | None:
        """Take the oldest pending mission, atomically.

        The claim is the UPDATE itself rather than a read followed by a write,
        so two schedulers -- or one that overlapped its own tick -- cannot both
        start runs for the same objective.
        """
        with self.transaction() as con:
            row = con.execute(
                "SELECT * FROM missions WHERE status=? ORDER BY created_at ASC, id ASC LIMIT 1",
                (MissionStatus.PENDING.value,),
            ).fetchone()
            if row is None:
                return None
            mission_id = str(row["id"])
            changed = con.execute(
                "UPDATE missions SET status=?,updated_at=? WHERE id=? AND status=?",
                (MissionStatus.RUNNING.value, utc_now(), mission_id, MissionStatus.PENDING.value),
            ).rowcount
            if not changed:
                return None
            row = con.execute("SELECT * FROM missions WHERE id=?", (mission_id,)).fetchone()
        return self._mission_from_row(row)

    def note_mission_run(self, mission_id: str, run_id: str) -> None:
        with self.transaction() as con:
            con.execute(
                "UPDATE missions SET runs_used=runs_used+1,last_run_id=?,updated_at=? WHERE id=?",
                (run_id, utc_now(), mission_id),
            )

    def set_mission_status(
        self,
        mission_id: str,
        status: MissionStatus,
        *,
        error: str | None = None,
    ) -> AgentMission:
        with self.transaction() as con:
            row = con.execute("SELECT status FROM missions WHERE id=?", (mission_id,)).fetchone()
            if row is None:
                raise KeyError(mission_id)
            current = MissionStatus(row["status"])
            if current in TERMINAL_MISSION_STATUSES and status != current:
                raise ValueError(f"mission is already {current.value}")
            con.execute(
                "UPDATE missions SET status=?,error=?,updated_at=? WHERE id=?",
                (status.value, error[:1000] if error else None, utc_now(), mission_id),
            )
            if status in TERMINAL_MISSION_STATUSES:
                self._maybe_trim_finished_threads(con)
        mission = self.get_mission(mission_id)
        assert mission is not None
        return mission

    def _maybe_trim_finished_threads(self, con: sqlite3.Connection) -> None:
        self._finished_writes += 1
        if self._finished_writes < self.finished_trim_interval:
            return
        self._finished_writes = 0
        self._trim_finished_threads(con)

    def _trim_finished_threads(self, con: sqlite3.Connection) -> None:
        """Drop the oldest finished threads; live work is not eligible.

        A thread is finished when it has at least one mission, every mission
        has ended, and no run is still in flight. Idle threads with no mission
        yet are left alone -- those are an inbox, not history. Ordered by the
        newest mission clock so a just-finished thread is kept even if it was
        created early.
        """
        keep = max(0, int(self.retained_finished_threads))
        mission_done = tuple(status.value for status in TERMINAL_MISSION_STATUSES)
        run_done = tuple(status.value for status in TERMINAL_RUN_STATUSES)
        placeholders_m = ",".join("?" * len(mission_done))
        placeholders_r = ",".join("?" * len(run_done))
        con.execute(
            "DELETE FROM threads WHERE id IN ("
            " SELECT id FROM ("
            "  SELECT t.id FROM threads t"
            "  WHERE EXISTS (SELECT 1 FROM missions m WHERE m.thread_id=t.id)"
            f"   AND NOT EXISTS (SELECT 1 FROM missions m WHERE m.thread_id=t.id AND m.status NOT IN ({placeholders_m}))"
            f"   AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.thread_id=t.id AND r.status NOT IN ({placeholders_r}))"
            "  ORDER BY (SELECT MAX(m.updated_at) FROM missions m WHERE m.thread_id=t.id) DESC, t.id DESC"
            "  LIMIT -1 OFFSET ?"
            " )"
            ")",
            (*mission_done, *run_done, keep),
        )

    def cancel_mission(self, mission_id: str) -> AgentMission:
        mission = self.get_mission(mission_id)
        if mission is None:
            raise KeyError(mission_id)
        if mission.status in TERMINAL_MISSION_STATUSES:
            return mission
        return self.set_mission_status(mission_id, MissionStatus.CANCELLED, error="cancelled")
