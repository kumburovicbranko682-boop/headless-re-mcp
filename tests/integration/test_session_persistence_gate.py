"""Session persistence Gate: a session and its trail survive a service restart.

The console promises that an analysis session comes back by the *same id* after a
restart -- the mechanism is ``hydrate_persisted_sessions``, which re-adopts unclean
``sessions.db`` rows into a fresh registry as dormant ``created`` sessions carrying
``metadata.restored``. Keeping the id stable is what keeps a session's knowledge,
timeline, and audit trail attached across the restart.

That guarantee has no Linux coverage. ``test_m12_persist_gate.py`` exercises the
store, but it is pinned to a Windows-only ``headless_fixture.exe`` and force-skipped
off Windows, and even there it only checks that ``sessions.unclean`` *lists* a dirty
id -- it never proves the session is actually re-adopted so that ``session.get`` works
again, nor that the recorded knowledge/timeline reattach by id. This gate drives a real
two-instance restart on Linux against a committed PE fixture, backend-free, and proves:

  * an *open* (uncleanly abandoned) session is restored into a fresh service --
    ``session.get`` succeeds, ``metadata.restored`` is set, and binary / SHA-256 /
    architecture survive -- and its knowledge, timeline, and audit trail reattach by
    id, with the session offered as leftover work by ``sessions.unclean``;
  * a *cleanly closed* session is not restored (``session.get`` -> ``session_not_found``
    and it is absent from ``sessions.unclean``), yet its audit + timeline trail remains
    durably queryable by id.

No external tool is involved, so nothing should skip on any platform; a missing fixture
skips loudly (skip != pass).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService, JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
_FIXTURE_X86 = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x86.pre-upx.exe"


def _fixture(path: Path) -> Path:
    if not path.is_file():
        pytest.skip(f"missing committed PE fixture: {path} (skip != pass)")
    return path


def _service(artifact_root: Path) -> AnalysisService:
    """A fresh service on a given artifact root -- a new one models a restart."""
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=artifact_root,
        upx=None,
        diec=None,
    )
    return AnalysisService(settings)


def _data(result: object) -> JsonObject:
    assert getattr(result, "ok", False), getattr(result, "error", None)
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


def _ids(payload: JsonObject, key: str = "sessions") -> set[str]:
    return {str(item["id"]) for item in payload.get(key, [])}


@pytest.mark.integration
def test_an_open_session_and_its_trail_survive_a_service_restart(tmp_path: Path) -> None:
    binary = _fixture(_FIXTURE)
    root = tmp_path / "artifacts"

    # --- first run: open a session, record a fact, then vanish without closing ---
    first = _service(root)
    created = _data(first.create_session(str(binary)))["session"]
    session_id = str(created["id"])
    sha256 = str(created["sha256"])
    architecture = str(created["architecture"])
    _data(first.knowledge_record(session_id, "function", "entry", {"rva": 0x1000, "note": "OEP"}))

    # The create is trailed as it happens (the audit/timeline surface, on Linux).
    audit = _data(first.audit_list(session_id))
    assert "session.create" in {e["action"] for e in audit["entries"]}, audit
    timeline = _data(first.timeline_list(session_id))
    assert "session.created" in {e["event"] for e in timeline["events"]}, timeline

    # Simulate a crash/restart: drop the service without a clean close so the row
    # stays unclean, then bring a brand-new service up on the same artifact root.
    del first

    # --- second run: the session must come back by the same id ---
    second = _service(root)
    restored = _data(second.get_session(session_id))["session"]
    assert restored["metadata"].get("restored") is True, restored
    assert restored["state"] == "created", restored
    assert restored["sha256"] == sha256, restored
    assert restored["architecture"] == architecture, restored
    assert Path(str(restored.get("binary") or restored.get("locator"))).name == binary.name

    assert session_id in _ids(_data(second.list_sessions())), "restored session not listed"
    # Offered as leftover work: an abandoned session is unfinished, not forgotten.
    assert session_id in _ids(_data(second.sessions_unclean())), "not offered as unclean"

    # The fact recorded before the restart reattaches by id -- the whole point of
    # keeping the id stable across the restart.
    knowledge = _data(second.knowledge_query(session_id))
    assert knowledge["total"] == 1, knowledge
    assert knowledge["entries"][0]["value"] == {"rva": 0x1000, "note": "OEP"}, knowledge

    # And so do the timeline / audit trails.
    assert "session.created" in {
        e["event"] for e in _data(second.timeline_list(session_id))["events"]
    }
    assert "session.create" in {
        e["action"] for e in _data(second.audit_list(session_id))["entries"]
    }


@pytest.mark.integration
def test_a_cleanly_closed_session_is_not_restored_but_its_trail_persists(tmp_path: Path) -> None:
    binary = _fixture(_FIXTURE_X86)
    root = tmp_path / "artifacts"

    first = _service(root)
    session_id = str(_data(first.create_session(str(binary)))["session"]["id"])
    _data(first.close_session(session_id))
    del first

    second = _service(root)
    # A clean close is a finished session: it must not be resurrected into the
    # live registry, and it is not leftover work.
    gone = second.get_session(session_id)
    assert gone.ok is False
    assert gone.error is not None
    assert gone.error.code == "session_not_found", gone.error
    assert session_id not in _ids(_data(second.sessions_unclean())), "closed session offered again"

    # The record of what happened outlives the live session: both the create and the
    # close remain queryable by id.
    audit_actions = {e["action"] for e in _data(second.audit_list(session_id))["entries"]}
    assert {"session.create", "session.close"} <= audit_actions, audit_actions
    timeline_events = {e["event"] for e in _data(second.timeline_list(session_id))["events"]}
    assert {"session.created", "session.closed"} <= timeline_events, timeline_events
