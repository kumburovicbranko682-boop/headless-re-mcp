"""Live Gate for the pure-Python findings store (``knowledge.record`` / ``query``).

The knowledge store is the durable memory the agent and ``report.generate``
both read back: every recorded fact is keyed by ``(kind, key)`` so revisiting a
function replaces the finding in place instead of piling up duplicates, values
are size-capped so a truncated JSON blob never reads back as a broken string,
and queries filter by kind and paginate. It is pure Python over the session
store -- no IDA, debugger, device, or CLI -- yet it had no dedicated end-to-end
gate; a regression in the replace-in-place semantics, the value cap, or the
pagination window would only surface through the agent.

This gate drives the real service against a committed PE fixture: a
record/query round trip, idempotent replacement of the same key, kind
filtering with a ``{kind: count}`` summary and offset/limit pagination, the
size/shape guards (all ``invalid_request``), and the read/write asymmetry on a
closed session (writes fail closed, reads still resolve). No toolchain, so it
never skips.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_REPO = Path(__file__).resolve().parents[2]
_PE = _REPO / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            diec=None,
        )
    )


def _require(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"fixture missing: {path}")


def _open(service: AnalysisService, path: Path) -> str:
    created = service.create_session(str(path))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


@pytest.mark.integration
def test_record_then_query_roundtrip(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)

    recorded = service.knowledge_record(session_id, "function", "main", {"addr": "0x401000"})
    assert recorded.ok and recorded.data is not None, recorded.error
    assert recorded.data["kind"] == "function"
    assert recorded.data["key"] == "main"
    assert recorded.data["replaced"] is False
    assert recorded.data["created_at"] == recorded.data["updated_at"]

    queried = service.knowledge_query(session_id)
    assert queried.ok and queried.data is not None, queried.error
    assert queried.data["total"] == 1
    entry = queried.data["entries"][0]
    assert entry["kind"] == "function"
    assert entry["key"] == "main"
    assert entry["value"] == {"addr": "0x401000"}


@pytest.mark.integration
def test_recording_same_key_replaces_in_place(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)

    first = service.knowledge_record(session_id, "function", "main", {"addr": "0x401000"})
    assert first.ok and first.data is not None, first.error
    second = service.knowledge_record(
        session_id, "function", "main", {"addr": "0x401500", "note": "renamed"}
    )
    assert second.ok and second.data is not None, second.error

    # Same (kind, key) updates the row rather than appending a duplicate.
    assert second.data["replaced"] is True
    assert second.data["created_at"] == first.data["created_at"]

    queried = service.knowledge_query(session_id, kind="function")
    assert queried.ok and queried.data is not None, queried.error
    assert queried.data["total"] == 1
    assert queried.data["entries"][0]["value"] == {"addr": "0x401500", "note": "renamed"}


@pytest.mark.integration
def test_query_filters_by_kind_and_paginates(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)

    assert service.knowledge_record(session_id, "function", "main", {"addr": "0x1"}).ok
    assert service.knowledge_record(session_id, "string", "banner", {"text": "H3adl3ss"}).ok
    assert service.knowledge_record(session_id, "string", "url", {"text": "http://x"}).ok

    everything = service.knowledge_query(session_id)
    assert everything.ok and everything.data is not None, everything.error
    assert everything.data["total"] == 3
    # The response summarises how many facts exist per kind.
    assert everything.data["kinds"] == {"function": 1, "string": 2}

    strings = service.knowledge_query(session_id, kind="string")
    assert strings.ok and strings.data is not None, strings.error
    assert strings.data["total"] == 2
    assert {entry["key"] for entry in strings.data["entries"]} == {"banner", "url"}

    # Two single-row windows cover the kind without overlap; has_more flags the
    # boundary honestly.
    page0 = service.knowledge_query(session_id, kind="string", offset=0, limit=1)
    page1 = service.knowledge_query(session_id, kind="string", offset=1, limit=1)
    assert page0.data["total"] == 2 and page1.data["total"] == 2
    assert page0.data["has_more"] is True
    assert page1.data["has_more"] is False
    keys0 = {entry["key"] for entry in page0.data["entries"]}
    keys1 = {entry["key"] for entry in page1.data["entries"]}
    assert len(keys0) == 1 and len(keys1) == 1
    assert keys0.isdisjoint(keys1)
    assert keys0 | keys1 == {"banner", "url"}


@pytest.mark.integration
def test_record_guards(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)

    oversize = service.knowledge_record(session_id, "note", "big", {"blob": "A" * 9000})
    assert oversize.ok is False and oversize.error is not None
    assert oversize.error.code == "invalid_request"
    assert "8000" in oversize.error.message

    for kind, key in (("", "k"), ("k" * 65, "k"), ("kind", ""), ("kind", "k" * 257)):
        guarded = service.knowledge_record(session_id, kind, key, {})
        assert guarded.ok is False and guarded.error is not None, (kind[:8], key[:8])
        assert guarded.error.code == "invalid_request"

    service.close_session(session_id)
    closed = service.knowledge_record(session_id, "kind", "key", {})
    assert closed.ok is False and closed.error is not None
    assert closed.error.code == "invalid_request"


@pytest.mark.integration
def test_query_survives_a_closed_session(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)
    assert service.knowledge_record(session_id, "string", "banner", {"text": "H3adl3ss"}).ok

    service.close_session(session_id)
    # Reads still resolve after close so a report or review can read the record;
    # only writes fail closed.
    queried = service.knowledge_query(session_id)
    assert queried.ok and queried.data is not None, queried.error
    assert queried.data["total"] == 1
    assert queried.data["entries"][0]["key"] == "banner"
