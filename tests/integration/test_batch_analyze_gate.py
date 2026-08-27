"""batch.analyze Gate: parallel session creation with per-sample error isolation.

``batch.analyze`` fans a list of binaries out across a bounded thread pool, creating
one session each so an operator can triage many samples in a single call. Its contract
is that every entry succeeds or fails on its own -- a single bad sample must not abort
the batch -- and it validates its inputs before doing any work.

Its only end-to-end coverage is
``test_composite_tools_gate.py::test_batch_opens_parallel_ida_sessions_and_reports``,
which passes ``open_static=True`` against a real IDA backend and is marked Windows-only,
so on Linux the orchestration itself -- parallel session creation, per-entry error
isolation, and input validation -- is unproven. With ``open_static=False`` none of that
needs a backend. This gate drives it against the committed PE fixtures and proves:

  * a batch of valid binaries yields one real, distinct, resolvable session each;
  * a bad sample among good ones fails in place with a structured error while the good
    ones still succeed, input order is preserved, and the batch as a whole returns ok;
  * empty input, an out-of-range ``max_workers``, and an over-long list are refused.

No external tool is involved, so nothing should skip on any platform; a missing fixture
skips loudly (skip != pass).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService, JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _PROJECT_ROOT / "fixtures" / "upx"
_GOOD_X64 = _FIXTURES / "console_fixture-x64.pre-upx.exe"
_GOOD_X86 = _FIXTURES / "console_fixture-x86.pre-upx.exe"
_MISSING = _FIXTURES / "does-not-exist.exe"


def _fixtures() -> tuple[Path, Path]:
    for path in (_GOOD_X64, _GOOD_X86):
        if not path.is_file():
            pytest.skip(f"missing committed PE fixture: {path} (skip != pass)")
    return _GOOD_X64, _GOOD_X86


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=None,
        diec=None,
    )
    return AnalysisService(settings)


def _data(result: object) -> JsonObject:
    assert getattr(result, "ok", False), getattr(result, "error", None)
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


@pytest.mark.integration
def test_batch_analyze_creates_a_real_session_per_binary(tmp_path: Path) -> None:
    good_x64, good_x86 = _fixtures()
    service = _service(tmp_path)
    try:
        result = _data(
            service.batch_analyze([str(good_x64), str(good_x86)], max_workers=2, open_static=False)
        )
        assert result["count"] == 2, result
        assert result["succeeded"] == 2, result
        assert result["failed"] == 0, result
        assert result["max_workers"] == 2, result

        entries = result["entries"]
        assert all(entry["ok"] is True for entry in entries), entries
        assert all(entry.get("error") is None for entry in entries), entries

        session_ids = [str(entry["session_id"]) for entry in entries]
        assert len(set(session_ids)) == 2, session_ids
        # Each reported session is a real, resolvable session, not just an id.
        for session_id in session_ids:
            assert service.get_session(session_id).ok, session_id
        listed = {str(item["id"]) for item in _data(service.list_sessions())["sessions"]}
        assert set(session_ids) <= listed, (session_ids, listed)
    finally:
        service.close_all()


@pytest.mark.integration
def test_batch_analyze_isolates_a_bad_sample_and_preserves_order(tmp_path: Path) -> None:
    good_x64, good_x86 = _fixtures()
    service = _service(tmp_path)
    try:
        # A missing file sits between two good samples: the batch must ride over it.
        inputs = [str(good_x64), str(_MISSING), str(good_x86)]
        result = _data(service.batch_analyze(inputs, max_workers=3, open_static=False))
        assert result["count"] == 3, result
        assert result["succeeded"] == 2, result
        assert result["failed"] == 1, result

        entries = result["entries"]
        # Order is preserved, so each entry lines up with its input path.
        assert [entry["binary"] for entry in entries] == inputs, entries

        good_first, bad, good_last = entries
        assert good_first["ok"] is True and good_first["session_id"], good_first
        assert good_last["ok"] is True and good_last["session_id"], good_last

        # The bad sample failed in place with a structured error and no session.
        assert bad["ok"] is False, bad
        assert bad["session_id"] is None, bad
        assert bad["error"]["code"] == "file_not_found", bad

        # The good sessions are real despite the failure sandwiched between them.
        for entry in (good_first, good_last):
            assert service.get_session(str(entry["session_id"])).ok, entry
    finally:
        service.close_all()


@pytest.mark.integration
def test_batch_analyze_validates_its_inputs(tmp_path: Path) -> None:
    good_x64, _ = _fixtures()
    service = _service(tmp_path)
    try:
        empty = service.batch_analyze([], open_static=False)
        assert empty.ok is False
        assert empty.error is not None
        assert empty.error.code == "invalid_request", empty.error

        # max_workers is bounded (1..8) so a batch cannot spawn unbounded analysers.
        assert service.batch_analyze([str(good_x64)], max_workers=0, open_static=False).ok is False
        assert service.batch_analyze([str(good_x64)], max_workers=9, open_static=False).ok is False

        # The list length is capped.
        assert service.batch_analyze([str(good_x64)] * 33, open_static=False).ok is False
    finally:
        service.close_all()
