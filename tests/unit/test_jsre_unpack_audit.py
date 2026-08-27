"""js.unpack_bundle must land in the global (session-less) audit log.

js.unpack_bundle writes an unpack-<uuid>/ tree under artifact_root/jsre/ but
keys by a file path, not a session, so -- exactly like device.pull/screenshot --
the artifact table (which needs a session_id) never registers it and it owns no
timeline. Without this the unpacked tree had zero provenance: nothing recorded
which bundle was unpacked, where it landed, or how many files it produced. These
pin that a successful unpack records a session-less audit entry naming the input
path plus output dir and file count, that a failure is recorded with its error
code, and that an audit-write failure never fails the unpack itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _FakeJs:
    """A JsClient stand-in for the one call js_unpack_bundle makes."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        del path, timeout, offset, limit
        if self.fail:
            raise JsReError("backend_error", "webcrack unpack failed")
        return {
            "output_dir": str(out_dir),
            "file_count": 3,
            "files": ["a.js", "b.js", "c.js"],
            "count": 3,
            "total": 3,
            "offset": 0,
            "has_more": False,
            "listing_truncated": False,
        }


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )


def _entries(service: AnalysisService) -> list[JsonObject]:
    result = service.audit_list(None)
    assert result.ok and result.data is not None
    return list(result.data["entries"])


def _by_action(service: AnalysisService, action: str) -> list[JsonObject]:
    return [e for e in _entries(service) if e["action"] == action]


def test_unpack_records_its_provenance_session_less(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_jsre.JsClient", lambda *a, **k: _FakeJs()
    )
    service = _service(tmp_path)
    try:
        result = service.js_unpack_bundle("/tmp/bundle.js")
        assert result.ok is True, result.error

        entry = _by_action(service, "js.unpack_bundle")[0]
        assert entry["session_id"] is None
        assert entry["ok"] == 1
        assert entry["params_summary"] == {"path": "/tmp/bundle.js"}
        assert entry["result_summary"]["file_count"] == 3
        assert entry["result_summary"]["output_dir"]  # a concrete tree path was recorded
    finally:
        service.close_all()


def test_a_failed_unpack_is_audited_with_its_code(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_jsre.JsClient", lambda *a, **k: _FakeJs(fail=True)
    )
    service = _service(tmp_path)
    try:
        result = service.js_unpack_bundle("/tmp/bundle.js")
        assert result.ok is False

        entry = _by_action(service, "js.unpack_bundle")[0]
        assert entry["ok"] == 0
        assert entry["result_summary"] == {"code": "backend_error"}
    finally:
        service.close_all()


def test_an_audit_write_failure_does_not_fail_the_unpack(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The tree was already written to disk; a bookkeeping failure in the audit
    write must not turn a successful unpack into a failed tool call."""
    monkeypatch.setattr(
        "headless_re_mcp.core.service_jsre.JsClient", lambda *a, **k: _FakeJs()
    )
    service = _service(tmp_path)
    original_repo = getattr(service, "repository", None)

    class _RaisingRepo:
        def append_audit(self, **kwargs: Any) -> None:
            raise RuntimeError("audit store is down")

    try:
        service.repository = _RaisingRepo()  # type: ignore[assignment]
        result = service.js_unpack_bundle("/tmp/bundle.js")
        assert result.ok is True
        assert result.data is not None
        assert result.data["file_count"] == 3
    finally:
        service.repository = original_repo  # type: ignore[assignment]
        service.close_all()
