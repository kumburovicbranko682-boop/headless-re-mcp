"""proxy.export_har must both register its file and mark the timeline.

The backend ``ProxyBackend.export_har`` is pinned elsewhere (spec-valid HAR,
byte-bounded to the capture cap). This covers the *service* wiring around it,
which the backend tests never touch and which is what makes the export usable:

* the written HAR is registered as an artifact -- a bare path is a dead end in
  both directions, since nothing on the tool surface opens one and retention
  only reclaims what the repository knows about, so an unregistered HAR both
  hides from the agent that asked for it and grows the artifact root forever;
* a ``proxy.export_har`` timeline entry lands next to proxy.start / stop /
  replay / ca.install_android, so timeline.list can answer "a capture was
  exported", not just that a proxy ran;
* a failed export -- like every state-changing proxy sibling, which timeline
  only on success -- leaves no misleading "exported" mark.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FakeProxy:
    """A ProxyBackend stand-in for the one call proxy_export_har makes.

    It writes a real (small) file to the path the service chose so the service's
    own artifact registration -- hash, size, record -- runs against a genuine
    file, which is the wiring under test; the file's HAR validity is the backend
    test's concern, not this one's.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, Path]] = []
        self.fail = False

    def export_har(self, session_id: str, out_path: Path) -> JsonObject:
        self.calls.append((session_id, out_path))
        if self.fail:
            raise ProxyError("invalid_state", "proxy is not running")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps({"log": {"version": "1.2", "entries": []}}),
            encoding="utf-8",
        )
        return {"path": str(out_path), "entry_count": 2, "truncated": False, "size": 42}

    def close_all(self) -> None:  # close_all() calls this unguarded
        pass


def _open_session(tmp_path: Path) -> tuple[AnalysisService, str, _FakeProxy]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    fake = _FakeProxy()
    service._proxy_backend = fake  # type: ignore[attr-defined]
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"], fake


def _timeline_events(service: AnalysisService, session_id: str) -> list[JsonObject]:
    result = service.timeline_list(session_id)
    assert result.ok and result.data is not None, result.error
    return list(result.data["events"])


def test_proxy_export_har_registers_the_artifact_and_marks_the_timeline(
    tmp_path: Path,
) -> None:
    service, session_id, fake = _open_session(tmp_path)
    try:
        result = service.proxy_export_har(session_id)
        assert result.ok is True, result.error
        assert result.data is not None

        # The backend payload rides through unchanged...
        assert result.data["entry_count"] == 2
        assert result.data["truncated"] is False
        # ...and the service hangs a real, retrievable artifact id off it, so the
        # agent can re-open the HAR and retention can reclaim it.
        artifact_id = result.data.get("artifact_id")
        assert isinstance(artifact_id, str) and artifact_id
        described = service.repository.describe_artifact(artifact_id)
        assert described is not None
        assert described["kind"] == "proxy_har"
        assert Path(described["path"]).is_file()

        # And the export leaves exactly one timeline mark next to its siblings.
        exports = [
            e for e in _timeline_events(service, session_id) if e["event"] == "proxy.export_har"
        ]
        assert len(exports) == 1
    finally:
        service.close_all()


def test_a_failed_proxy_export_har_leaves_no_timeline_entry(tmp_path: Path) -> None:
    service, session_id, fake = _open_session(tmp_path)
    try:
        fake.fail = True
        result = service.proxy_export_har(session_id)
        assert result.ok is False
        assert result.error is not None

        events = _timeline_events(service, session_id)
        assert [e for e in events if e["event"] == "proxy.export_har"] == []
    finally:
        service.close_all()
