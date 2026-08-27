"""Spilled web bodies and sources must be registered artifacts, not dead ends.

web.network.get and web.script.source spill oversized payloads to the session
artifact area and return body_path / source_path. _register_capture exists
because a bare path is a dead end in both directions: nothing on the tool
surface opens one (artifacts.read takes an artifact_id), and retention only
reclaims files the repository knows about. The service blocks that wire the
two spill tools through registration (service_web web_network_get and
web_script_source) had no coverage, so dropping either would return payloads
whose spilled file no tool can read back -- with every direct test of
_register_capture still green.

A fake WebBackend writes the spill exactly where the real one does (the
directory the service hands it -- artifact_root/web/<session_id>) and returns
the real payload shape, so these exercise the service wiring, not Playwright.
The round trip through artifacts.read is asserted, not just the id's presence:
an id that describe/read cannot resolve would satisfy a key-presence check and
still be a dead end.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]

_SPILL = b"function hidden() { return 'the-part-past-the-inline-cap'; }\n"


class _FakeWeb:
    """WebBackend stand-in: spills where pointed, binds no real browser."""

    def __init__(self, *, spill: bool = True, spill_to: str | None = None) -> None:
        self._spill = spill
        self._spill_to = spill_to

    def _spill_path(self, artifact_dir: Path, name: str) -> str:
        if self._spill_to is not None:
            return self._spill_to
        out = Path(artifact_dir) / name
        out.write_bytes(_SPILL)
        return str(out)

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> JsonObject:
        payload: JsonObject = {"body": "", "base64_encoded": False, "body_truncated": False}
        if not self._spill:
            payload["body"] = "small inline body"
            return payload
        payload["body_truncated"] = True
        payload["body_path"] = self._spill_path(artifact_dir, f"body-{request_id}.bin")
        return payload

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> JsonObject:
        return {
            "scriptId": script_id,
            "bytes": len(_SPILL),
            "source": "",
            "truncated": True,
            "source_path": self._spill_path(artifact_dir, f"script-{script_id}.js"),
        }

    def close(self, session_id: str) -> JsonObject:
        return {"closed": True}

    def close_all(self) -> None:
        return None


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _read_back(service: AnalysisService, artifact_id: str) -> bytes:
    read = service.artifacts_read(artifact_id, limit=4096)
    assert read.ok and read.data is not None, read.error
    return bytes.fromhex(str(read.data["data"]))


def test_a_spilled_body_is_registered_and_readable_via_artifacts_read(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service._web_backend = _FakeWeb()  # type: ignore[assignment]

        result = service.web_network_get(session_id, "r1")

        assert result.ok and result.data is not None, result.error
        artifact_id = result.data.get("artifact_id")
        assert isinstance(artifact_id, str) and artifact_id, (
            "a spilled body must carry the id artifacts.read accepts"
        )
        # The documented spill fields survive the registration rewrap.
        assert result.data["body_truncated"] is True
        assert str(result.data["body_path"]).endswith("body-r1.bin")

        described = service.artifacts_describe(artifact_id)
        assert described.ok and described.data is not None, described.error
        artifact = described.data["artifact"]
        assert artifact["kind"] == "web_response_body"
        assert artifact["source"] == "web.network.get"

        assert _read_back(service, artifact_id) == _SPILL
    finally:
        service.close_all()


def test_a_spilled_script_source_is_registered_and_readable(tmp_path: Path) -> None:
    """script.source has its own registration block; pinning it separately
    catches a regression that keeps the body wiring and drops the source one."""
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service._web_backend = _FakeWeb()  # type: ignore[assignment]

        result = service.web_script_source(session_id, "42")

        assert result.ok and result.data is not None, result.error
        artifact_id = result.data.get("artifact_id")
        assert isinstance(artifact_id, str) and artifact_id

        described = service.artifacts_describe(artifact_id)
        assert described.ok and described.data is not None, described.error
        artifact = described.data["artifact"]
        assert artifact["kind"] == "web_script_source"
        assert artifact["source"] == "web.script.source"

        assert _read_back(service, artifact_id) == _SPILL
    finally:
        service.close_all()


def test_an_inline_body_registers_nothing(tmp_path: Path) -> None:
    """No spill, no artifact: registering the absence would fabricate an id for
    a file that does not exist, and artifact_error would misreport success."""
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service._web_backend = _FakeWeb(spill=False)  # type: ignore[assignment]

        result = service.web_network_get(session_id, "r1")

        assert result.ok and result.data is not None, result.error
        assert result.data["body"] == "small inline body"
        assert "artifact_id" not in result.data
        assert "artifact_error" not in result.data
    finally:
        service.close_all()


def test_a_spill_path_whose_file_vanished_passes_through_unregistered(tmp_path: Path) -> None:
    """_register_capture must not fail the capture: a body_path pointing at a
    file that is already gone (raced retention, backend bug) returns the payload
    untouched rather than raising or minting an id for nothing."""
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        gone = tmp_path / "never-written.bin"
        service._web_backend = _FakeWeb(spill_to=str(gone))  # type: ignore[assignment]

        result = service.web_network_get(session_id, "r1")

        assert result.ok and result.data is not None, result.error
        assert result.data["body_path"] == str(gone)
        assert "artifact_id" not in result.data
        assert "artifact_error" not in result.data
    finally:
        service.close_all()
