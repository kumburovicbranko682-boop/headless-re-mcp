"""``_register_capture`` must register a capture without ever failing it.

Every web/proxy/apk capture that writes a file (screenshot, HAR, response body,
script source, flow body) runs its payload through ``_register_capture`` so the
file enters the artifact table -- otherwise the tool surface has no id to open it
with and retention, which only collects what the repository knows, lets it grow
the artifact root forever. The load-bearing rule is in the docstring:
"registering must not fail the capture -- the file exists either way -- so a
failure travels in the payload rather than as an exception."

That gives three legs, and the fixtures elsewhere only ever exercise the happy
one (a real file, a healthy repository):

* the file the capture named is **not** there -- return the payload untouched,
  with neither an ``artifact_id`` nor an ``artifact_error``, and without even
  attempting to register a phantom path;
* the file is there and registration succeeds -- attach the ``artifact_id``;
* the file is there but registration raises -- swallow it and attach
  ``artifact_error`` so the capture result still lands.

The missing-file leg is the one no test drove: with a real file always present,
the ``path.is_file()`` guard was inert, and deleting it would turn a capture
that produced nothing into one that reports an ``artifact_error`` from hashing a
file that is not there. These pin all three legs against a fake recorder, and
check the caller's payload dict is never mutated in place.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.core.service_ext import _register_capture


class _FakeService:
    """A stand-in whose ``record_artifact`` the helper prefers over a repository."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[dict[str, Any]] = []
        self._fail = fail

    def record_artifact(self, **fields: Any) -> dict[str, Any]:
        self.calls.append(fields)
        if self._fail:
            raise RuntimeError("repository is down")
        return {"id": "artifact-1"}


def test_a_missing_capture_file_returns_the_payload_untouched(tmp_path: Path) -> None:
    """A path the capture never wrote is not registered and not an error.

    Without the ``path.is_file()`` guard the helper would try to hash a file
    that is not there, raise inside registration, and report an
    ``artifact_error`` -- turning "the capture produced nothing" into a failure
    signal. The guard makes it a clean no-op: payload back, nothing registered.
    """
    service = _FakeService()
    payload = {"kind": "screenshot", "note": "kept"}

    result = _register_capture(
        service,
        "s",
        tmp_path / "does-not-exist.png",
        kind="web_screenshot",
        source="web.screenshot",
        payload=payload,
    )

    assert result == {"kind": "screenshot", "note": "kept"}
    assert "artifact_id" not in result
    assert "artifact_error" not in result
    assert service.calls == [], "a phantom path must not reach the artifact table"


def test_a_written_capture_gets_its_artifact_id(tmp_path: Path) -> None:
    """The happy path: a real file is registered and its id rides in the payload."""
    service = _FakeService()
    blob = tmp_path / "capture.bin"
    blob.write_bytes(b"captured-bytes")
    payload = {"kind": "har"}

    result = _register_capture(
        service,
        "s",
        blob,
        kind="web_har",
        source="web.har.export",
        payload=payload,
    )

    assert result["artifact_id"] == "artifact-1"
    assert result["kind"] == "har"
    assert "artifact_error" not in result
    assert len(service.calls) == 1


def test_a_registration_failure_is_reported_not_raised(tmp_path: Path) -> None:
    """A repository that raises must not lose the capture: report, do not throw.

    The file exists, so the capture succeeded; only the bookkeeping failed. The
    error travels as ``artifact_error`` and no ``artifact_id`` is fabricated.
    """
    service = _FakeService(fail=True)
    blob = tmp_path / "capture.bin"
    blob.write_bytes(b"captured-bytes")

    result = _register_capture(
        service,
        "s",
        blob,
        kind="web_har",
        source="web.har.export",
        payload={"kind": "har"},
    )

    assert "repository is down" in result["artifact_error"]
    assert "artifact_id" not in result
    assert result["kind"] == "har"


def test_the_callers_payload_dict_is_not_mutated_in_place(tmp_path: Path) -> None:
    """The helper returns a new dict; the caller's payload is left as it was.

    Callers pass the same payload they will return on the error path, so an
    in-place ``artifact_id`` would leak into results that never registered.
    """
    service = _FakeService()
    blob = tmp_path / "capture.bin"
    blob.write_bytes(b"x")
    payload = {"kind": "screenshot"}

    _register_capture(
        service,
        "s",
        blob,
        kind="web_screenshot",
        source="web.screenshot",
        payload=payload,
    )

    assert payload == {"kind": "screenshot"}, "input payload must not gain artifact_id"
