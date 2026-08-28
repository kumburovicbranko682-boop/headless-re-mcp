"""``artifacts.read`` must refuse a path outside artifact_root and floor its limit.

``_artifacts_read`` hands back raw bytes of a registered artifact by id. Two of
its guards are load-bearing yet inert under the existing suite, which only ever
reads legitimate in-root artifacts with a positive limit:

* **Path confinement.** ``register_artifact`` stores whatever path it is given
  verbatim -- it does not confine it -- so the reader is the last line of defense.
  Before opening anything it resolves the path and refuses, with
  ``permission_denied``, any artifact whose file is not under ``artifact_root``.
  A poisoned or crash-corrupted artifact row pointing at ``/etc/passwd`` (or any
  file outside the sandbox) must not be hex-dumped back to the caller. No test
  exercised this branch: every fixture registers a file under the root, so the
  refusal was dead code a mutation could delete unseen.

* **Byte-limit floor.** The agent and OpenAI-bridge transports call the handler
  straight from model arguments, skipping the schema, so a non-positive limit
  reaches ``stream.read(limit)`` unchecked. ``read(-5)`` reads to EOF -- an
  unbounded page over what may be a multi-gigabyte dump -- and ``read(0)`` reads
  nothing; ``limit = max(1, min(int(limit), 256 * 1024))`` turns any non-positive
  request into a single byte and caps an oversized one. Existing reads all pass a
  positive, in-range limit, so neither the floor nor the ceiling was pinned.

These tests register an out-of-root artifact and assert the refusal, register an
in-root one as the control that the guard does not over-reject, and drive the
limit floor and ceiling through the echoed ``limit`` field and the bytes served.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service import AnalysisService

# The per-read byte ceiling ``_artifacts_read`` enforces (inline ``256 * 1024``).
_READ_CEILING = 256 * 1024


def _service(tmp_path: Path) -> tuple[AnalysisService, InMemoryAnalysisRepository, Path]:
    root = tmp_path / "artifacts"
    repository = InMemoryAnalysisRepository(root)
    settings = replace(Settings.load(), artifact_root=root)
    service = AnalysisService(settings, repository=repository)
    return service, repository, root


def _register(repository: InMemoryAnalysisRepository, path: Path) -> str:
    artifact = repository.register_artifact(
        session_id="s",
        kind="capture",
        path=path,
        sha256="a" * 64,
        source="test",
    )
    return str(artifact["id"])


def test_a_path_outside_artifact_root_is_refused_not_dumped(tmp_path: Path) -> None:
    """An artifact row whose file escapes the root is a permission_denied, not bytes.

    The escaping file is real and readable, so a reader that skipped the
    confinement check would happily hex-dump it. The guard must fire before the
    open, turning a poisoned artifact path into a refusal.
    """
    service, repository, _root = _service(tmp_path)
    try:
        outside = tmp_path / "outside" / "secret.bin"
        outside.parent.mkdir(parents=True, exist_ok=True)
        outside.write_bytes(b"top-secret-bytes")
        artifact_id = _register(repository, outside)

        result = service.artifacts_read(artifact_id)

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "permission_denied"
        assert result.data is None
    finally:
        service.close_all()


def test_an_in_root_artifact_still_reads(tmp_path: Path) -> None:
    """Control: a file under the root is served, so the guard is a fence, not a wall.

    Without this, a mutation that denied every path would pass the refusal test
    above while quietly breaking every real read.
    """
    service, repository, root = _service(tmp_path)
    try:
        root.mkdir(parents=True, exist_ok=True)
        blob = root / "capture.bin"
        blob.write_bytes(b"0123456789")
        artifact_id = _register(repository, blob)

        result = service.artifacts_read(artifact_id, offset=0, limit=4)

        assert result.ok, result.error
        assert result.data is not None
        assert bytes.fromhex(str(result.data["data"])) == b"0123"
    finally:
        service.close_all()


def test_a_negative_limit_reads_one_byte_not_to_end_of_file(tmp_path: Path) -> None:
    """limit=-5 must not become ``read(-5)`` -- a read to EOF over the whole dump.

    The ``max(1, ...)`` floor collapses any non-positive limit to a single byte,
    so an out-of-range page cannot drain an arbitrarily large artifact.
    """
    service, repository, root = _service(tmp_path)
    try:
        root.mkdir(parents=True, exist_ok=True)
        blob = root / "capture.bin"
        blob.write_bytes(b"0123456789")
        artifact_id = _register(repository, blob)

        result = service.artifacts_read(artifact_id, offset=0, limit=-5)

        assert result.ok, result.error
        assert result.data is not None
        assert result.data["limit"] == 1
        assert bytes.fromhex(str(result.data["data"])) == b"0"
    finally:
        service.close_all()


def test_a_zero_limit_reads_one_byte(tmp_path: Path) -> None:
    """limit=0 is the boundary the floor exists for: ``read(0)`` is an empty page."""
    service, repository, root = _service(tmp_path)
    try:
        root.mkdir(parents=True, exist_ok=True)
        blob = root / "capture.bin"
        blob.write_bytes(b"0123456789")
        artifact_id = _register(repository, blob)

        result = service.artifacts_read(artifact_id, offset=0, limit=0)

        assert result.ok, result.error
        assert result.data is not None
        assert result.data["limit"] == 1
        assert bytes.fromhex(str(result.data["data"])) == b"0"
    finally:
        service.close_all()


def test_an_oversized_limit_is_capped_at_the_read_ceiling(tmp_path: Path) -> None:
    """A limit past the 256 KiB ceiling must be reported and served as the cap.

    The echoed ``limit`` is what a caller pages against; if it exceeded the
    ceiling the two transports would disagree about the largest read.
    """
    service, repository, root = _service(tmp_path)
    try:
        root.mkdir(parents=True, exist_ok=True)
        blob = root / "capture.bin"
        blob.write_bytes(b"0123456789")
        artifact_id = _register(repository, blob)

        result = service.artifacts_read(artifact_id, offset=0, limit=10**9)

        assert result.ok, result.error
        assert result.data is not None
        assert result.data["limit"] == _READ_CEILING
    finally:
        service.close_all()
