"""Web backend degradation gate: playwright installed, no browser binary.

Every test in test_web_lifecycle_gate.py opens a real browser and *skips* when
Chromium cannot launch, so on a host that has the playwright package but has not
run ``playwright install`` -- every CI runner that does not download a browser,
and many real deployments -- there is no web coverage that actually executes.
That is exactly the state this gate asserts against: web.open must degrade to a
structured ``backend_error`` (never a raw exception, never an internal_error
incident), must free the session slot so the id is reusable, and must not leave
the node driver process behind. It runs only in the browserless state and skips
honestly when a browser is present (the lifecycle/CDP gates cover that path).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.core.service import AnalysisService

_BLANK = "data:text/html,<html><head><title>degrade</title></head><body>x</body></html>"
_STRUCTURED = {"backend_error", "capability_unavailable"}
_BROWSER_PRESENT = "a browser is installed — browserless path not exercised (skip != pass)"


def _playwright_importable() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


def _open_attempt(backend: WebBackend, session_id: str) -> WebError | None:
    """Return the WebError from a browserless open, or None if a browser launched."""
    try:
        backend.open(session_id, _BLANK, headless=True, timeout=15.0)
    except WebError as exc:
        return exc
    return None


@pytest.mark.integration
def test_web_open_without_a_browser_is_a_structured_error_and_frees_the_slot() -> None:
    if not _playwright_importable():
        pytest.skip("playwright not installed — web degrade Gate not run (skip != pass)")
    backend = WebBackend()
    try:
        first = _open_attempt(backend, "degrade-1")
        if first is None:
            pytest.skip(_BROWSER_PRESENT)

        # A raw playwright exception escaping here would reach the service as an
        # internal_error incident; it must be wrapped as a structured code.
        assert first.code in _STRUCTURED, first.code
        # The opening reservation must be gone, not left wedging the id.
        assert backend.status("degrade-1") == {"open": False}
        # And the id must be reusable: a second open re-attempts the launch and
        # fails the same structured way, rather than tripping the "already open"
        # invalid_state a stuck reservation would produce.
        second = _open_attempt(backend, "degrade-1")
        assert second is not None
        assert second.code in _STRUCTURED, second.code
        assert second.code != "invalid_state"
    finally:
        backend.close_all()


@pytest.mark.integration
def test_web_open_failure_does_not_leak_the_node_driver() -> None:
    """A failed launch must reap the node driver it spawned, not orphan it.

    ``sync_playwright().start()`` spawns the node driver before the browser
    launch fails, and the open() failure path is what has to kill it. A leak
    here is invisible per call and fatal over a long unattended run -- one
    orphaned node per failed open. psutil is not a project dependency, so this
    is best-effort: it asserts only when psutil is present (the CI job installs
    it so the check is real there).
    """
    if not _playwright_importable():
        pytest.skip("playwright not installed — web degrade Gate not run (skip != pass)")
    try:
        import psutil
    except ImportError:
        pytest.skip("psutil not available — driver-leak check not run (skip != pass)")

    me: Any = psutil.Process()

    def driver_children() -> set[int]:
        found: set[int] = set()
        for child in me.children(recursive=True):
            try:
                name = child.name().casefold()
            except Exception:  # noqa: BLE001 - the child may already be gone
                continue
            if any(marker in name for marker in ("node", "chrom", "playwright")):
                found.add(child.pid)
        return found

    backend = WebBackend()
    try:
        before = driver_children()
        err = _open_attempt(backend, "degrade-leak")
        if err is None:
            pytest.skip(_BROWSER_PRESENT)
        # Give the reap a moment; it kills the tree asynchronously on failure.
        deadline = time.monotonic() + 5.0
        leaked = driver_children() - before
        while leaked and time.monotonic() < deadline:
            time.sleep(0.1)
            leaked = driver_children() - before
        assert not leaked, f"failed open leaked driver processes: {sorted(leaked)}"
    finally:
        backend.close_all()


@pytest.mark.integration
def test_service_web_open_without_a_browser_is_a_clean_backend_error(tmp_path: Path) -> None:
    if not _playwright_importable():
        pytest.skip("playwright not installed — web degrade Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(_BLANK, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=15.0)
        if opened.ok:
            pytest.skip(_BROWSER_PRESENT)
        # The raw playwright launch error must not reach the service envelope as
        # an internal_error with a logged incident; it is the caller's host
        # missing a browser, not a server defect.
        assert opened.error is not None
        assert opened.error.code != "internal_error", opened.error.code
        assert opened.error.code in _STRUCTURED, opened.error.code
        assert "incident_id" not in (opened.error.details or {})
    finally:
        service.close_all()
