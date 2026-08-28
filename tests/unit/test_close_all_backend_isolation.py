"""Shutdown cleanup in AnalysisService.close_all must be best-effort per backend.

close_all reaps the long-lived resources the non-PE tracks hold: the browser and
its driver (web), the mitmproxy subprocess (proxy) and the adb port forwards. The
old implementation called each cleanup on a straight line, so the first one that
raised -- a wedged driver reap, say -- skipped every step behind it and let the
exception escape close_all, stranding the mitmproxy subprocess and the forwards
and surprising the run_stdio/web shutdown paths that call it without a try.

These tests pin the contract: every backend cleanup is attempted regardless of
its siblings, a failure is reported in the envelope (not swallowed, not raised)
so an operator can see which resource may have leaked, and a clean shutdown still
answers a plain {"closed": n}.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


class _RecordingProxy:
    def __init__(self) -> None:
        self.closed = False

    def close_all(self) -> None:
        self.closed = True


class _RecordingAdb:
    def __init__(self) -> None:
        self.released = False

    def release_forwards(self) -> dict[str, object]:
        self.released = True
        return {"count": 0, "removed": [], "failed": []}


class _ExplodingWeb:
    def __init__(self) -> None:
        self.called = False

    def close_all(self) -> None:
        self.called = True
        raise RuntimeError("driver reap wedged")


class _QuietWeb:
    def __init__(self) -> None:
        self.called = False

    def close_all(self) -> None:
        self.called = True


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        yield svc
    finally:
        # close_all is best-effort and no longer raises, so a second call in
        # teardown is a harmless belt-and-braces stop of anything still live.
        svc.close_all()


def test_a_failing_web_cleanup_still_reaps_proxy_and_adb(
    service: AnalysisService,
) -> None:
    web = _ExplodingWeb()
    proxy = _RecordingProxy()
    adb = _RecordingAdb()
    service._web_backend = web  # type: ignore[assignment]
    service._proxy_backend = proxy  # type: ignore[assignment]
    service._adb_backend = adb  # type: ignore[assignment]

    # No exception escapes -- the shutdown paths call this without a try.
    result = service.close_all()

    # The failing backend was attempted, and so were the two behind it.
    assert web.called is True
    assert proxy.closed is True, "a web failure must not strand the mitmproxy subprocess"
    assert adb.released is True, "a web failure must not strand the adb forwards"

    # The failure is surfaced, not swallowed.
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "close_all_failed"
    components = {
        entry.get("component")
        for entry in result.error.details["errors"]
        if isinstance(entry, dict)
    }
    assert "web_backend" in components
    web_entry = next(
        entry
        for entry in result.error.details["errors"]
        if isinstance(entry, dict) and entry.get("component") == "web_backend"
    )
    assert web_entry["error"]["type"] == "RuntimeError"
    assert "wedged" in web_entry["error"]["message"]


def test_a_clean_shutdown_answers_closed_zero(service: AnalysisService) -> None:
    web = _QuietWeb()
    proxy = _RecordingProxy()
    adb = _RecordingAdb()
    service._web_backend = web  # type: ignore[assignment]
    service._proxy_backend = proxy  # type: ignore[assignment]
    service._adb_backend = adb  # type: ignore[assignment]

    result = service.close_all()

    assert web.called and proxy.closed and adb.released
    assert result.ok is True
    assert result.data is not None
    assert result.data["closed"] == 0


def test_a_failing_health_stop_does_not_skip_the_backends(
    service: AnalysisService,
) -> None:
    class _ExplodingHealth:
        def stop(self) -> None:
            raise RuntimeError("monitor thread would not join")

    proxy = _RecordingProxy()
    adb = _RecordingAdb()
    service._health = _ExplodingHealth()  # type: ignore[assignment]
    service._web_backend = _QuietWeb()  # type: ignore[assignment]
    service._proxy_backend = proxy  # type: ignore[assignment]
    service._adb_backend = adb  # type: ignore[assignment]

    result = service.close_all()

    assert proxy.closed is True
    assert adb.released is True
    assert result.ok is False
    assert result.error is not None
    components = {
        entry.get("component")
        for entry in result.error.details["errors"]
        if isinstance(entry, dict)
    }
    assert "health_monitor" in components
