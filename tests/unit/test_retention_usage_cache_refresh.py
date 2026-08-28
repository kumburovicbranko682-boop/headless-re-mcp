"""Branch coverage for the UsageCache background refresh failure arcs.

``test_retention_measure_usage.py`` pins the disk-walk bounds inside
``measure_usage``. These pin the two arcs in ``UsageCache._refresh`` the wider
suite does not reach: a failed walk that must keep the last good measurement
rather than overwrite it with the cold-start floor, and a repeated failure that
must not re-alert. ``_refresh`` is driven directly (it runs synchronously) so
no daemon thread is involved. A separate file keeps this off the
measure_usage-focused test module.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.core.retention as retention
from headless_re_mcp.core.retention import DiskUsage, UsageCache


def test_refresh_keeps_the_last_good_value_when_a_later_walk_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(retention, "record_alert", lambda *args, **kwargs: None)
    cache = UsageCache()

    monkeypatch.setattr(
        retention,
        "measure_usage",
        lambda root, **kwargs: DiskUsage(bytes=4096, files=3, truncated=False),
    )
    cache._refresh(tmp_path)
    assert cache._value == DiskUsage(bytes=4096, files=3, truncated=False)

    def _boom(root: Path, **kwargs: object) -> DiskUsage:
        raise RuntimeError("volume went away")

    monkeypatch.setattr(retention, "measure_usage", _boom)
    cache._refresh(tmp_path)

    # The failed walk keeps the last measurement instead of resetting it to the
    # cold-start floor, so a probe still sees the real number, marked failing.
    assert cache._value == DiskUsage(bytes=4096, files=3, truncated=False)
    assert cache._failing is True
    assert cache._refreshing is False


def test_refresh_alerts_once_then_stays_quiet_while_it_keeps_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alerts: list[str] = []
    monkeypatch.setattr(retention, "record_alert", lambda kind, **kwargs: alerts.append(kind))

    def _boom(root: Path, **kwargs: object) -> DiskUsage:
        raise OSError("walk refused")

    monkeypatch.setattr(retention, "measure_usage", _boom)
    cache = UsageCache()

    cache._refresh(tmp_path)  # first failure raises the alert
    cache._refresh(tmp_path)  # still failing: must not re-alert

    assert alerts == ["artifact_usage_measurement_failing"]
    # A cold-start failure with no prior value falls back to the floor.
    assert cache._value == DiskUsage(bytes=0, files=0, truncated=True)
    assert cache._failing is True
