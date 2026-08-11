"""An unreadable interval must not silently switch self-healing off."""

from __future__ import annotations

from headless_re_mcp.config import _as_float


def test_an_unparsable_value_falls_back_to_the_default_not_to_zero() -> None:
    # Zero disables the monitor, so a typo used to turn off background healing
    # instead of ignoring the typo.
    assert _as_float("not-a-number", "also-bad", fallback=5.0) == 5.0


def test_the_environment_wins_when_it_parses() -> None:
    assert _as_float("2.5", 5.0, fallback=5.0) == 2.5


def test_the_file_value_is_used_when_the_environment_is_unset() -> None:
    assert _as_float(None, 7.0, fallback=5.0) == 7.0


def test_an_explicit_zero_still_disables_the_monitor() -> None:
    # Turning the monitor off has to stay possible; only unreadable input falls
    # back to the default.
    assert _as_float("0", 5.0, fallback=5.0) == 0.0


def test_a_negative_interval_is_clamped_rather_than_rejected() -> None:
    assert _as_float("-3", 5.0, fallback=5.0) == 0.0
