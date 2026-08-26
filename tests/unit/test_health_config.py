"""An unreadable interval must not silently switch self-healing off."""

from __future__ import annotations

import pytest

from headless_re_mcp.config import _as_bool, _as_float, _as_tuple


def test_an_unparsable_value_falls_back_to_the_default_not_to_zero() -> None:
    # Zero disables the monitor, so a typo used to turn off background healing
    # instead of ignoring the typo.
    assert _as_float("not-a-number", "also-bad", fallback=5.0) == 5.0


@pytest.mark.parametrize("falsey", ["0", "false", "no", "off", "FALSE", "  Off  ", "No"])
def test_as_bool_reads_the_documented_false_words_case_and_space_insensitively(
    falsey: str,
) -> None:
    """_as_bool gates local_full_access -- the whole write surface -- so the set
    of words that mean 'off' must be exactly {0,false,no,off}, trimmed and
    case-folded, and nothing else may read as false."""
    assert _as_bool(falsey, True) is False


@pytest.mark.parametrize("truthy", ["1", "true", "yes", "on", "TRUE", "enabled", "anything"])
def test_as_bool_treats_every_other_nonempty_value_as_true(truthy: str) -> None:
    assert _as_bool(truthy, False) is True


def test_as_bool_uses_the_default_only_when_unset() -> None:
    # None means the env var is unset: fall back to the file/default value,
    # which for local_full_access is True (the documented single-user default).
    assert _as_bool(None, True) is True
    assert _as_bool(None, False) is False
    # An empty string is a *set* value, and is not one of the false words, so it
    # reads true rather than falling back -- pin it so the behaviour is a choice.
    assert _as_bool("", False) is True


def test_as_tuple_splits_strips_drops_empties_and_dedupes_in_order() -> None:
    """agent_never_auto_approve is parsed here; a repeated rule must not look
    like two, and blank fragments from trailing commas must not become rules."""
    assert _as_tuple("a, b ,a,, c ", ()) == ("a", "b", "c")
    # A JSON/default list is normalized the same way.
    assert _as_tuple(None, ["x", "x", " y "]) == ("x", "y")
    # A default string is comma-split just like the env var.
    assert _as_tuple(None, "p, q ,p") == ("p", "q")
    # Neither env nor a stringy/listy default -> empty, never a crash.
    assert _as_tuple(None, None) == ()
    assert _as_tuple("", ()) == ()


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
