"""An unreadable interval must not silently switch self-healing off."""

from __future__ import annotations

import pytest

from headless_re_mcp.config import _as_bool, _as_float, _as_tuple, _loaded_string_tuple


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


def _tripwire_preset() -> tuple[str, ...]:
    raise AssertionError("preset must not be consulted when a value is provided")


def test_loaded_string_tuple_lets_the_environment_override_everything() -> None:
    """agent_auto_approve_* resolve here; the env var must win over file+preset."""
    assert _loaded_string_tuple("a,b", {"k": ["ignored"]}, "k", preset=_tripwire_preset) == (
        "a",
        "b",
    )
    # An env var set to empty is still a decision: auto-approve nothing, and it
    # must not fall through to the preset.
    assert _loaded_string_tuple("", {"k": ["ignored"]}, "k", preset=_tripwire_preset) == ()


def test_loaded_string_tuple_treats_an_explicit_empty_list_as_fail_closed() -> None:
    """A user who writes ``"agent_auto_approve_tools": []`` means *nothing*.

    The key being present -- even as [] -- is an explicit choice and must not be
    quietly replaced by the packed-analysis preset, or opting out of
    auto-approval would silently re-enable it.
    """
    assert _loaded_string_tuple(None, {"k": []}, "k", preset=_tripwire_preset) == ()
    assert _loaded_string_tuple(None, {"k": ["x", "x", " y "]}, "k", preset=_tripwire_preset) == (
        "x",
        "y",
    )


def test_loaded_string_tuple_uses_the_preset_only_when_the_key_is_absent() -> None:
    """An unset key (no env, not in the file) is what earns the preset default."""
    marker = ("state_change",)
    assert _loaded_string_tuple(None, {}, "k", preset=lambda: marker) == marker


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


@pytest.mark.parametrize("word", ["inf", "-inf", "infinity", "Infinity", "1e400", "nan", "NaN"])
def test_a_non_finite_environment_value_falls_back_to_the_default(word: str) -> None:
    # float() parses these without raising -- "inf"/"nan" directly and "1e400"
    # by overflow -- so before the guard they reached the setting as inf/nan. An
    # infinite interval makes time.sleep raise OverflowError out of the health
    # loop, and both inf and nan compare so that a watchdog is never due; a
    # nonsense value has to be ignored exactly like any other unreadable typo.
    assert _as_float(word, 5.0, fallback=5.0) == 5.0


def test_a_non_finite_file_default_falls_back_too() -> None:
    # A config file supplies the default, and json.loads turns 1e400 / Infinity
    # into a Python float("inf"), so the file path needs the same guard as the
    # environment string one.
    assert _as_float(None, float("inf"), fallback=5.0) == 5.0
    assert _as_float(None, float("nan"), fallback=5.0) == 5.0


def test_a_non_finite_environment_value_still_prefers_a_readable_file_default() -> None:
    # The env var is unreadable, but the file default is a real number: it, not
    # the fallback, is what a non-finite env override should defer to.
    assert _as_float("inf", 7.0, fallback=5.0) == 7.0
