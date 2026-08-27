"""Session hydration must survive a poisoned persisted store, not sink the fleet.

On a console restart, in-flight sessions (PE, APK, and web alike) are rebound
from the sessions.db rows the last run left ``unclean``. That restore path runs
before anything else and over data an earlier crash may have left partial, so a
single malformed row -- or a store that cannot be read at all -- must degrade to
"skip it and keep going", never an exception that loses every other session.

The happy path and the missing-file case are pinned in test_session; this pins
the degradation surface:

* a store whose read raises leaves the registry empty and boots anyway,
* a non-mapping row, a path-traversal id, and a locator-less row are each
  skipped while the good rows around them still restore,
* an unrecognised state string falls back to CREATED rather than dropping the
  row,
* a restored **web** session keeps its http locator and is not mislabelled a
  missing file (there is no file on disk for a URL),
* an unparseable architecture or timestamp is tolerated, not fatal.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from headless_re_mcp.core.models import Architecture, SessionState, TargetKind
from headless_re_mcp.core.session import (
    SessionNotFound,
    SessionRegistry,
    hydrate_persisted_sessions,
    session_from_store_row,
)

_GOOD_ID = "ab" * 16


class _Source:
    """A fake SessionRecordSource returning a fixed page of rows."""

    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def list_unclean_sessions(
        self, *, offset: int = 0, limit: int = 100
    ) -> tuple[list[Any], int]:
        return self._rows[offset : offset + limit], len(self._rows)


class _BrokenSource:
    def list_unclean_sessions(self, *, offset: int = 0, limit: int = 100) -> tuple[list[Any], int]:
        raise OSError("sessions.db is locked")


def _web_row(session_id: str, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": session_id,
        "binary": "https://example.com/app",
        "state": "ready",
        "closed_cleanly": 0,
    }
    row.update(overrides)
    return row


def test_a_store_read_that_raises_boots_empty_instead_of_crashing() -> None:
    """A broken store must not take the console down: hydrate returns 0."""
    registry = SessionRegistry()
    assert hydrate_persisted_sessions(registry, _BrokenSource()) == 0


def test_a_non_mapping_row_is_skipped_and_the_good_rows_still_restore() -> None:
    """A stray non-dict row (a partial write) is stepped over, not fatal."""
    rows: list[Any] = ["not-a-mapping", None, _web_row(_GOOD_ID)]
    registry = SessionRegistry()
    assert hydrate_persisted_sessions(registry, _Source(rows)) == 1
    assert registry.get(_GOOD_ID).target is TargetKind.WEB


def test_a_path_traversal_or_empty_id_row_is_dropped() -> None:
    """The id names an on-disk session dir, so it must be a bare name."""
    for bad_id in ("", "../escape", "nested/id", "."):
        assert session_from_store_row(_web_row(bad_id)) is None


def test_a_locator_less_row_is_dropped() -> None:
    """Without a binary/locator there is nothing to rebind the session to."""
    assert session_from_store_row({"id": _GOOD_ID, "binary": "", "state": "ready"}) is None
    assert session_from_store_row({"id": _GOOD_ID, "state": "ready"}) is None


def test_an_unknown_state_falls_back_to_created_not_dropped() -> None:
    """A garbled state string must not lose the row: it hydrates as CREATED.

    Only genuinely terminal states (closed/failed/closing) are skipped; an
    unrecognised value is treated as a fresh CREATED session so a restart does
    not silently forget an in-flight target over one bad enum string.
    """
    session = session_from_store_row(_web_row(_GOOD_ID, state="who-knows"))
    assert session is not None
    assert session.state is SessionState.CREATED


def test_a_restored_web_session_keeps_its_url_and_is_not_a_missing_file() -> None:
    """A web target is a URL, not a file: keep the locator, do not flag missing.

    The missing-file marker exists for on-disk targets whose file is gone; a
    web session has no file, so flagging it would surface a phantom "missing"
    warning on every restored browsing session.
    """
    session = session_from_store_row(_web_row(_GOOD_ID))
    assert session is not None
    assert session.target is TargetKind.WEB
    assert session.locator == "https://example.com/app"
    assert session.binary is None
    assert "missing_file" not in session.metadata


def test_an_unparseable_architecture_is_tolerated() -> None:
    """A stored architecture the enum no longer knows becomes None, not a crash."""
    session = session_from_store_row(_web_row(_GOOD_ID, architecture="pentium-pro"))
    assert session is not None
    assert session.architecture is None


def test_a_known_architecture_survives_the_round_trip() -> None:
    session = session_from_store_row(_web_row(_GOOD_ID, architecture="x64"))
    assert session is not None
    assert session.architecture is Architecture.X64


def test_a_naive_datetime_object_is_made_timezone_aware() -> None:
    """A stored datetime lacking a tzinfo is normalised to UTC, not left naive."""
    naive = datetime(2020, 1, 2, 3, 4, 5)  # noqa: DTZ001 - deliberately naive input
    session = session_from_store_row(_web_row(_GOOD_ID, created_at=naive))
    assert session is not None
    assert session.created_at.tzinfo is not None


def test_an_unparseable_timestamp_falls_back_to_now() -> None:
    """A garbled created_at string yields a valid aware datetime, not an error."""
    before = datetime.now(UTC)
    session = session_from_store_row(_web_row(_GOOD_ID, created_at="last tuesday"))
    assert session is not None
    assert session.created_at.tzinfo is not None
    assert session.created_at >= before


def test_a_terminal_state_row_is_skipped_by_hydration() -> None:
    """A cleanly-classified terminal row is not resurrected on restart."""
    registry = SessionRegistry()
    rows: list[Any] = [_web_row("cd" * 16, state="closed")]
    assert hydrate_persisted_sessions(registry, _Source(rows)) == 0
    try:
        registry.get("cd" * 16)
    except SessionNotFound:
        pass
    else:  # pragma: no cover - the row must not have been adopted
        raise AssertionError("a closed row must not be hydrated")
