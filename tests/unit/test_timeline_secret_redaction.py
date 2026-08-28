"""The session timeline must mask credentials, like the audit log already does.

timeline.list is an observability surface an operator reads after an unattended
run, so a secret that reaches a timeline entry is a durable leak. Every other
persistence sink -- audit rows, agent events, provider config -- runs the shared
`redact` at its write boundary; the timeline was the one that did not, leaning
entirely on each _timeline_append caller to hand-pick secret-free params (the way
web.type records only selector and length, never the typed text). That is one
careless call from a plaintext secret, so redaction now runs at the timeline
write boundary too. These pin that secret-looking keys and bearer substrings are
masked while the url / selector / pid / count params callers actually pass are
left intact, across both the file-backed and in-memory repositories and at the
low-level store function itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)
from headless_re_mcp.core.store.timeline import (
    append_session_timeline,
    list_session_timeline,
)


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_timeline_redacts_credentials_but_keeps_benign_params(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    repository = repository_type(tmp_path / "artifacts")
    repository.append_timeline(
        "session-1",
        "web.open",
        "web opened",
        url="https://example.test/app",
        selector="#login",
        pid=4242,
        authorization="Bearer top-secret",
        nested={"token": "nested-secret", "count": 3},
        note="send Bearer inline-secret",
    )

    events = repository.list_timeline("session-1")["events"]
    assert len(events) == 1
    details = events[0]["details"]
    # The params callers actually pass on the write lines are untouched.
    assert details["url"] == "https://example.test/app"
    assert details["selector"] == "#login"
    assert details["pid"] == 4242
    # Secret-looking keys and bearer substrings are masked, recursively.
    assert details["authorization"] == "***"
    assert details["nested"] == {"token": "***", "count": 3}
    assert details["note"] == "send Bearer ***"


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_timeline_marks_a_never_created_session_absent_in_both_stores(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    """A never-created session must read as absent (exists False) in both stores.

    application_services.list_timeline turns ``exists is False`` into
    session_not_found, and timeline.list documents that a session that was never
    created answers session_not_found, not an empty events list. The file-backed
    store reports ``exists: False`` when there is no timeline file; the in-memory
    port keyed its timeline by session id and simply returned an empty page for a
    missing id, with no ``exists`` flag -- so the same bogus (or post-restart) id
    read back as an ok empty timeline through the in-memory port but as
    session_not_found through SQLite. This pins the missing-session signal, and
    that a created session is NOT flagged absent, identically across both.
    """
    repository = repository_type(tmp_path / "artifacts")

    missing = repository.list_timeline("never-created")
    assert missing.get("exists") is False, "a never-created session must be flagged absent"
    assert missing["total"] == 0

    # A created session writes a session.created entry, so it is present and must
    # NOT carry the absent flag -- otherwise it would be misread as not-found.
    repository.append_timeline("s1", "session.created", "session created")
    present = repository.list_timeline("s1")
    assert present.get("exists") is not False
    assert present["total"] == 1


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_timeline_limit_clamps_to_the_same_ceiling_in_both_stores(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    """Both stores must clamp the timeline page to the same 256 ceiling.

    The timeline.list schema caps limit at le=256 and the file-backed store
    clamps to 256; the in-memory port clamped to 1000. A direct-transport caller
    (agent / OpenAI bridge) that skips the pydantic schema and asks for 500 would
    then get a 256-row page from SQLite but a 500-capable page from the in-memory
    port -- an observable divergence in a port that promises the same contract.
    """
    repository = repository_type(tmp_path / "artifacts")
    repository.append_timeline("s1", "session.created", "session created")

    page = repository.list_timeline("s1", limit=500)
    assert page["limit"] == 256


def test_append_session_timeline_masks_secrets_at_the_file_boundary(tmp_path: Path) -> None:
    """The redaction lives at the lowest write point, so no caller can bypass it."""
    path = tmp_path / "sessions" / "sess" / "timeline.jsonl"
    append_session_timeline(
        path,
        event="frida.hook",
        message="frida hook template injected as a probe (not resident)",
        details={"token": "leaked-secret", "template": "noop", "pid": 7},
    )

    events = list_session_timeline(path)["events"]
    assert len(events) == 1
    assert events[0]["details"] == {"token": "***", "template": "noop", "pid": 7}
