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
