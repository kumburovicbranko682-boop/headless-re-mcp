"""Last uncovered guards in the helpers every CLI/web backend shares.

``har_entry`` fills ``queryString`` by parsing the captured URL, but captures
record whatever the wire carried -- including URLs ``urlsplit`` refuses, such as
an unterminated IPv6 literal. That parse failure must cost the entry its query
pane, not the whole HAR export. And ``run_bounded``'s ``finally`` reap exists
for the surprise no scripted path reaches: an exception between spawning the
child and the normal timeout/return handling. Without the reap, that surprise
leaks a live JVM/node with the caller none the wiser.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from headless_re_mcp.backends.common import bounded_run
from headless_re_mcp.backends.common.har import _query_string, har_entry
from headless_re_mcp.core.process_tree import terminate_process_tree


# ---------------------------------------------------------------------------
# har: a URL urlsplit rejects loses its query pane, not the export.
# ---------------------------------------------------------------------------
def test_unparseable_url_yields_an_empty_query_string() -> None:
    # urlsplit raises ValueError("Invalid IPv6 URL") on the unterminated
    # bracket; a capture can hold exactly this if the wire did.
    assert _query_string("http://[::1/path?a=b") == []


def test_har_entry_survives_a_url_urlsplit_rejects() -> None:
    entry = har_entry(
        method="GET",
        url="http://[::1/path?a=b",
        status=200,
        mime_type="text/html",
    )
    request = entry["request"]
    assert isinstance(request, dict)
    assert request["url"] == "http://[::1/path?a=b"
    assert request["queryString"] == []


# ---------------------------------------------------------------------------
# run_bounded: a surprise error between spawn and the normal paths still
# reaps the child.
# ---------------------------------------------------------------------------
def test_a_surprise_error_after_spawn_still_reaps_the_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``finally`` reap fires when no scripted return/raise path ran.

    Every normal exit of run_bounded -- completion, timeout, cancel -- has
    already reaped or waited the child. The finally clause is for anything
    unexpected raised in between; here assign_to_process_group stands in for
    that surprise while a real sleeper child is alive. The child must be dead
    after the exception propagates, because a leaked JVM/node outliving its
    tool call is exactly what this module exists to prevent.
    """
    reaped: list[Any] = []

    def _recording_terminate(process: Any, **kwargs: Any) -> list[int]:
        reaped.append(process)
        return terminate_process_tree(process, **kwargs)

    monkeypatch.setattr(bounded_run, "terminate_process_tree", _recording_terminate)

    def _boom(pid: int) -> bool:
        raise RuntimeError("job-object attach exploded")

    monkeypatch.setattr(bounded_run, "assign_to_process_group", _boom)

    with pytest.raises(RuntimeError, match="job-object attach exploded"):
        bounded_run.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            timeout=30.0,
        )

    assert len(reaped) == 1
    # terminate_process_tree waits on the process, so poll() is set: the
    # sleeper did not outlive the failed call.
    assert reaped[0].poll() is not None
