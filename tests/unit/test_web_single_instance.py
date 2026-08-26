"""One console per artifact root.

A second one is not additive: creating the app declares every run the first has
in flight dead and requeues its missions, and then both schedulers claim from
the same database. Measured against two real consoles before the guard: a run
that was streaming became interrupted with service_restarted while the first
instance was still executing it.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from headless_re_mcp.web.app import _claim_artifact_root


def test_a_second_console_cannot_claim_a_root_that_is_in_use(tmp_path: Path) -> None:
    first = _claim_artifact_root(tmp_path)
    assert first is not None and first >= 0, "the first console takes the root"
    try:
        assert _claim_artifact_root(tmp_path) is None, "the second must be refused"
    finally:
        os.close(first)


def test_the_root_is_free_again_once_the_holder_lets_go(tmp_path: Path) -> None:
    """The supervisor restarts within a second of killing the child.

    An operating-system lock rather than a lease for exactly this reason: a
    lease would leave the replacement waiting for its own predecessor to
    expire. Closing the handle stands in for the process dying, which is when
    the kernel drops it.
    """
    first = _claim_artifact_root(tmp_path)
    assert first is not None
    os.close(first)

    second = _claim_artifact_root(tmp_path)
    assert second is not None and second >= 0, "the replacement must not have to wait"
    os.close(second)


def test_two_different_roots_do_not_block_each_other(tmp_path: Path) -> None:
    """The guard is about sharing one database, not about running one console."""
    left = _claim_artifact_root(tmp_path / "left")
    right = _claim_artifact_root(tmp_path / "right")
    try:
        assert left is not None and left >= 0
        assert right is not None and right >= 0
    finally:
        for handle in (left, right):
            if handle is not None and handle >= 0:
                os.close(handle)


def test_console_refuses_to_run_when_the_root_lock_cannot_be_created(
    tmp_path: Path, monkeypatch: Any
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> int:
        raise PermissionError("read-only artifact root")

    monkeypatch.setattr(os, "open", unavailable)

    assert _claim_artifact_root(tmp_path) is None
