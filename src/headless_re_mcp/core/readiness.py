"""Whether this process can accept new work, and which build is running.

Liveness and readiness are different questions. A process can answer HTTP while
its database is unreachable or its artifact directory is full, so a probe that
only proves the event loop is turning will keep a broken instance in rotation.
The checks here are deliberately cheap and side-effect free apart from one
zero-byte probe file, because a supervisor calls them on a short interval.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from headless_re_mcp import __version__

JsonObject = dict[str, Any]

UNKNOWN_COMMIT = "unknown"
_PROBE_NAME = ".readyz-probe"


class _Repository(Protocol):
    def list_unclean_sessions(self) -> list[JsonObject]: ...


@dataclass(frozen=True, slots=True)
class Check:
    """One pass/fail condition that gates readiness."""

    name: str
    ok: bool
    detail: str

    def as_json(self) -> JsonObject:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


def build_info() -> JsonObject:
    """Identify the running build so a bug report can name the right code.

    The commit is stamped into the environment by the release script rather than
    read from git: an installed package has no work tree, and a probe endpoint
    must not fork a process to answer.
    """
    return {
        "version": __version__,
        "commit": os.environ.get("HEADLESS_RE_BUILD_COMMIT", "").strip() or UNKNOWN_COMMIT,
        "python": platform.python_version(),
    }


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def probe_store(repository: _Repository) -> Check:
    """Confirm the metadata database still answers a trivial read."""
    try:
        repository.list_unclean_sessions()
    except BaseException as exc:  # noqa: BLE001 - reported, never raised at a probe
        return Check("store", False, _describe(exc))
    return Check("store", True, "readable")


def probe_artifact_root(root: Path) -> Check:
    """Confirm artifacts can still be written.

    Actually writes, because a directory that exists but has become read-only or
    sits on a full volume passes every cheaper test and then fails the first
    real analysis.
    """
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / _PROBE_NAME
        probe.write_bytes(b"")
        probe.unlink()
    except OSError as exc:
        return Check("artifact_root", False, _describe(exc))
    return Check("artifact_root", True, str(root))


def readiness_report(
    *,
    repository: _Repository,
    artifact_root: Path,
    open_sessions: int,
    backends: list[JsonObject],
    telemetry_log: Path | None,
    disk: JsonObject | None = None,
    disk_budget_bytes: int = 0,
) -> JsonObject:
    """Summarise whether this instance should receive traffic.

    An unhealthy backend does not make the process unready. It belongs to one
    session and the caller decides whether to recover it; draining the whole
    instance for it would turn a single failed analysis into an outage. Disk use
    is reported rather than gated for the same reason: the operator sets the
    alert threshold, because the right number depends on the volume.
    """
    checks = [probe_store(repository), probe_artifact_root(artifact_root)]
    unhealthy = [item for item in backends if not item.get("healthy", True)]
    return {
        "ready": all(check.ok for check in checks),
        "build": build_info(),
        "checks": [check.as_json() for check in checks],
        "sessions": {"open": open_sessions},
        "backends": {
            "total": len(backends),
            "unhealthy": len(unhealthy),
        },
        "disk": {
            **(disk or {}),
            # The budget only governs registered artifacts. Anything written
            # straight to the tree counts towards "bytes" and towards nothing
            # else, which is exactly the gap this field makes visible.
            "budget_bytes": disk_budget_bytes,
        },
        "telemetry_log": str(telemetry_log) if telemetry_log is not None else None,
    }
