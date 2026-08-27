"""Declared-size pre-flight for tools that inflate an APK.

apktool and jadx inflate the archive onto disk; androguard inflates it into
RAM. A hostile APK can declare petabytes in its central directory (the classic
42.zip shape) and each of those tools will faithfully try to materialise it,
bounded only by the call timeout -- which is minutes of disk- or RAM-filling
before the deadline fires. The central directory itself is cheap to read, so
every inflation point runs this check first and refuses the bomb before any
tool spends a byte on it.

The caps are far above anything a legitimate app ships (Play distributes at
most 4 GB, and resource tables top out at tens of thousands of entries) while
turning a declared-petabyte or million-member archive into a clean refusal.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

_MAX_MEMBERS = 100_000
_MAX_DECLARED_BYTES = 4 * 1024**3


class ZipExpansionError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def check_zip_expansion(
    path: Path,
    *,
    max_members: int | None = None,
    max_declared_bytes: int | None = None,
) -> dict[str, int]:
    """Refuse an archive whose central directory declares a bomb.

    Raises ``too_large`` when the declared uncompressed total or the member
    count exceeds the cap, and ``invalid_params`` when the central directory
    cannot be read at all -- a zip none of the downstream tools could decode
    either, so refusing early loses nothing and fails closed. Returns the
    declared totals so callers can surface them.
    """
    members_cap = _MAX_MEMBERS if max_members is None else max_members
    bytes_cap = _MAX_DECLARED_BYTES if max_declared_bytes is None else max_declared_bytes
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            member_count = len(entries)
            declared = sum(max(0, item.file_size) for item in entries)
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
        raise ZipExpansionError(
            "invalid_params",
            f"not a readable zip archive: {exc}",
            path=str(path),
        ) from exc
    if member_count > members_cap:
        raise ZipExpansionError(
            "too_large",
            "archive declares too many members",
            members=member_count,
            cap=members_cap,
        )
    if declared > bytes_cap:
        raise ZipExpansionError(
            "too_large",
            "archive declares an expansion beyond the safety cap",
            declared_bytes=declared,
            cap=bytes_cap,
        )
    return {"members": member_count, "declared_bytes": declared}
