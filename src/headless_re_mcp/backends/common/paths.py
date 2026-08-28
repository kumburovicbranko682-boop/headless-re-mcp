"""Filesystem probes shared across backends."""

from __future__ import annotations

import os
from pathlib import Path


def is_regular_file(path: Path | str) -> bool:
    """Whether ``path`` names an existing regular file, without ever raising.

    Use this for **caller-supplied input paths**. ``pathlib.Path.is_file()``
    swallows ENOENT (a plain missing file, answered ``False``) but *re-raises*
    ENAMETOOLONG, EACCES and other errnos, so a path with a component past the
    filesystem's NAME_MAX -- or an unreadable parent -- makes the probe throw an
    uncaught ``OSError`` rather than answering "no". A backend that does
    ``if not path.is_file(): raise not_found`` then crashes on a caller's bad
    path instead of failing cleanly.

    ``os.path.isfile`` is the standard throw-free form of exactly that check: it
    catches every ``OSError`` and returns ``False``. Routing caller-path
    existence checks through here means an impossible or unprobeable path reads
    as ``not_found`` (the file cannot be there) instead of a 500-shaped crash,
    while a normal present/absent file behaves identically to ``Path.is_file``.
    """
    return os.path.isfile(path)
