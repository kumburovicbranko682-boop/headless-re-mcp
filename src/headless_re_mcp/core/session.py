from __future__ import annotations

import hashlib
import zipfile
from collections import deque
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any

from headless_re_mcp.core.models import (
    Architecture,
    BackendHandle,
    BackendKind,
    Session,
    SessionState,
    TargetKind,
)

_ALLOWED_TRANSITIONS: dict[SessionState, frozenset[SessionState]] = {
    SessionState.CREATED: frozenset(
        {SessionState.OPENING, SessionState.CLOSING, SessionState.FAILED}
    ),
    SessionState.OPENING: frozenset(
        {SessionState.READY, SessionState.SUSPENDED, SessionState.FAILED}
    ),
    SessionState.READY: frozenset(
        {SessionState.RUNNING, SessionState.SUSPENDED, SessionState.CLOSING, SessionState.FAILED}
    ),
    SessionState.RUNNING: frozenset(
        {SessionState.SUSPENDED, SessionState.CLOSING, SessionState.FAILED}
    ),
    SessionState.SUSPENDED: frozenset(
        {SessionState.RUNNING, SessionState.READY, SessionState.CLOSING, SessionState.FAILED}
    ),
    SessionState.CLOSING: frozenset({SessionState.CLOSED, SessionState.FAILED}),
    SessionState.CLOSED: frozenset(),
    SessionState.FAILED: frozenset({SessionState.CLOSING, SessionState.CLOSED}),
}


class InvalidStateTransition(RuntimeError):
    pass


# A closed session is kept so the caller can still read how it ended, but the
# registry is in memory and a long-lived server closes sessions forever. Nothing
# called remove_closed outside tests, so every session ever opened stayed
# resident and session.list returned the entire history.
_RETAINED_CLOSED_SESSIONS = 64


class SessionNotFound(KeyError):
    """Asked for a session that is not there.

    A distinct type because the result mapper turned *any* KeyError into
    ``session_not_found``: a missing dictionary key while parsing a backend
    reply, or a cache eviction race, told an unattended caller that its session
    had disappeared -- and the reasonable thing to do about that, recreating the
    session, is exactly the wrong response to a transient internal error. It
    subclasses KeyError so every existing ``except KeyError`` still catches it.
    """


class SessionRegistry:
    def __init__(self, *, retained_closed: int = _RETAINED_CLOSED_SESSIONS) -> None:
        self._sessions: dict[str, Session] = {}
        self._closed_order: deque[str] = deque()
        self._retained_closed = max(0, retained_closed)
        self._lock = RLock()

    def create(
        self,
        reference: str | Path,
        *,
        target: TargetKind | None = None,
    ) -> Session:
        text = str(reference).strip()
        kind = target if target is not None else classify_target(text)
        if kind is TargetKind.WEB:
            candidate = Path(text).expanduser()
            # A web target can be a remote URL (any scheme) or a local asset
            # such as a downloaded .js/.wasm; only the latter has a binary.
            if not is_http_url(text) and candidate.is_file():
                path = candidate.resolve()
                session = Session(
                    target=kind,
                    binary=path,
                    locator=str(path),
                    sha256=file_sha256(path),
                )
            else:
                session = Session(target=kind, locator=text)
        else:
            path = Path(text).expanduser().resolve(strict=True)
            if not path.is_file():
                raise ValueError(f"session target is not a regular file: {path}")
            architecture: Architecture | None = None
            metadata: dict[str, Any] = {}
            if kind is TargetKind.PE:
                architecture = detect_pe_architecture(path)
            elif kind is TargetKind.APK:
                metadata = describe_apk(path)
            session = Session(
                target=kind,
                binary=path,
                locator=str(path),
                sha256=file_sha256(path),
                architecture=architecture,
                metadata=metadata,
            )
        with self._lock:
            self._sessions[session.id] = session
        return session.model_copy(deep=True)

    def get(self, session_id: str) -> Session:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionNotFound(f"session not found: {session_id}")
            return session.model_copy(deep=True)

    def list(self, states: Iterable[SessionState] | None = None) -> list[Session]:
        allowed = set(states) if states is not None else None
        with self._lock:
            return [
                session.model_copy(deep=True)
                for session in self._sessions.values()
                if allowed is None or session.state in allowed
            ]

    def transition(self, session_id: str, target: SessionState) -> Session:
        with self._lock:
            session = self._require(session_id)
            if target == session.state:
                return session.model_copy(deep=True)
            if target not in _ALLOWED_TRANSITIONS[session.state]:
                raise InvalidStateTransition(
                    f"{session.state.value} -> {target.value} is not allowed"
                )
            session.state = target
            session.updated_at = datetime.now(UTC)
            if target is SessionState.CLOSED:
                self._retire_closed(session_id)
            return session.model_copy(deep=True)

    def _retire_closed(self, session_id: str) -> None:
        """Drop the oldest closed sessions once the retained history is full."""
        self._closed_order.append(session_id)
        while len(self._closed_order) > self._retained_closed:
            self._sessions.pop(self._closed_order.popleft(), None)

    def attach_backend(self, session_id: str, handle: BackendHandle) -> Session:
        with self._lock:
            session = self._require(session_id)
            if session.state in {SessionState.CLOSING, SessionState.CLOSED}:
                raise InvalidStateTransition(
                    f"cannot attach {handle.kind.value} to a {session.state.value} session"
                )
            session.backends[handle.kind] = handle.model_copy(deep=True)
            session.updated_at = datetime.now(UTC)
            return session.model_copy(deep=True)

    def detach_backend(self, session_id: str, kind: BackendKind) -> Session:
        with self._lock:
            session = self._require(session_id)
            session.backends.pop(kind, None)
            session.updated_at = datetime.now(UTC)
            return session.model_copy(deep=True)

    def update_metadata(self, session_id: str, values: dict[str, object]) -> Session:
        with self._lock:
            session = self._require(session_id)
            session.metadata.update(values)
            session.updated_at = datetime.now(UTC)
            return session.model_copy(deep=True)

    def remove_closed(self, session_id: str) -> None:
        with self._lock:
            session = self._require(session_id)
            if session.state != SessionState.CLOSED:
                raise InvalidStateTransition("only closed sessions can be removed")
            del self._sessions[session_id]
            if session_id in self._closed_order:
                self._closed_order.remove(session_id)

    def _require(self, session_id: str) -> Session:
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFound(f"session not found: {session_id}")
        return session


def file_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


_APK_SUFFIXES = frozenset({".apk", ".aab", ".apks", ".xapk"})
_WEB_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".wasm", ".html", ".htm", ".har"})
_APK_MANIFEST = "AndroidManifest.xml"
# Enough for every magic number below without pulling a large header into memory.
_MAGIC_BYTES = 8


def is_http_url(reference: str) -> bool:
    return reference.lower().startswith(("http://", "https://"))


def classify_target(reference: str | Path) -> TargetKind:
    """Infer the target kind so existing callers keep their one-argument create.

    Extension first because it is the caller's stated intent, then magic bytes
    for files named without one. Anything unrecognised stays PE, which keeps the
    original "not a PE file" error rather than inventing a vaguer one.
    """

    text = str(reference).strip()
    if is_http_url(text):
        return TargetKind.WEB
    path = Path(text).expanduser()
    suffix = path.suffix.lower()
    if suffix in _APK_SUFFIXES:
        return TargetKind.APK
    if suffix in _WEB_SUFFIXES:
        return TargetKind.WEB
    try:
        with path.open("rb") as stream:
            magic = stream.read(_MAGIC_BYTES)
    except OSError:
        return TargetKind.PE
    if magic.startswith(b"MZ"):
        return TargetKind.PE
    if magic.startswith(b"\x00asm"):
        return TargetKind.WEB
    if magic.startswith(b"PK\x03\x04") and _is_android_package(path):
        return TargetKind.APK
    return TargetKind.PE


def _is_android_package(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            return _APK_MANIFEST in archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


def describe_apk(path: Path) -> dict[str, Any]:
    """Read cheap identity facts from the package without a decompiler.

    Deliberately stdlib-only: session creation must not depend on androguard
    being installed, otherwise the whole Android surface becomes unavailable
    instead of degrading to "opened, but cannot decompile".
    """

    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"not a readable Android package: {path}") from exc
    if _APK_MANIFEST not in names:
        raise ValueError(f"archive has no {_APK_MANIFEST}: {path}")
    abis = sorted(
        {
            parts[1]
            for name in names
            if name.startswith("lib/") and len(parts := name.split("/")) >= 3 and parts[1]
        }
    )
    return {
        "apk": {
            "native_abis": abis,
            "dex_count": sum(1 for name in names if name.endswith(".dex")),
            "entry_count": len(names),
            "signed_v1": any(
                name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC"))
                for name in names
            ),
        }
    }


def detect_pe_architecture(path: Path) -> Architecture:
    with path.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            raise ValueError(f"not a PE file: {path}")
        pe_offset = int.from_bytes(dos[0x3C:0x40], "little")
        stream.seek(pe_offset)
        header = stream.read(6)
    if len(header) != 6 or header[:4] != b"PE\0\0":
        raise ValueError(f"invalid PE header: {path}")
    machine = int.from_bytes(header[4:6], "little")
    if machine == 0x014C:
        return Architecture.X86
    if machine == 0x8664:
        return Architecture.X64
    raise ValueError(f"unsupported PE machine 0x{machine:04x}: {path}")
