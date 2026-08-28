from __future__ import annotations

import hashlib
import zipfile
from collections import deque
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

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
        {
            SessionState.CREATED,
            SessionState.READY,
            SessionState.SUSPENDED,
            SessionState.FAILED,
        }
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

    @staticmethod
    def for_id(session_id: str) -> SessionNotFound:
        """Name the missing session without echoing an unbounded caller string.

        Real ids are 32 hex characters. Interpolating whatever arrived used to
        put it in the exception, the error message and the details, so a
        200,000 character id produced a 400,229 byte envelope.
        """
        shown = (
            session_id
            if len(session_id) <= 64
            else f"{session_id[:32]}...({len(session_id)} chars)"
        )
        return SessionNotFound(f"session not found: {shown}")


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

    def adopt(self, session: Session) -> Session:
        """Put an already-identified session into this process.

        ``create`` always mints a new id. After a console restart the same id
        must come back from SQLite so agent threads and artifacts stay bound.
        An id already in this registry is left untouched: a live worker must
        not be replaced by a dormant row.
        """
        with self._lock:
            existing = self._sessions.get(session.id)
            if existing is not None:
                return existing.model_copy(deep=True)
            stored = session.model_copy(deep=True)
            self._sessions[session.id] = stored
            if stored.state is SessionState.CLOSED:
                self._closed_order.append(session.id)
            return stored.model_copy(deep=True)

    def get(self, session_id: str) -> Session:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionNotFound.for_id(session_id)
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
            if (
                target in {SessionState.CLOSED, SessionState.FAILED}
                and session_id not in self._closed_order
            ):
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
            raise SessionNotFound.for_id(session_id)
        return session


_HYDRATE_LIMIT = 64
_SKIP_HYDRATE_STATES = frozenset(
    {SessionState.CLOSED, SessionState.FAILED, SessionState.CLOSING}
)


class SessionRecordSource(Protocol):
    def list_unclean_sessions(
        self, *, offset: int = 0, limit: int = 100
    ) -> tuple[list[Any], int]: ...


def hydrate_persisted_sessions(
    registry: SessionRegistry,
    source: SessionRecordSource,
    *,
    limit: int = _HYDRATE_LIMIT,
) -> int:
    """Re-bind unclean SQLite rows into an empty in-memory registry.

    Workers do not come back: restored sessions are ``created`` with
    ``metadata.restored``. The same id is what keeps chat threads, timelines
    and artifacts attached across a console restart.
    """
    window = max(1, min(int(limit), 1000))
    try:
        rows, _total = source.list_unclean_sessions(offset=0, limit=window)
    except Exception:
        return 0
    restored = 0
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        session = session_from_store_row(row)
        if session is None:
            continue
        registry.adopt(session)
        restored += 1
    return restored


def session_from_store_row(row: Mapping[str, Any]) -> Session | None:
    """Build a dormant Session from a sessions.db row, or skip a bad row."""
    session_id = str(row.get("id") or "").strip()
    if not session_id or Path(session_id).name != session_id:
        return None
    stored_state = str(row.get("state") or "").strip().lower()
    try:
        recorded = SessionState(stored_state) if stored_state else SessionState.CREATED
    except ValueError:
        recorded = SessionState.CREATED
    if recorded in _SKIP_HYDRATE_STATES:
        return None
    locator = str(row.get("binary") or "").strip()
    if not locator:
        return None
    kind = classify_target(locator)
    binary: Path | None = None
    missing_file = False
    if kind is TargetKind.WEB and is_http_url(locator):
        pass
    else:
        candidate = Path(locator).expanduser()
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        if resolved.is_file():
            binary = resolved
            locator = str(resolved)
        else:
            missing_file = kind is not TargetKind.WEB
            binary = None
    architecture = _architecture_from_stored(row.get("architecture"))
    sha256 = str(row.get("sha256") or "").strip() or None
    metadata: dict[str, Any] = {"restored": True}
    if missing_file:
        metadata["missing_file"] = True
    return Session(
        id=session_id,
        target=kind,
        binary=binary,
        locator=locator,
        sha256=sha256,
        architecture=architecture,
        state=SessionState.CREATED,
        created_at=_parse_stored_datetime(row.get("created_at")),
        updated_at=_parse_stored_datetime(row.get("updated_at")),
        metadata=metadata,
    )


def _architecture_from_stored(value: object) -> Architecture | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    try:
        return Architecture(text)
    except ValueError:
        return None


def _parse_stored_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value or "").strip()
    if not text:
        return datetime.now(UTC)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def file_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


_APK_SUFFIXES = frozenset({".apk", ".aab", ".apks", ".xapk"})
_WEB_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".wasm", ".html", ".htm", ".har"})
_APK_MANIFEST = "AndroidManifest.xml"
# The ABI directory names Android recognises under lib/. Matching this set
# rather than "any directory under lib/" keeps an assets/ path that happens to
# contain a lib segment from being read as a native ABI.
_ANDROID_ABIS = frozenset(
    {"armeabi", "armeabi-v7a", "arm64-v8a", "x86", "x86_64", "mips", "mips64", "riscv64"}
)
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


def _android_abis(names: Iterable[str]) -> list[str]:
    """Native ABI directories, wherever the format keeps lib/.

    A plain APK stores them at ``lib/<abi>/``; an app bundle at
    ``base/lib/<abi>/`` (and ``<feature>/lib/<abi>/``). Matching a ``lib``
    path segment followed by a known ABI covers both without recursing into
    nested archives.
    """
    abis: set[str] = set()
    for name in names:
        parts = name.split("/")
        for index, segment in enumerate(parts):
            if segment == "lib" and index + 2 < len(parts):
                candidate = parts[index + 1]
                if candidate in _ANDROID_ABIS:
                    abis.add(candidate)
    return sorted(abis)


def _android_container_format(names: set[str], suffix: str) -> str | None:
    """Which Android packaging this archive is, or None if it is not one.

    ``apk`` has the manifest at the root; ``aab`` keeps it under a module's
    ``manifest/`` directory (and carries ``BundleConfig.pb``); ``apks`` and
    ``xapk`` are containers that bundle one or more real APKs.
    """
    if _APK_MANIFEST in names:
        return "apk"
    if "BundleConfig.pb" in names or any(
        name.endswith("/manifest/AndroidManifest.xml") for name in names
    ):
        return "aab"
    if any(name.endswith(".apk") for name in names):
        return "xapk" if suffix == ".xapk" or "manifest.json" in names else "apks"
    return None


def describe_apk(path: Path) -> dict[str, Any]:
    """Read cheap identity facts from the package without a decompiler.

    Deliberately stdlib-only: session creation must not depend on androguard
    being installed, otherwise the whole Android surface becomes unavailable
    instead of degrading to "opened, but cannot decompile".

    Handles the four packagings classify_target accepts, not just plain APK:
    an app bundle (.aab) or a container (.apks/.xapk) still yields a session
    with best-effort identity and a ``format`` marker, instead of failing
    creation with a misleading "no AndroidManifest.xml" -- in those formats the
    manifest simply lives elsewhere, or inside the bundled APKs.
    """

    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"not a readable Android package: {path}") from exc
    name_set = set(names)
    fmt = _android_container_format(name_set, path.suffix.lower())
    if fmt is None:
        raise ValueError(
            f"archive is not an Android package "
            f"(no {_APK_MANIFEST}, app-bundle manifest, or embedded APK): {path}"
        )
    identity: dict[str, Any] = {
        "format": fmt,
        "native_abis": _android_abis(names),
        "dex_count": sum(1 for name in names if name.endswith(".dex")),
        "entry_count": len(names),
        "signed_v1": any(
            name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC"))
            for name in names
        ),
    }
    if fmt in {"apks", "xapk"}:
        # The ABIs and signature of a container live inside the APKs it holds,
        # not in the outer archive, so report how many it carries rather than
        # implying the container itself is native or signed.
        identity["apk_count"] = sum(1 for name in names if name.endswith(".apk"))
    return {"apk": identity}


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
