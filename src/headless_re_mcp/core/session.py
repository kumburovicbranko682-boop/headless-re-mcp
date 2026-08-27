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
                # A local .wasm gets tool-free identity facts; describe_wasm
                # returns {} for anything else (a .js/.html asset or a bad
                # module), so this stays a no-op except for real modules.
                session = Session(
                    target=kind,
                    binary=path,
                    locator=str(path),
                    sha256=file_sha256(path),
                    metadata=describe_wasm(path),
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
# Enough for every magic number below without pulling a large header into memory.
_MAGIC_BYTES = 8

# APK Signature Scheme v2/v3 live in the APK Signing Block, which sits between
# the last local entry and the central directory -- not as ZIP entries, so the
# v1 (JAR) META-INF check cannot see them. A modern apksigner build is often
# v2/v3-only, which the v1 check reads as unsigned. The block ends, just before
# the central directory, with an 8-byte size, and a 16-byte magic; each scheme
# is one ID-value pair keyed by these IDs (v3.1 rotates v3, so it counts as v3).
_APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_APK_SIG_SCHEME_V2_ID = 0x7109871A
_APK_SIG_SCHEME_V3_ID = 0xF05368C0
_APK_SIG_SCHEME_V3_1_ID = 0x1B93AD61
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_MIN = 22
_ZIP_MAX_COMMENT = 0xFFFF
_ZIP64_SENTINEL = 0xFFFFFFFF
# Real signing blocks are a few kilobytes even with many signers; this only
# refuses a pathological size before allocating for it.
_APK_SIG_BLOCK_MAX = 8 * 1024 * 1024

# AndroidManifest.xml ships as compiled binary XML (AXML), not text, so the
# package name, versions, SDK levels and permissions -- the facts every triage
# starts from -- are otherwise only reachable through androguard. These let
# describe_apk read them stdlib-only, the Android analogue of describe_wasm.
_AXML_RES_XML_TYPE = 0x0003
_AXML_STRING_POOL_TYPE = 0x0001
_AXML_RESOURCE_MAP_TYPE = 0x0180
_AXML_START_ELEMENT_TYPE = 0x0102
_AXML_END_ELEMENT_TYPE = 0x0103
_AXML_STRING_POOL_UTF8 = 1 << 8
_AXML_TYPE_STRING = 0x03
# A compiled manifest is a few kilobytes; getinfo reports the uncompressed size,
# so a zip-bomb member is refused before it is read.
_AXML_MAX_BYTES = 4 * 1024 * 1024
_AXML_MAX_CHUNKS = 100_000
_AXML_MAX_STRINGS = 200_000
_AXML_MAX_ATTRS = 4096
_AXML_MAX_PERMISSIONS = 4096
# aapt2 can drop the android:* attribute names from the string pool and keep
# only their framework resource ids, so resolve the handful we read by id too.
_AXML_ATTR_BY_RES_ID = {
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion",
    0x01010003: "name",
}

# A DEX file opens with a fixed 0x70-byte header whose counts (classes, methods,
# strings) and format version are at known offsets, so how much code an APK
# carries is a stdlib-only fact -- no androguard, no reading the whole member.
_DEX_HEADER_SIZE = 0x70
_DEX_MAGIC = b"dex\n"
_DEX_ENDIAN_TAG = 0x12345678
_DEX_MAX_FILES = 256
# u32 fields; a real DEX stays well under this, so a larger value is a corrupt
# header we refuse rather than sum into a nonsense total.
_DEX_MAX_COUNT = 64_000_000


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
    signed_v2, signed_v3 = _apk_signature_schemes(path)
    return {
        "apk": {
            "native_abis": abis,
            "dex_count": sum(1 for name in names if name.endswith(".dex")),
            "entry_count": len(names),
            "signed_v1": any(
                name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC"))
                for name in names
            ),
            "signed_v2": signed_v2,
            "signed_v3": signed_v3,
            "manifest": _apk_manifest_facts_from_apk(path),
            "dex": _apk_dex_facts(path),
        }
    }


def _apk_dex_facts(path: Path) -> dict[str, Any]:
    """Sum the DEX header counts across every ``*.dex`` in the package, or {}.

    Reads only each member's 0x70-byte header. Fail-closed: an unreadable member
    or an implausible header is skipped, and a package with no readable DEX
    header yields {} rather than raising.
    """
    versions: set[str] = set()
    class_count = method_count = string_count = 0
    found = False
    try:
        with zipfile.ZipFile(path) as archive:
            dex_names = sorted(n for n in archive.namelist() if n.endswith(".dex"))
            for name in dex_names[:_DEX_MAX_FILES]:
                try:
                    with archive.open(name) as handle:
                        header = handle.read(_DEX_HEADER_SIZE)
                except (OSError, zipfile.BadZipFile):
                    continue
                facts = _parse_dex_header(header)
                if facts is None:
                    continue
                found = True
                versions.add(facts["version"])
                string_count += facts["string_count"]
                method_count += facts["method_count"]
                class_count += facts["class_count"]
    except (OSError, zipfile.BadZipFile):
        return {}
    if not found:
        return {}
    return {
        "versions": sorted(versions),
        "class_count": class_count,
        "method_count": method_count,
        "string_count": string_count,
    }


def _parse_dex_header(header: bytes) -> dict[str, Any] | None:
    if len(header) < _DEX_HEADER_SIZE or header[0:4] != _DEX_MAGIC:
        return None
    if int.from_bytes(header[40:44], "little") != _DEX_ENDIAN_TAG:
        return None
    string_count = int.from_bytes(header[56:60], "little")
    method_count = int.from_bytes(header[88:92], "little")
    class_count = int.from_bytes(header[96:100], "little")
    if max(string_count, method_count, class_count) > _DEX_MAX_COUNT:
        return None
    return {
        "version": header[4:7].decode("ascii", errors="replace"),
        "string_count": string_count,
        "method_count": method_count,
        "class_count": class_count,
    }


def _apk_manifest_facts_from_apk(path: Path) -> dict[str, Any]:
    """Read the compiled AndroidManifest and return its identity facts, or {}.

    Fail-closed: a manifest we cannot open, that is implausibly large, or that
    does not parse yields an empty dict rather than raising, so a session still
    opens over a hostile or unusual package.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo(_APK_MANIFEST)
            if info.file_size > _AXML_MAX_BYTES:
                return {}
            with archive.open(_APK_MANIFEST) as handle:
                data = handle.read(_AXML_MAX_BYTES + 1)
    except (OSError, zipfile.BadZipFile, KeyError):
        return {}
    if len(data) > _AXML_MAX_BYTES:
        return {}
    return _apk_manifest_facts(data)


def _apk_signature_schemes(path: Path) -> tuple[bool, bool]:
    """Return ``(signed_v2, signed_v3)`` from the APK Signing Block.

    Fail-closed: any structural surprise (a comment, ZIP64, a truncated or
    oversized block) yields ``(False, False)`` so this cheap identity fact never
    raises on a hostile or unusual archive.
    """
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            tail_len = min(size, _ZIP_EOCD_MIN + _ZIP_MAX_COMMENT)
            handle.seek(size - tail_len)
            tail = handle.read(tail_len)
            eocd = tail.rfind(_ZIP_EOCD_SIGNATURE)
            if eocd < 0 or eocd + _ZIP_EOCD_MIN > len(tail):
                return (False, False)
            comment_len = int.from_bytes(tail[eocd + 20 : eocd + 22], "little")
            if eocd + _ZIP_EOCD_MIN + comment_len != len(tail):
                # The record does not end the file where its comment length
                # says: not the real EOCD (or an archive shape we do not read).
                return (False, False)
            cd_size = int.from_bytes(tail[eocd + 12 : eocd + 16], "little")
            cd_offset = int.from_bytes(tail[eocd + 16 : eocd + 20], "little")
            if _ZIP64_SENTINEL in (cd_size, cd_offset):
                return (False, False)
            if cd_offset < 24 or cd_offset > size:
                return (False, False)
            handle.seek(cd_offset - 16)
            if handle.read(16) != _APK_SIG_BLOCK_MAGIC:
                return (False, False)
            handle.seek(cd_offset - 24)
            block_size = int.from_bytes(handle.read(8), "little")
            if not 24 <= block_size <= _APK_SIG_BLOCK_MAX:
                return (False, False)
            block_start = cd_offset - 8 - block_size
            if block_start < 0:
                return (False, False)
            handle.seek(block_start)
            block = handle.read(block_size + 8)
    except OSError:
        return (False, False)
    return _apk_signing_block_ids(block)


def _apk_signing_block_ids(block: bytes) -> tuple[bool, bool]:
    """Walk the ID-value pairs of a read APK Signing Block for scheme IDs."""
    signed_v2 = signed_v3 = False
    # block = [uint64 size][pairs...][uint64 size][16-byte magic]; the trailing
    # size + magic are the last 24 bytes and the leading size is the first 8.
    cursor = 8
    end = len(block) - 24
    while cursor + 8 <= end:
        pair_len = int.from_bytes(block[cursor : cursor + 8], "little")
        if pair_len < 4 or cursor + 8 + 4 > len(block):
            break
        scheme_id = int.from_bytes(block[cursor + 8 : cursor + 12], "little")
        if scheme_id == _APK_SIG_SCHEME_V2_ID:
            signed_v2 = True
        elif scheme_id in (_APK_SIG_SCHEME_V3_ID, _APK_SIG_SCHEME_V3_1_ID):
            signed_v3 = True
        cursor += 8 + pair_len
    return (signed_v2, signed_v3)


def _apk_manifest_facts(data: bytes) -> dict[str, Any]:
    """Parse the binary AndroidManifest (AXML) for cheap identity facts.

    Returns ``package``, ``version_code``, ``version_name``, ``min_sdk``,
    ``target_sdk`` and a sorted ``permissions`` list -- whatever the walk could
    read. Fail-closed: any structural surprise returns ``{}`` so this never
    raises on a truncated, obfuscated or hostile manifest.
    """
    try:
        return _walk_axml(data)
    except (ValueError, IndexError, UnicodeDecodeError):
        return {}


def _walk_axml(data: bytes) -> dict[str, Any]:
    if len(data) < 8 or int.from_bytes(data[0:2], "little") != _AXML_RES_XML_TYPE:
        return {}
    total = int.from_bytes(data[4:8], "little")
    limit = min(total, len(data)) if 8 <= total <= len(data) else len(data)
    strings: list[str] = []
    res_map: list[int] = []
    package: str | None = None
    version_code: int | None = None
    version_name: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: list[str] = []
    pos = 8
    chunks = 0
    while pos + 8 <= limit and chunks < _AXML_MAX_CHUNKS:
        chunks += 1
        ctype = int.from_bytes(data[pos + 0 : pos + 2], "little")
        csize = int.from_bytes(data[pos + 4 : pos + 8], "little")
        if csize < 8 or pos + csize > limit:
            break
        chunk = data[pos : pos + csize]
        if ctype == _AXML_STRING_POOL_TYPE:
            strings = _axml_string_pool(chunk)
        elif ctype == _AXML_RESOURCE_MAP_TYPE:
            res_map = _axml_resource_map(chunk)
        elif ctype == _AXML_START_ELEMENT_TYPE:
            name, attrs = _axml_start_element(chunk, strings, res_map)
            if name == "manifest":
                package = _axml_str(attrs, "package") or package
                version_name = _axml_str(attrs, "versionName") or version_name
                version_code = _axml_int(attrs, "versionCode", version_code)
            elif name == "uses-sdk":
                min_sdk = _axml_int(attrs, "minSdkVersion", min_sdk)
                target_sdk = _axml_int(attrs, "targetSdkVersion", target_sdk)
            elif name == "uses-permission" and len(permissions) < _AXML_MAX_PERMISSIONS:
                perm = _axml_str(attrs, "name")
                if perm:
                    permissions.append(perm)
        pos += csize
    return {
        "package": package,
        "version_code": version_code,
        "version_name": version_name,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": sorted(set(permissions)),
    }


def _axml_string_pool(chunk: bytes) -> list[str]:
    """Decode a ResStringPool chunk (UTF-8 or UTF-16) into its string list."""
    if len(chunk) < 28:
        return []
    count = min(int.from_bytes(chunk[8:12], "little"), _AXML_MAX_STRINGS)
    flags = int.from_bytes(chunk[16:20], "little")
    strings_start = int.from_bytes(chunk[20:24], "little")
    is_utf8 = bool(flags & _AXML_STRING_POOL_UTF8)
    out: list[str] = []
    for i in range(count):
        off_pos = 28 + i * 4
        if off_pos + 4 > len(chunk):
            break
        start = strings_start + int.from_bytes(chunk[off_pos : off_pos + 4], "little")
        if not 0 <= start < len(chunk):
            out.append("")
            continue
        out.append(_axml_read_utf8(chunk, start) if is_utf8 else _axml_read_utf16(chunk, start))
    return out


def _axml_read_utf16(chunk: bytes, pos: int) -> str:
    length = int.from_bytes(chunk[pos : pos + 2], "little")
    pos += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | int.from_bytes(chunk[pos : pos + 2], "little")
        pos += 2
    return chunk[pos : min(pos + length * 2, len(chunk))].decode("utf-16-le", errors="replace")


def _axml_read_utf8(chunk: bytes, pos: int) -> str:
    # A UTF-8 pool prefixes each string with its char count then its byte count,
    # each a 1- or 2-byte varint. Only the byte count matters for the slice.
    _, pos = _axml_utf8_len(chunk, pos)
    nbytes, pos = _axml_utf8_len(chunk, pos)
    return chunk[pos : min(pos + nbytes, len(chunk))].decode("utf-8", errors="replace")


def _axml_utf8_len(chunk: bytes, pos: int) -> tuple[int, int]:
    first = chunk[pos]
    pos += 1
    if first & 0x80:
        value = ((first & 0x7F) << 8) | chunk[pos]
        return value, pos + 1
    return first, pos


def _axml_resource_map(chunk: bytes) -> list[int]:
    body = chunk[8:]
    count = min(len(body) // 4, _AXML_MAX_STRINGS)
    return [int.from_bytes(body[i * 4 : i * 4 + 4], "little") for i in range(count)]


def _axml_start_element(
    chunk: bytes, strings: list[str], res_map: list[int]
) -> tuple[str, list[tuple[str, int, Any]]]:
    """Return ``(element_name, [(attr_name, data_type, value), ...])``."""

    def name_of(idx: int) -> str:
        return strings[idx] if 0 <= idx < len(strings) else ""

    element = name_of(int.from_bytes(chunk[20:24], "little"))
    attr_start = int.from_bytes(chunk[24:26], "little")
    attr_size = int.from_bytes(chunk[26:28], "little") or 20
    attr_count = min(int.from_bytes(chunk[28:30], "little"), _AXML_MAX_ATTRS)
    base = 16 + attr_start
    attrs: list[tuple[str, int, Any]] = []
    for i in range(attr_count):
        at = base + i * attr_size
        if at + 20 > len(chunk):
            break
        name_idx = int.from_bytes(chunk[at + 4 : at + 8], "little")
        data_type = chunk[at + 15]
        data = int.from_bytes(chunk[at + 16 : at + 20], "little")
        attr_name = name_of(name_idx)
        if not attr_name and 0 <= name_idx < len(res_map):
            attr_name = _AXML_ATTR_BY_RES_ID.get(res_map[name_idx], "")
        value: Any = name_of(data) if data_type == _AXML_TYPE_STRING else data
        attrs.append((attr_name, data_type, value))
    return element, attrs


def _axml_str(attrs: list[tuple[str, int, Any]], name: str) -> str | None:
    for attr_name, data_type, value in attrs:
        if attr_name == name and data_type == _AXML_TYPE_STRING and isinstance(value, str):
            return value
    return None


def _axml_int(attrs: list[tuple[str, int, Any]], name: str, default: int | None) -> int | None:
    for attr_name, _data_type, value in attrs:
        if attr_name != name:
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.lstrip("-").isdigit():
            return int(value)
    return default


_WASM_MAGIC = b"\x00asm"
_WASM_MAX_PARSE_BYTES = 64 * 1024 * 1024
_WASM_MAX_SECTIONS = 4096
_WASM_MAX_CUSTOM_NAMES = 64
_WASM_SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
}
# Sections whose payload begins with a LEB128 vector count we can surface as a
# cheap "how many of X" fact. start (8) is a single index, data_count (12) is a
# bare count, and custom (0) begins with a name, so those are handled apart.
_WASM_COUNTED_SECTIONS = frozenset({1, 2, 3, 4, 5, 6, 7, 9, 10, 11})
# The import (2) and export (7) sections name what the module needs from the
# host and what it exposes -- the facts a reverser reads first. Bound how many
# we surface so a hostile module cannot make session creation allocate freely.
_WASM_MAX_NAMES = 1024
_WASM_EXTERNAL_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global"}


def _read_leb_u32(data: bytes, pos: int) -> tuple[int, int, bool]:
    """Read an unsigned LEB128 (max 5 bytes) -> (value, next_pos, ok)."""
    result = 0
    shift = 0
    for _ in range(5):
        if pos >= len(data):
            return (0, pos, False)
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return (result & 0xFFFFFFFF, pos, True)
        shift += 7
    return (0, pos, False)


def describe_wasm(path: Path) -> dict[str, Any]:
    """Cheap, stdlib-only WebAssembly identity facts (no wabt).

    The WASM line otherwise has no tool-free floor: every fact comes from wabt's
    wasm2wat / wasm-objdump, so a module on a machine without wabt yields
    nothing at all. This walks the module's own section table -- a well-defined
    binary format -- to report the version, which sections are present, the
    vector counts (types, imports, functions, exports, ...), and the import and
    export names that identify what the module needs and exposes, the same way
    describe_apk does for a package.

    Fail-closed and bounded: a non-WASM or unreadable file returns ``{}``; a
    malformed tail stops the walk and is reported via ``well_formed`` rather
    than raising, so session creation never fails on a bad module.
    """
    try:
        with path.open("rb") as handle:
            data = handle.read(_WASM_MAX_PARSE_BYTES + 1)
    except OSError:
        return {}
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        return {}
    truncated = len(data) > _WASM_MAX_PARSE_BYTES
    version = int.from_bytes(data[4:8], "little")
    section_counts: dict[str, int] = {}
    vector_counts: dict[str, int] = {}
    custom_sections: list[str] = []
    exports: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []
    has_start = False
    well_formed = True
    pos = 8
    walked = 0
    while pos < len(data) and walked < _WASM_MAX_SECTIONS:
        section_id = data[pos]
        pos += 1
        payload_len, pos, ok = _read_leb_u32(data, pos)
        if not ok:
            well_formed = False
            break
        body_start = pos
        body_end = pos + payload_len
        if body_end > len(data):
            well_formed = False
            break
        name = _WASM_SECTION_NAMES.get(section_id, f"unknown_{section_id}")
        section_counts[name] = section_counts.get(name, 0) + 1
        if section_id in _WASM_COUNTED_SECTIONS:
            count, _, counted = _read_leb_u32(data, body_start)
            if counted:
                vector_counts[f"{name}_count"] = count
            if section_id == 7:
                exports = _wasm_exports(data, body_start, body_end)
            elif section_id == 2:
                imports = _wasm_imports(data, body_start, body_end)
        elif section_id == 8:
            has_start = True
        elif section_id == 0:
            name_len, name_pos, named = _read_leb_u32(data, body_start)
            if (
                named
                and name_pos + name_len <= body_end
                and len(custom_sections) < _WASM_MAX_CUSTOM_NAMES
            ):
                custom_sections.append(
                    data[name_pos : name_pos + name_len].decode("utf-8", errors="replace")
                )
        pos = body_end
        walked += 1
    return {
        "wasm": {
            "version": version,
            "section_counts": section_counts,
            "type_count": vector_counts.get("type_count"),
            "import_count": vector_counts.get("import_count"),
            "function_count": vector_counts.get("function_count"),
            "export_count": vector_counts.get("export_count"),
            "global_count": vector_counts.get("global_count"),
            "table_count": vector_counts.get("table_count"),
            "memory_count": vector_counts.get("memory_count"),
            "has_start": has_start,
            "custom_sections": custom_sections,
            "exports": exports,
            "imports": imports,
            "well_formed": well_formed and not truncated,
            "truncated": truncated,
        }
    }


def _read_wasm_name(data: bytes, pos: int) -> tuple[str | None, int]:
    """Read a WASM name (LEB128 length + UTF-8 bytes) -> (name, next_pos)."""
    length, pos, ok = _read_leb_u32(data, pos)
    if not ok or pos + length > len(data):
        return None, pos
    return data[pos : pos + length].decode("utf-8", errors="replace"), pos + length


def _wasm_exports(data: bytes, body_start: int, body_end: int) -> list[dict[str, Any]]:
    """Names and kinds from the export section vector."""
    count, pos, ok = _read_leb_u32(data, body_start)
    if not ok:
        return []
    out: list[dict[str, Any]] = []
    for _ in range(min(count, _WASM_MAX_NAMES)):
        name, pos = _read_wasm_name(data, pos)
        if name is None or pos >= body_end:
            break
        kind = data[pos]
        _, pos, ok = _read_leb_u32(data, pos + 1)  # exported index
        out.append({"name": name, "kind": _WASM_EXTERNAL_KINDS.get(kind, f"kind_{kind}")})
        if not ok or pos > body_end:
            break
    return out


def _wasm_imports(data: bytes, body_start: int, body_end: int) -> list[dict[str, Any]]:
    """(module, name, kind) triples from the import section vector."""
    count, pos, ok = _read_leb_u32(data, body_start)
    if not ok:
        return []
    out: list[dict[str, Any]] = []
    for _ in range(min(count, _WASM_MAX_NAMES)):
        module, pos = _read_wasm_name(data, pos)
        if module is None:
            break
        field, pos = _read_wasm_name(data, pos)
        if field is None or pos >= body_end:
            break
        kind = data[pos]
        pos, ok = _skip_wasm_import_desc(data, pos + 1, kind, body_end)
        out.append(
            {
                "module": module,
                "name": field,
                "kind": _WASM_EXTERNAL_KINDS.get(kind, f"kind_{kind}"),
            }
        )
        if not ok or pos > body_end:
            break
    return out


def _skip_wasm_import_desc(data: bytes, pos: int, kind: int, body_end: int) -> tuple[int, bool]:
    """Advance past one import descriptor so the next import can be read."""
    if kind == 0:  # func: a type index
        _, pos, ok = _read_leb_u32(data, pos)
        return pos, ok
    if kind == 3:  # global: value type + mutability, one byte each
        return pos + 2, pos + 2 <= body_end
    if kind == 1:  # table: element ref type, then limits
        pos += 1
        return _skip_wasm_limits(data, pos, body_end)
    if kind == 2:  # memory: limits
        return _skip_wasm_limits(data, pos, body_end)
    return pos, False


def _skip_wasm_limits(data: bytes, pos: int, body_end: int) -> tuple[int, bool]:
    if pos >= body_end:
        return pos, False
    flag = data[pos]
    _, pos, ok = _read_leb_u32(data, pos + 1)  # minimum
    if ok and flag & 0x01:  # a maximum follows
        _, pos, ok = _read_leb_u32(data, pos)
    return pos, ok


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
