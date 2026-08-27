from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import zipfile
from collections import deque
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from threading import RLock
from typing import Any, BinaryIO, Protocol
from urllib.parse import urlsplit

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
                # A local asset gets tool-free identity facts by kind: a .wasm
                # its section facts, a .js its size/source-map facts.
                # describe_web_asset returns {} for anything else (a .html page,
                # a bad module), so this stays a no-op except for real assets.
                session = Session(
                    target=kind,
                    binary=path,
                    locator=str(path),
                    sha256=file_sha256(path),
                    metadata=describe_web_asset(path),
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
                metadata = describe_pe_clr(path)
            elif kind is TargetKind.APK:
                metadata = describe_apk(path)
            elif kind is TargetKind.NATIVE:
                metadata = describe_native(path)
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

# Native (non-PE) binaries. ELF (Linux/BSD) starts with 0x7f 'E' 'L' 'F'; Mach-O
# (macOS) thin objects start with one of four byte orders of the MH magic, and a
# universal ("fat") binary starts with 0xCAFEBABE. These are the native inputs
# for radare2, Ghidra and frida, so classifying them lets a session open over
# them instead of failing detect_pe_architecture with "not a PE file".
_MACHO_THIN_MAGICS = {
    b"\xfe\xed\xfa\xce": (32, "big"),
    b"\xce\xfa\xed\xfe": (32, "little"),
    b"\xfe\xed\xfa\xcf": (64, "big"),
    b"\xcf\xfa\xed\xfe": (64, "little"),
}
_MACHO_FAT_MAGIC = b"\xca\xfe\xba\xbe"
# Real universal binaries carry a handful of slices; the cap also disambiguates
# Java .class files (whose 0xCAFEBABE is followed by a version >= 45).
_NATIVE_MAX_FAT_ARCHS = 20
_NATIVE_HEADER_BYTES = 4096
_ELF_MAX_PHNUM = 1024
_ELF_MAX_SHNUM = 4096
_ELF_MAX_DYN = 4096
_ELF_MAX_INTERP = 4096
# DT_NEEDED names the shared libraries the loader must pull in -- the ELF
# analogue of Mach-O's LC_LOAD_DYLIB list -- so a native session reports what it
# depends on, not just its interpreter. The names live in the dynamic string
# table (DT_STRTAB), whose virtual address maps to a file offset through the
# PT_LOAD segments; the count and table size are bounded before either is read.
_PT_LOAD = 1
_PT_DYNAMIC = 2
_PT_INTERP = 3
_PT_NOTE = 4
_SHT_SYMTAB = 2
_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_SONAME = 14
_DT_STRSZ = 10
_DT_BIND_NOW = 24
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6FFFFFFB
_DF_1_PIE = 0x08000000
# The exploit-mitigation ("checksec") facts. NX comes from PT_GNU_STACK's
# permissions; RELRO from PT_GNU_RELRO plus whether the loader is told to bind
# eagerly (DT_BIND_NOW, or DF_BIND_NOW/DF_1_NOW), which upgrades partial RELRO
# to full. radare2's `iI` reports the same nx/relro, so the native gate can
# cross-check the stdlib reading against real analysis.
_PT_GNU_RELRO = 0x6474E552
_PT_GNU_STACK = 0x6474E551
_PF_X = 0x1
_DF_BIND_NOW = 0x08
_DF_1_NOW = 0x01
# Stack-protector ("canary") detection: the guard symbols a -fstack-protector
# build references. They live in the dynamic string table, so their presence
# there is the same signal checksec greps for and radare2's `iI` canary reports.
_ELF_CANARY_SYMBOLS = (b"__stack_chk_fail", b"__stack_chk_guard")
_ELF_MAX_NEEDED = 512
_ELF_MAX_STRTAB = 4 * 1024 * 1024
# The GNU build-id (a PT_NOTE record) uniquely identifies a build and is how a
# stripped binary is matched to its debug symbols, so a native session surfaces
# it the way it surfaces the interpreter. DT_SONAME is the provider-side pair to
# DT_NEEDED: the name a shared object declares for itself, present only on a
# library, so it also separates a real .so from a PIE executable (both ET_DYN).
_NT_GNU_BUILD_ID = 3
_ELF_MAX_NOTE_BYTES = 64 * 1024
_ELF_MAX_NOTES = 256
_ELF_BUILD_ID_MAX = 64
_ELF_TYPES = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}
_ELF_MACHINES = {
    2: "sparc",
    3: "x86",
    8: "mips",
    20: "ppc",
    21: "ppc64",
    22: "s390",
    40: "arm",
    62: "x86-64",
    183: "arm64",
    243: "riscv",
}
_MACHO_CPU = {
    7: "x86",
    12: "arm",
    18: "ppc",
    0x01000007: "x86-64",
    0x0100000C: "arm64",
    0x01000012: "ppc64",
}
_MH_PIE = 0x00200000
_MH_DYLDLINK = 0x00000004
# When set, the kernel maps the stack executable -- the inverse of ELF's
# PT_GNU_STACK PF_X bit, so nx is simply this flag's absence.
_MH_ALLOW_STACK_EXECUTION = 0x00020000
_LC_DYLIB_CMDS = frozenset({0x0C, 0x80000018, 0x8000001F})  # LOAD_DYLIB, weak, reexport
_LC_SYMTAB = 0x02  # names the symbol/string tables -- where stack_chk imports live
# FairPlay DRM (App Store) encryption: cryptid != 0 means __TEXT is still
# encrypted on disk and static analysis reads ciphertext -- the first question
# an iOS reverser asks of a binary.
_LC_ENCRYPTION_INFO = 0x21
_LC_ENCRYPTION_INFO_64 = 0x2C
_LC_LOAD_DYLINKER = 0x0E  # names the dynamic linker -- the Mach-O PT_INTERP
_LC_ID_DYLIB = 0x0D  # a dylib's own install name -- the Mach-O DT_SONAME
_LC_UUID = 0x1B  # the build's unique id -- the Mach-O GNU build-id
_LC_MAIN = 0x80000028  # entry point as a file offset of main() -- the Mach-O e_entry
_LC_SEGMENT = 0x01
_LC_SEGMENT_64 = 0x19
_MACHO_MAX_LOAD_CMDS = 4096
_MACHO_MAX_DYLIBS = 64
# The header window read for identity facts is small, but a real image's load
# commands can run past it, so the command region is read in full from the file
# (bounded) rather than truncated at the window, the way the ELF reader seeks.
_MACHO_MAX_CMDS_BYTES = 2 * 1024 * 1024
_MACHO_FILETYPES = {
    1: "object",
    2: "execute",
    3: "fvmlib",
    4: "core",
    5: "preload",
    6: "dylib",
    7: "dylinker",
    8: "bundle",
    9: "dsym",
    10: "kext_bundle",
}

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
    # The security-posture flags on <application>: whether the build ships
    # debuggable (a critical release finding) and whether it is test-only. The
    # ids are the framework resource ids aapt2 uses (frameworks/base
    # tools/aapt2/dump/DumpManifest.cpp), so they resolve even when aapt2 drops
    # the android:* name strings and leaves only the resource map -- the mobile
    # analogue of the native checksec facts.
    0x0101000F: "debuggable",
    0x01010272: "testOnly",
}
# The intent-filter markers that make an <activity> the app's launcher -- its
# entry point, the Android analogue of an ELF's e_entry or a .NET entry token.
# An activity is launchable when one intent-filter carries both.
_ANDROID_ACTION_MAIN = "android.intent.action.MAIN"
_ANDROID_CATEGORY_LAUNCHER = "android.intent.category.LAUNCHER"

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
# The header counts are read from just 0x70 bytes, but the *names* of defined
# classes live in the string/type/class-def tables, so surfacing them means
# reading the member. The whole APK is already hashed at session creation, so
# this only bounds a single member (skip names for anything larger), the
# per-member class walk, and the package-wide sample the facts carry.
_DEX_MAX_BYTES = 32 * 1024 * 1024
_DEX_MAX_NAMES = 8192
_DEX_MAX_TOTAL_NAMES = 512

# An .aab bundle, an .apks (bundletool) or an .xapk (APKPure) all carry the .apk
# family suffixes classify_target routes to describe_apk, but none has a compiled
# AndroidManifest.xml at the archive root: a bundle nests it under
# ``<module>/manifest/`` as protobuf, and a set is a ZIP of whole APKs. Rather
# than fail session creation on a legitimate artifact, recognise these shapes and
# return their structure, recursing into a set's base APK for the real manifest.
_AAB_BUNDLE_CONFIG = "BundleConfig.pb"
_AAB_BASE_MANIFEST = "base/manifest/AndroidManifest.xml"
_AAB_MODULE_MANIFEST_SUFFIX = "/manifest/AndroidManifest.xml"
_APK_SET_MAX_LIST = 256
# A set's base APK is read whole into memory to reach its manifest, so refuse an
# implausibly large member rather than allocate for it.
_APK_INNER_MAX = 128 * 1024 * 1024
# Config/density/ABI splits carry only a slice of resources or native libs, never
# the app manifest, so they are excluded when picking the base APK to recurse
# into. bundletool names them ``base-xxhdpi.apk``; APKPure names them
# ``config.arm64_v8a.apk``. Matched on the basename so the ``splits/`` directory
# every bundletool member sits under does not itself read as a split.
_APK_CONFIG_SPLIT_TOKENS = (
    "ldpi",
    "mdpi",
    "hdpi",
    "tvdpi",
    "arm64_v8a",
    "armeabi_v7a",
    "armeabi",
    "x86_64",
    "x86",
    "mips64",
    "mips",
)


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
    if magic.startswith(b"\x7fELF") or magic[:4] in _MACHO_THIN_MAGICS:
        return TargetKind.NATIVE
    if magic.startswith(_MACHO_FAT_MAGIC) and _is_macho_fat(path):
        return TargetKind.NATIVE
    return TargetKind.PE


def _is_android_package(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            return _APK_MANIFEST in archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


def _is_macho_fat(path: Path) -> bool:
    """Validate a 0xCAFEBABE header as a Mach-O universal binary.

    A Java ``.class`` file shares the 0xCAFEBABE magic, so a magic match alone is
    not enough: require a plausible slice count and a first slice whose cputype
    is a known Mach-O CPU. Java's version and constant-pool bytes fail both.
    """
    try:
        with path.open("rb") as stream:
            head = stream.read(12)
    except OSError:
        return False
    if len(head) < 12 or head[:4] != _MACHO_FAT_MAGIC:
        return False
    slices = int.from_bytes(head[4:8], "big")
    if not 1 <= slices <= _NATIVE_MAX_FAT_ARCHS:
        return False
    return int.from_bytes(head[8:12], "big") in _MACHO_CPU


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
        bundle = _apk_bundle_facts(path, names)
        if bundle is not None:
            return {"apk": bundle}
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
            "format": "apk",
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


def _apk_bundle_facts(path: Path, names: list[str]) -> dict[str, Any] | None:
    """Identity facts for an archive with no root manifest, or None.

    Distinguishes the two legitimate no-root-manifest shapes classify_target
    routes here so session creation does not fail on them:

    * an APK set (``.apks`` from bundletool, ``.xapk`` from APKPure) is a ZIP of
      whole APKs -- reported as ``format="apk_set"`` with its base APK's manifest
      read by recursing into that member;
    * an app bundle (``.aab``) nests each module's manifest under
      ``<module>/manifest/`` -- reported as ``format="aab"`` with the module
      list. The bundle manifest is protobuf, not AXML, so it is not parsed here.

    Returns None for anything that is neither, so describe_apk still raises on a
    ZIP that is genuinely not an Android package.
    """
    apk_entries = sorted(n for n in names if n.lower().endswith(".apk"))
    if apk_entries:
        facts: dict[str, Any] = {
            "format": "apk_set",
            "apk_count": len(apk_entries),
            "apks": apk_entries[:_APK_SET_MAX_LIST],
        }
        base = _apk_set_base(path, apk_entries)
        if base is not None:
            facts["base_apk"] = base
            manifest = _apk_manifest_facts_from_inner(path, base)
            if manifest:
                facts["manifest"] = manifest
        return facts
    if _AAB_BUNDLE_CONFIG in names or _AAB_BASE_MANIFEST in names:
        modules = sorted(
            {
                name.split("/", 1)[0]
                for name in names
                if name.endswith(_AAB_MODULE_MANIFEST_SUFFIX) and "/" in name
            }
        )
        return {"format": "aab", "modules": modules}
    return None


def _apk_is_config_split(basename: str) -> bool:
    """True for a config/density/ABI split member, which holds no app manifest."""
    stem = basename[:-4] if basename.endswith(".apk") else basename
    if stem.startswith("config") or stem.startswith("split_config"):
        return True
    return any(token in stem for token in _APK_CONFIG_SPLIT_TOKENS)


def _apk_set_base(path: Path, apk_entries: list[str]) -> str | None:
    """Pick the base APK of a set: the non-split, ``base``-named, largest member.

    Config/density/ABI splits carry no manifest, so they lose to any other
    member; a ``base``-named member then wins and size breaks ties, since the
    base APK holding the dex and resources is reliably the largest. Fail-closed:
    an unreadable archive yields None and the set is reported without a manifest.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            sizes: dict[str, int] = {}
            for name in apk_entries:
                try:
                    sizes[name] = archive.getinfo(name).file_size
                except KeyError:
                    continue
    except (OSError, zipfile.BadZipFile):
        return None
    if not sizes:
        return None

    def rank(name: str) -> tuple[bool, bool, int]:
        base = name.rsplit("/", 1)[-1].lower()
        config = _apk_is_config_split(base)
        named_base = "base" in base and not config
        return (not config, named_base, sizes[name])

    return max(sizes, key=rank)


def _apk_manifest_facts_from_inner(path: Path, inner_name: str) -> dict[str, Any]:
    """Read the compiled manifest of an APK nested inside a set, or {}.

    A set member is a whole APK, so reaching its manifest means opening a ZIP
    within the ZIP. Fail-closed and bounded: an implausibly large member, or one
    we cannot open, yields {} rather than raising or reading unbounded bytes.
    """
    try:
        with zipfile.ZipFile(path) as outer:
            if outer.getinfo(inner_name).file_size > _APK_INNER_MAX:
                return {}
            blob = outer.read(inner_name)
        with zipfile.ZipFile(io.BytesIO(blob)) as inner:
            if inner.getinfo(_APK_MANIFEST).file_size > _AXML_MAX_BYTES:
                return {}
            with inner.open(_APK_MANIFEST) as handle:
                data = handle.read(_AXML_MAX_BYTES + 1)
    except (OSError, zipfile.BadZipFile, KeyError):
        return {}
    if len(data) > _AXML_MAX_BYTES:
        return {}
    return _apk_manifest_facts(data)


def _apk_dex_facts(path: Path) -> dict[str, Any]:
    """DEX header counts across every ``*.dex``, plus a sample of class names.

    The counts come from each member's 0x70-byte header; the defined-class names
    need the member's tables, so a member up to 32 MiB is read in full for them
    and larger ones contribute counts only. Fail-closed: an unreadable member or
    an implausible header is skipped, and a package with no readable DEX header
    yields {} rather than raising.
    """
    versions: set[str] = set()
    class_count = method_count = string_count = 0
    class_names: set[str] = set()
    signatures: list[dict[str, str]] = []
    found = False
    try:
        with zipfile.ZipFile(path) as archive:
            dex_names = sorted(n for n in archive.namelist() if n.endswith(".dex"))
            for name in dex_names[:_DEX_MAX_FILES]:
                try:
                    info = archive.getinfo(name)
                    read_cap = (
                        _DEX_HEADER_SIZE if info.file_size > _DEX_MAX_BYTES else _DEX_MAX_BYTES
                    )
                    with archive.open(name) as handle:
                        data = handle.read(read_cap)
                except (OSError, zipfile.BadZipFile, KeyError):
                    continue
                facts = _parse_dex_header(data[:_DEX_HEADER_SIZE])
                if facts is None:
                    continue
                found = True
                versions.add(facts["version"])
                string_count += facts["string_count"]
                method_count += facts["method_count"]
                class_count += facts["class_count"]
                # Per-member so a repackaged split can be told apart; each dex
                # carries its own fingerprint even when the counts are summed.
                signatures.append({"dex": name, "sha1": facts["signature"]})
                if len(data) > _DEX_HEADER_SIZE and len(class_names) < _DEX_MAX_TOTAL_NAMES:
                    for cname in _dex_class_names(data, facts):
                        class_names.add(cname)
                        if len(class_names) >= _DEX_MAX_TOTAL_NAMES:
                            break
    except (OSError, zipfile.BadZipFile):
        return {}
    if not found:
        return {}
    return {
        "versions": sorted(versions),
        "class_count": class_count,
        "method_count": method_count,
        "string_count": string_count,
        "classes": sorted(class_names),
        "signatures": signatures,
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
        # The 20-byte SHA-1 over everything past it: the DEX build fingerprint,
        # the Android analogue of an ELF build-id / Mach-O uuid / .NET MVID. Two
        # APKs whose classes.dex share this carry byte-identical code.
        "signature": header[12:32].hex(),
        "string_count": string_count,
        "string_ids_off": int.from_bytes(header[60:64], "little"),
        "type_count": int.from_bytes(header[64:68], "little"),
        "type_ids_off": int.from_bytes(header[68:72], "little"),
        "method_count": method_count,
        "class_count": class_count,
        "class_defs_off": int.from_bytes(header[100:104], "little"),
    }


def _dex_class_names(data: bytes, header: dict[str, Any]) -> list[str]:
    """Resolve the defined classes' names from the DEX id tables.

    Each class_def's first u32 is a type index; that type's descriptor index
    points into the string table, whose entry is a MUTF-8 string. Every lookup
    is bounds-checked, so a corrupt index is skipped rather than raising.
    """
    string_ids_off = header["string_ids_off"]
    string_ids_size = header["string_count"]
    type_ids_off = header["type_ids_off"]
    type_ids_size = header["type_count"]
    class_defs_off = header["class_defs_off"]
    class_defs_size = header["class_count"]
    names: list[str] = []
    for i in range(min(class_defs_size, _DEX_MAX_NAMES)):
        cd = class_defs_off + i * 32
        if cd + 4 > len(data):
            break
        type_idx = int.from_bytes(data[cd : cd + 4], "little")
        if type_idx >= type_ids_size:
            continue
        t = type_ids_off + type_idx * 4
        if t + 4 > len(data):
            continue
        desc_idx = int.from_bytes(data[t : t + 4], "little")
        if desc_idx >= string_ids_size:
            continue
        s = string_ids_off + desc_idx * 4
        if s + 4 > len(data):
            continue
        descriptor = _dex_read_mutf8(data, int.from_bytes(data[s : s + 4], "little"))
        if descriptor:
            names.append(_dex_descriptor_to_name(descriptor))
    return names


def _dex_read_mutf8(data: bytes, offset: int) -> str | None:
    """Read a DEX string: a uleb128 length prefix then MUTF-8 bytes to a NUL."""
    if not 0 <= offset < len(data):
        return None
    _, pos, ok = _read_leb_u32(data, offset)  # utf-16 unit count; the NUL bounds the bytes
    if not ok:
        return None
    end = data.find(b"\x00", pos)
    if end < 0:
        end = len(data)
    return data[pos:end].decode("utf-8", errors="replace")


def _dex_descriptor_to_name(descriptor: str) -> str:
    """``Lcom/example/Foo;`` -> ``com.example.Foo``; other shapes pass through."""
    if len(descriptor) >= 3 and descriptor[0] == "L" and descriptor[-1] == ";":
        return descriptor[1:-1].replace("/", ".")
    return descriptor


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
    debuggable: bool | None = None
    test_only: bool | None = None
    # Launcher (entry-point) detection is a small state machine over the flat
    # element walk: remember the current <activity>'s name, and whether the
    # intent-filter currently open has declared both MAIN and LAUNCHER. Both in
    # one filter marks that activity launchable -- MAIN in one filter and
    # LAUNCHER in another does not, so the pair resets on each intent-filter.
    launcher_activity: str | None = None
    current_activity: str | None = None
    filter_main = False
    filter_launcher = False
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
            elif name == "application":
                if debuggable is None:
                    debuggable = _axml_bool(attrs, "debuggable")
                if test_only is None:
                    test_only = _axml_bool(attrs, "testOnly")
            elif name in ("activity", "activity-alias"):
                # A new activity subtree: its own android:name is the launchable
                # component (for an alias too -- that is what gets launched).
                current_activity = _axml_str(attrs, "name")
                filter_main = filter_launcher = False
            elif name == "intent-filter":
                filter_main = filter_launcher = False
            elif name == "action":
                if _axml_str(attrs, "name") == _ANDROID_ACTION_MAIN:
                    filter_main = True
            elif name == "category":
                if _axml_str(attrs, "name") == _ANDROID_CATEGORY_LAUNCHER:
                    filter_launcher = True
            if launcher_activity is None and current_activity and filter_main and filter_launcher:
                launcher_activity = current_activity
        pos += csize
    facts: dict[str, Any] = {
        "package": package,
        "version_code": version_code,
        "version_name": version_name,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": sorted(set(permissions)),
        # The launchable activity (entry point), reported as declared in the
        # manifest -- None for a library/service-only APK with no launcher.
        "launcher_activity": launcher_activity,
    }
    # Security-posture flags are reported only when the manifest declares them:
    # their framework defaults are version-dependent, so an explicit value is a
    # fact while absence is not something to guess at.
    if debuggable is not None:
        facts["debuggable"] = debuggable
    if test_only is not None:
        facts["test_only"] = test_only
    return facts


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


def _axml_bool(attrs: list[tuple[str, int, Any]], name: str) -> bool | None:
    """A manifest boolean attribute, or None when it is not declared.

    aapt encodes ``android:debuggable="true"`` as TYPE_INT_BOOLEAN whose data is
    0xFFFFFFFF (true) or 0 (false), so any non-zero int reads True; a manifest
    that was recompiled from text may carry the literal string instead, which is
    accepted too. Absence returns None so the caller omits the fact rather than
    inventing a default.
    """
    for attr_name, _data_type, value in attrs:
        if attr_name != name:
            continue
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            low = value.strip().lower()
            if low in {"true", "1"}:
                return True
            if low in {"false", "0", ""}:
                return False
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
# The "producers" custom section (a tool-conventions standard) records which
# language and toolchain built the module. A real section carries a handful of
# fields (language / processed-by / sdk) with a few entries each, so small caps
# bound a hostile section without losing anything from an honest one.
_WASM_MAX_PRODUCER_FIELDS = 8
_WASM_MAX_PRODUCER_VALUES = 8
_WASM_MAX_PRODUCER_CHARS = 256
# The "name" custom section (core spec appendix) is WASM's debug-symbol store:
# subsection 0 names the module, subsection 1 maps function indices to source
# names. Its presence is the stripped/unstripped distinction for a module.
_WASM_NAME_SUBSEC_MODULE = 0
_WASM_NAME_SUBSEC_FUNCTIONS = 1


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
    vector counts (types, imports, functions, exports, ...), the import and
    export names that identify what the module needs and exposes, and the
    debug names (module / function) an unstripped build carries, the same way
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
    producers: dict[str, list[str]] | None = None
    name_facts: dict[str, Any] = {}
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
            if named and name_pos + name_len <= body_end:
                cname = data[name_pos : name_pos + name_len].decode("utf-8", errors="replace")
                if len(custom_sections) < _WASM_MAX_CUSTOM_NAMES:
                    custom_sections.append(cname)
                # "producers" names the toolchain that built the module -- the
                # WASM analogue of an ELF .comment: rustc/wasm-bindgen,
                # Emscripten/clang and friends all emit it.
                if cname == "producers" and producers is None:
                    producers = _wasm_producers(data, name_pos + name_len, body_end)
                # "name" is the debug-symbol store: the module's own name and
                # the function-index -> source-name map an unstripped build
                # carries. Its absence is what "stripped" means for WASM.
                elif cname == "name" and not name_facts:
                    name_facts = _wasm_name_section(data, name_pos + name_len, body_end)
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
            "producers": producers,
            "module_name": name_facts.get("module_name"),
            "function_name_count": name_facts.get("function_name_count"),
            "function_names": name_facts.get("function_names", []),
            "exports": exports,
            "imports": imports,
            "well_formed": well_formed and not truncated,
            "truncated": truncated,
        }
    }


_JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs"})
_JS_MAX_BYTES = 16 * 1024 * 1024
# Tools take the *last* sourceMappingURL directive; it appears as ``//# `` (or
# the legacy ``//@ ``) for scripts and ``/*# ... */`` for blocks, so key off the
# ``#``/``@`` and stop the value at the first whitespace (URLs carry none).
_JS_SOURCEMAP_RE = re.compile(rb"[#@]\s*sourceMappingURL=(\S+)")
# An external map reference is short; cap it so a pathological line cannot make
# the identity facts large, and never store an inline (data:) map's payload.
_JS_SOURCEMAP_MAX = 2048


def describe_web_asset(path: Path) -> dict[str, Any]:
    """Tool-free identity facts for a local web asset, dispatched by kind.

    A ``.wasm`` module gets its section facts; a ``.js``/``.mjs``/``.cjs`` script
    gets its size and source-map facts; a ``.har`` capture gets its traffic
    shape; a ``.html``/``.htm`` page gets its script and resource shape.
    Anything else has no tool-free reader yet and returns ``{}``.
    """
    suffix = path.suffix.lower()
    if suffix in _JS_SUFFIXES:
        return describe_js(path)
    if suffix == ".har":
        return describe_har(path)
    if suffix in _HTML_SUFFIXES:
        return describe_html(path)
    return describe_wasm(path)


def describe_js(path: Path) -> dict[str, Any]:
    """Cheap, stdlib-only JavaScript identity facts (no webcrack).

    The JS line otherwise has no tool-free floor: every fact comes from webcrack
    (deobfuscate / unpack), so a script on a machine without it yields nothing.
    These are the facts a reverser reads first and that need no tool: the size,
    the line shape (a single 400 KB line is the signature of a minified bundle),
    and -- most usefully -- whether a ``sourceMappingURL`` points at the original
    sources, inline or external.

    Fail-closed and bounded: an unreadable file returns ``{}`` and only the first
    16 MiB is scanned, so session creation never stalls or raises on a script.
    """
    if path.suffix.lower() not in _JS_SUFFIXES:
        return {}
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            data = handle.read(_JS_MAX_BYTES)
    except OSError:
        return {}
    truncated = size > _JS_MAX_BYTES
    line_count = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    max_line_length = max((len(line) for line in data.split(b"\n")), default=0)
    source_map: str | None = None
    source_map_inline = False
    last = None
    for match in _JS_SOURCEMAP_RE.finditer(data):
        last = match
    if last is not None:
        url = last.group(1).decode("utf-8", errors="replace")
        if url.startswith("data:"):
            source_map_inline = True
        else:
            source_map = url[:_JS_SOURCEMAP_MAX]
    return {
        "js": {
            "size": size,
            "line_count": line_count,
            "max_line_length": max_line_length,
            "source_map": source_map,
            "source_map_inline": source_map_inline,
            "truncated": truncated,
        }
    }


_HAR_MAX_BYTES = 64 * 1024 * 1024
_HAR_MAX_ENTRIES = 200_000
# Distinct hosts are a strong "what did this capture touch" fact; list a bounded
# sample and always report the true count alongside it.
_HAR_MAX_HOSTS = 64


def describe_har(path: Path) -> dict[str, Any]:
    """Cheap, stdlib-only facts about an HTTP Archive (HAR) capture (no mitmproxy).

    A ``.har`` is the JSON transcript a proxy or browser writes, and reading its
    shape -- how many requests, which methods and hosts, the status mix, whether
    it carried WebSocket traffic, and which tool recorded it -- is the first pass
    over a captured session. It is plain JSON, so this needs no proxy running.

    Fail-closed and bounded: a file over 64 MiB, one that is not valid HAR JSON,
    or a malformed entry is skipped rather than raising, so a session opens over
    any ``.har`` a user points at.
    """
    if path.suffix.lower() != ".har":
        return {}
    try:
        size = path.stat().st_size
        if size > _HAR_MAX_BYTES:
            return {}
        with path.open("rb") as handle:
            raw = handle.read(_HAR_MAX_BYTES + 1)
    except OSError:
        return {}
    if len(raw) > _HAR_MAX_BYTES:
        return {}
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return {}
    log = doc.get("log") if isinstance(doc, dict) else None
    if not isinstance(log, dict):
        return {}
    entries = log.get("entries")
    if not isinstance(entries, list):
        return {}

    creator = None
    if isinstance(log.get("creator"), dict):
        name = log["creator"].get("name")
        creator = name if isinstance(name, str) else None
    pages = log.get("pages")
    page_count = len(pages) if isinstance(pages, list) else 0

    methods: dict[str, int] = {}
    hosts: set[str] = set()
    status_classes: dict[str, int] = {}
    has_websocket = False
    total_response_bytes = 0
    truncated = len(entries) > _HAR_MAX_ENTRIES
    for entry in entries[:_HAR_MAX_ENTRIES]:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        if isinstance(request, dict):
            method = request.get("method")
            if isinstance(method, str) and method:
                methods[method.upper()] = methods.get(method.upper(), 0) + 1
            url = request.get("url")
            if isinstance(url, str):
                host = urlsplit(url).hostname
                if host:
                    hosts.add(host)
        response = entry.get("response")
        if isinstance(response, dict):
            status = response.get("status")
            if isinstance(status, int) and 100 <= status <= 599:
                status_classes[f"{status // 100}xx"] = (
                    status_classes.get(f"{status // 100}xx", 0) + 1
                )
            content = response.get("content")
            if isinstance(content, dict) and isinstance(content.get("size"), int):
                total_response_bytes += max(content["size"], 0)
        ws = entry.get("_webSocketMessages")
        if isinstance(ws, list) and ws:
            has_websocket = True
    return {
        "har": {
            "entry_count": len(entries),
            "page_count": page_count,
            "creator": creator,
            "methods": dict(sorted(methods.items())),
            "host_count": len(hosts),
            "hosts": sorted(hosts)[:_HAR_MAX_HOSTS],
            "status_classes": dict(sorted(status_classes.items())),
            "has_websocket": has_websocket,
            "total_response_bytes": total_response_bytes,
            "truncated": truncated,
        }
    }


_HTML_SUFFIXES = frozenset({".html", ".htm"})
_HTML_MAX_BYTES = 16 * 1024 * 1024
# Cap the recorded script/host lists (and the title) so a page with thousands
# of tags cannot make the identity facts large; the totals are always exact.
_HTML_MAX_ITEMS = 256
_HTML_MAX_TITLE = 256


class _HtmlFactsParser(HTMLParser):
    """Collect a page's script and resource shape in one lenient pass."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.script_total = 0
        self.external_script_total = 0
        self.inline_script_total = 0
        self.stylesheet_total = 0
        self.iframe_total = 0
        self.external_scripts: list[str] = []
        self.hosts: set[str] = set()
        self.title: str | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "script":
            self.script_total += 1
            src = attr.get("src")
            if src:
                self.external_script_total += 1
                if len(self.external_scripts) < _HTML_MAX_ITEMS:
                    self.external_scripts.append(src)
                self._add_host(src)
            else:
                self.inline_script_total += 1
        elif tag == "link":
            if "stylesheet" in (attr.get("rel") or "").lower():
                self.stylesheet_total += 1
                self._add_host(attr.get("href"))
        elif tag == "iframe":
            self.iframe_total += 1
            self._add_host(attr.get("src"))
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and self.title is None:
            text = data.strip()
            if text:
                self.title = text[:_HTML_MAX_TITLE]

    def _add_host(self, url: str | None) -> None:
        if not url or len(self.hosts) >= _HTML_MAX_ITEMS:
            return
        host = urlsplit(url).hostname
        if host:
            self.hosts.add(host)


def describe_html(path: Path) -> dict[str, Any]:
    """Cheap, stdlib-only facts about an HTML page (no browser).

    Where a page loads its code from is the first thing a web reverser maps:
    how many scripts it pulls, how many are external versus inline, which hosts
    those and its stylesheets and iframes reach, and the page title. stdlib
    html.parser reads all of it without launching a browser -- the page-level
    analogue of the script-level facts describe_js gives.

    Fail-closed and bounded: an unreadable file returns ``{}``, only the first
    16 MiB is scanned, and a parser hiccup on a hostile page yields the facts
    gathered so far rather than raising.
    """
    if path.suffix.lower() not in _HTML_SUFFIXES:
        return {}
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            raw = handle.read(_HTML_MAX_BYTES)
    except OSError:
        return {}
    parser = _HtmlFactsParser()
    try:
        parser.feed(raw.decode("utf-8", errors="replace"))
        parser.close()
    except Exception:  # noqa: BLE001 - a hostile page must not break session creation
        pass
    return {
        "html": {
            "title": parser.title,
            "script_count": parser.script_total,
            "external_script_count": parser.external_script_total,
            "inline_script_count": parser.inline_script_total,
            "external_scripts": parser.external_scripts,
            "stylesheet_count": parser.stylesheet_total,
            "iframe_count": parser.iframe_total,
            "external_host_count": len(parser.hosts),
            "external_hosts": sorted(parser.hosts)[:_HTML_MAX_ITEMS],
            "truncated": size > _HTML_MAX_BYTES,
        }
    }


def _read_wasm_name(data: bytes, pos: int) -> tuple[str | None, int]:
    """Read a WASM name (LEB128 length + UTF-8 bytes) -> (name, next_pos)."""
    length, pos, ok = _read_leb_u32(data, pos)
    if not ok or pos + length > len(data):
        return None, pos
    return data[pos : pos + length].decode("utf-8", errors="replace"), pos + length


def _wasm_producers(data: bytes, pos: int, body_end: int) -> dict[str, list[str]]:
    """Field -> ["name version", ...] from a producers custom section.

    The layout (tool-conventions ProducersSection.md) is a vector of fields,
    each a name plus a vector of (name, version) string pairs -- for example
    ``language: [Rust]`` and ``processed-by: [rustc 1.76.0, wasm-bindgen ...]``.
    Bounded and fail-closed like every other reader here: caps on fields,
    values and string length, and a malformed tail keeps what parsed cleanly
    rather than raising.
    """
    count, pos, ok = _read_leb_u32(data, pos)
    if not ok:
        return {}
    out: dict[str, list[str]] = {}
    for _ in range(min(count, _WASM_MAX_PRODUCER_FIELDS)):
        field, pos = _read_wasm_name(data, pos)
        if field is None or pos > body_end:
            break
        value_count, pos, ok = _read_leb_u32(data, pos)
        if not ok:
            break
        values: list[str] = []
        for _ in range(min(value_count, _WASM_MAX_PRODUCER_VALUES)):
            name, pos = _read_wasm_name(data, pos)
            if name is None or pos > body_end:
                break
            version, pos = _read_wasm_name(data, pos)
            if version is None or pos > body_end:
                break
            values.append(f"{name} {version}".strip()[:_WASM_MAX_PRODUCER_CHARS])
        out[field[:_WASM_MAX_PRODUCER_CHARS]] = values
        if len(values) < value_count:
            # Values were cut short (cap or malformed pair), so the stream
            # position no longer sits at the next field; stop rather than
            # misread the remainder as field names.
            break
    return out


def _wasm_name_section(data: bytes, pos: int, body_end: int) -> dict[str, Any]:
    """Module and function names from the "name" custom section.

    The layout (core spec appendix) is a sequence of subsections, each an id
    byte plus a LEB128 size: id 0 carries the module's own name, id 1 a name
    map of (function index, name) pairs -- the debug symbols a reverser wants
    before anything else. Other subsections (locals, and the extended-name
    proposal's types/globals/...) are skipped by size. Bounded and fail-closed
    like the producers reader: a malformed subsection keeps what parsed cleanly.
    """
    out: dict[str, Any] = {}
    while pos < body_end:
        sub_id = data[pos]
        size, pos, ok = _read_leb_u32(data, pos + 1)
        sub_end = pos + size
        if not ok or sub_end > body_end:
            break
        if sub_id == _WASM_NAME_SUBSEC_MODULE and "module_name" not in out:
            name, name_end = _read_wasm_name(data, pos)
            if name is not None and name_end <= sub_end:
                out["module_name"] = name[:_WASM_MAX_PRODUCER_CHARS]
        elif sub_id == _WASM_NAME_SUBSEC_FUNCTIONS and "function_names" not in out:
            count, entry_pos, counted = _read_leb_u32(data, pos)
            if counted:
                # The declared size of the map, like export_count for exports;
                # the list below is the (bounded) sample actually read.
                out["function_name_count"] = count
                names: list[dict[str, Any]] = []
                for _ in range(min(count, _WASM_MAX_NAMES)):
                    index, entry_pos, ok = _read_leb_u32(data, entry_pos)
                    if not ok:
                        break
                    fname, entry_pos = _read_wasm_name(data, entry_pos)
                    if fname is None or entry_pos > sub_end:
                        break
                    names.append(
                        {"index": index, "name": fname[:_WASM_MAX_PRODUCER_CHARS]}
                    )
                out["function_names"] = names
        pos = sub_end
    return out


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


# A .NET assembly is a PE with a COM descriptor data directory (index 14) that
# points at the CLR (COR20) header, whose MetaData directory points at the BSJB
# metadata root. Whether a PE is managed -- and its runtime and metadata version
# -- is the first fork in a Windows-binary triage (native RE vs the dotnet.*
# tools), so surface it stdlib-only. The heavier assembly-name table walk stays
# in dotnet.inspect; this only reads the headers via seeks (no hash, no full
# read), so it never regresses session creation over a large native PE.
_PE_COM_DESCRIPTOR_DIR = 14
_PE_MAX_SECTIONS = 96
_CLR_METADATA_MAGIC = b"BSJB"
_CLR_MAX_VERSION_LEN = 256
_COMIMAGE_FLAGS_ILONLY = 0x00000001
# The rest of the COR20 header Flags field -- the corflags surface. 32BITREQUIRED
# forces a 32-bit process; 32BITPREFERRED is the AnyCPU "prefer 32-bit" hint;
# STRONGNAMESIGNED means the strong-name signature blob is present. Mono's
# pedump decodes the same bits, so the .NET gate can cross-check them.
_COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
_COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008
_COMIMAGE_FLAGS_32BITPREFERRED = 0x00020000


def describe_pe_clr(path: Path) -> dict[str, Any]:
    """Tool-free .NET identity facts for a PE; ``{}`` for a native binary.

    Fail-closed and cheap: reads only the PE/CLR headers by seeking, so a native
    PE returns ``{}`` after a few small reads and a managed one never has its
    whole body read or hashed a second time.
    """
    major = minor = entry_token = flags = None
    metadata_version: str | None = None
    try:
        with path.open("rb") as stream:
            dos = stream.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return {}
            stream.seek(int.from_bytes(dos[0x3C:0x40], "little"))
            coff = stream.read(24)
            if len(coff) < 24 or coff[:4] != b"PE\x00\x00":
                return {}
            num_sections = int.from_bytes(coff[6:8], "little")
            optional = stream.read(int.from_bytes(coff[20:22], "little"))
            magic = int.from_bytes(optional[0:2], "little") if len(optional) >= 2 else 0
            if magic == 0x10B:  # PE32
                dir_count_off = 92
            elif magic == 0x20B:  # PE32+
                dir_count_off = 108
            else:
                return {}
            if dir_count_off + 4 > len(optional):
                return {}
            dir_count = int.from_bytes(optional[dir_count_off : dir_count_off + 4], "little")
            if dir_count <= _PE_COM_DESCRIPTOR_DIR:
                return {}
            entry = dir_count_off + 4 + _PE_COM_DESCRIPTOR_DIR * 8
            if entry + 8 > len(optional):
                return {}
            clr_rva = int.from_bytes(optional[entry : entry + 4], "little")
            if clr_rva == 0:
                return {}  # no CLR directory: a native PE
            sections = _pe_sections(stream.read(min(num_sections, _PE_MAX_SECTIONS) * 40))
            clr_off = _pe_rva_to_offset(sections, clr_rva)
            if clr_off is not None:
                stream.seek(clr_off)
                cor20 = stream.read(24)
                if len(cor20) >= 24:
                    major = int.from_bytes(cor20[4:6], "little")
                    minor = int.from_bytes(cor20[6:8], "little")
                    flags = int.from_bytes(cor20[16:20], "little")
                    entry_token = int.from_bytes(cor20[20:24], "little")
                    metadata_version = _clr_metadata_version(
                        stream, sections, int.from_bytes(cor20[8:12], "little")
                    )
    except OSError:
        return {}
    return {
        "dotnet": {
            "is_dotnet": True,
            "runtime_version": (
                f"{major}.{minor}" if major is not None and minor is not None else None
            ),
            "metadata_version": metadata_version,
            "entry_point_token": entry_token,
            "il_only": bool(flags & _COMIMAGE_FLAGS_ILONLY) if flags is not None else False,
            # The build-posture flags a corflags run would report: whether the
            # image forces a 32-bit process, prefers 32-bit under AnyCPU, and
            # carries a strong-name signature.
            "requires_32bit": (
                bool(flags & _COMIMAGE_FLAGS_32BITREQUIRED) if flags is not None else False
            ),
            "prefers_32bit": (
                bool(flags & _COMIMAGE_FLAGS_32BITPREFERRED) if flags is not None else False
            ),
            "strong_name_signed": (
                bool(flags & _COMIMAGE_FLAGS_STRONGNAMESIGNED) if flags is not None else False
            ),
        }
    }


def _pe_sections(table: bytes) -> list[tuple[int, int, int, int]]:
    """Parse the section table into (virtual_addr, span, raw_ptr, raw_size) rows."""
    rows: list[tuple[int, int, int, int]] = []
    for i in range(len(table) // 40):
        row = table[i * 40 : i * 40 + 40]
        virtual_size = int.from_bytes(row[8:12], "little")
        virtual_addr = int.from_bytes(row[12:16], "little")
        raw_size = int.from_bytes(row[16:20], "little")
        raw_ptr = int.from_bytes(row[20:24], "little")
        rows.append((virtual_addr, max(virtual_size, raw_size), raw_ptr, raw_size))
    return rows


def _pe_rva_to_offset(sections: list[tuple[int, int, int, int]], rva: int) -> int | None:
    for virtual_addr, span, raw_ptr, raw_size in sections:
        if virtual_addr <= rva < virtual_addr + span:
            delta = rva - virtual_addr
            if raw_size == 0 or delta < raw_size:
                return raw_ptr + delta
    return None


def _clr_metadata_version(
    stream: BinaryIO, sections: list[tuple[int, int, int, int]], meta_rva: int
) -> str | None:
    meta_off = _pe_rva_to_offset(sections, meta_rva)
    if meta_off is None:
        return None
    stream.seek(meta_off)
    root = stream.read(16)
    if len(root) < 16 or root[:4] != _CLR_METADATA_MAGIC:
        return None
    version_len = int.from_bytes(root[12:16], "little")
    if not 0 < version_len <= _CLR_MAX_VERSION_LEN:
        return None
    raw = stream.read(version_len)
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def describe_native(path: Path) -> dict[str, Any]:
    """Tool-free identity facts for an ELF or Mach-O binary.

    Parallels describe_pe_clr for the native lines: reads only the leading
    header bytes to report the container format, bitness, byte order, image
    type and CPU, so a radare2/Ghidra/frida session over a Linux or macOS
    binary knows what it is opened before any external tool runs. Fail-closed:
    an unreadable or unrecognised header yields ``{}``.
    """
    try:
        with path.open("rb") as stream:
            head = stream.read(_NATIVE_HEADER_BYTES)
            if head.startswith(b"\x7fELF"):
                return {"native": _elf_facts(head, stream)}
            magic = head[:4]
            if magic in _MACHO_THIN_MAGICS:
                return {"native": _macho_thin_facts(head, magic, stream)}
            if magic == _MACHO_FAT_MAGIC:
                facts = _macho_fat_facts(head)
                return {"native": facts} if facts else {}
    except OSError:
        return {}
    return {}


def _elf_facts(head: bytes, stream: BinaryIO) -> dict[str, Any]:
    facts: dict[str, Any] = {"format": "elf"}
    if len(head) < 20:
        return facts
    bits = {1: 32, 2: 64}.get(head[4])
    facts["bits"] = bits
    order: str | None = {1: "little", 2: "big"}.get(head[5])
    facts["endianness"] = order
    if order is None or bits is None:
        return facts
    e_type = int.from_bytes(head[16:18], order)  # type: ignore[arg-type]
    e_machine = int.from_bytes(head[18:20], order)  # type: ignore[arg-type]
    facts["type"] = _ELF_TYPES.get(e_type, f"type_{e_type}")
    facts["arch"] = _ELF_MACHINES.get(e_machine, f"machine_{e_machine}")
    # e_entry: where execution starts, the first address an analyst navigates
    # to. Zero means "no entry point" per the ELF spec (typical for a shared
    # object), so the fact is omitted rather than reported as 0.
    entry_size = 8 if bits == 64 else 4
    if len(head) >= 0x18 + entry_size:
        e_entry = int.from_bytes(head[0x18 : 0x18 + entry_size], order)  # type: ignore[arg-type]
        if e_entry:
            facts["entry"] = e_entry
    # The triage questions -- dynamically or statically linked, position
    # independent, stripped, which interpreter -- live in the program and
    # section headers. Read them best-effort: any hiccup leaves the base facts
    # above untouched rather than failing the whole read.
    with contextlib.suppress(OSError, ValueError):
        _elf_layout_facts(facts, head, stream, order, bits, e_type)
    return facts


def _elf_layout_facts(
    facts: dict[str, Any], head: bytes, stream: BinaryIO, order: str, bits: int, e_type: int
) -> None:
    if bits == 64:
        phoff = int.from_bytes(head[0x20:0x28], order)  # type: ignore[arg-type]
        phentsize = int.from_bytes(head[0x36:0x38], order)  # type: ignore[arg-type]
        phnum = int.from_bytes(head[0x38:0x3A], order)  # type: ignore[arg-type]
        shoff = int.from_bytes(head[0x28:0x30], order)  # type: ignore[arg-type]
        shentsize = int.from_bytes(head[0x3A:0x3C], order)  # type: ignore[arg-type]
        shnum = int.from_bytes(head[0x3C:0x3E], order)  # type: ignore[arg-type]
    else:
        phoff = int.from_bytes(head[0x1C:0x20], order)  # type: ignore[arg-type]
        phentsize = int.from_bytes(head[0x2A:0x2C], order)  # type: ignore[arg-type]
        phnum = int.from_bytes(head[0x2C:0x2E], order)  # type: ignore[arg-type]
        shoff = int.from_bytes(head[0x20:0x24], order)  # type: ignore[arg-type]
        shentsize = int.from_bytes(head[0x2E:0x30], order)  # type: ignore[arg-type]
        shnum = int.from_bytes(head[0x30:0x32], order)  # type: ignore[arg-type]
    program = _elf_program_headers(stream, order, bits, phoff, phentsize, phnum)
    if program is not None:
        facts["linking"] = "dynamic" if program["has_dynamic"] else "static"
        if program["has_dynamic"]:
            pie = _elf_dynamic_pie(stream, order, bits, program["dyn_off"], program["dyn_sz"])
            needed, soname, canary = _elf_dynamic_names(
                stream, order, bits, program["dyn_off"], program["dyn_sz"], program["loads"]
            )
            if needed is not None:
                facts["needed"] = needed
            if soname is not None:
                facts["soname"] = soname
            if canary is not None:
                facts["canary"] = canary
        else:
            pie = False
        if pie is not None:
            facts["pie"] = pie
        # Exploit-mitigation posture, the same two radare2's `iI` reports. NX is
        # on when a PT_GNU_STACK segment marks the stack non-executable (r2 reads
        # it the same way: no such segment, or an executable one, means off).
        # RELRO is "none" without PT_GNU_RELRO, "partial" with it, and "full"
        # when the dynamic section also forces eager binding.
        facts["nx"] = program["has_gnu_stack"] and not program["gnu_stack_exec"]
        if program["has_gnu_relro"]:
            bind_now = program["has_dynamic"] and _elf_dynamic_bind_now(
                stream, order, bits, program["dyn_off"], program["dyn_sz"]
            )
            facts["relro"] = "full" if bind_now else "partial"
        else:
            facts["relro"] = "none"
        if program["interp"] is not None:
            facts["interpreter"] = program["interp"]
        build_id = _elf_build_id(stream, order, program["notes"])
        if build_id is not None:
            facts["build_id"] = build_id
    stripped = _elf_is_stripped(stream, order, bits, shoff, shentsize, shnum)
    if stripped is not None:
        facts["stripped"] = stripped


def _elf_program_headers(
    stream: BinaryIO, order: str, bits: int, phoff: int, phentsize: int, phnum: int
) -> dict[str, Any] | None:
    if phoff <= 0 or phnum <= 0 or phnum > _ELF_MAX_PHNUM:
        return None
    want = 56 if bits == 64 else 32
    entsize = max(phentsize, want)
    stream.seek(phoff)
    table = stream.read(entsize * phnum)
    has_interp = has_dynamic = False
    has_gnu_stack = gnu_stack_exec = has_gnu_relro = False
    interp: str | None = None
    dyn_off = dyn_sz = 0
    loads: list[tuple[int, int, int]] = []
    notes: list[tuple[int, int]] = []
    for i in range(phnum):
        entry = table[i * entsize : i * entsize + want]
        if len(entry) < want:
            break
        p_type = int.from_bytes(entry[0:4], order)  # type: ignore[arg-type]
        if bits == 64:
            p_flags = int.from_bytes(entry[4:8], order)  # type: ignore[arg-type]
            p_offset = int.from_bytes(entry[8:16], order)  # type: ignore[arg-type]
            p_vaddr = int.from_bytes(entry[16:24], order)  # type: ignore[arg-type]
            p_filesz = int.from_bytes(entry[32:40], order)  # type: ignore[arg-type]
        else:
            p_offset = int.from_bytes(entry[4:8], order)  # type: ignore[arg-type]
            p_vaddr = int.from_bytes(entry[8:12], order)  # type: ignore[arg-type]
            p_filesz = int.from_bytes(entry[16:20], order)  # type: ignore[arg-type]
            p_flags = int.from_bytes(entry[24:28], order)  # type: ignore[arg-type]
        if p_type == _PT_LOAD and p_filesz > 0:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == _PT_DYNAMIC:
            has_dynamic = True
            dyn_off, dyn_sz = p_offset, p_filesz
        elif p_type == _PT_INTERP and 0 < p_filesz <= _ELF_MAX_INTERP and p_offset > 0:
            has_interp = True
            stream.seek(p_offset)
            interp = stream.read(p_filesz).split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        elif p_type == _PT_NOTE and 0 < p_filesz <= _ELF_MAX_NOTE_BYTES and p_offset > 0:
            notes.append((p_offset, p_filesz))
        elif p_type == _PT_GNU_STACK:
            has_gnu_stack = True
            gnu_stack_exec = bool(p_flags & _PF_X)
        elif p_type == _PT_GNU_RELRO:
            has_gnu_relro = True
    return {
        "has_interp": has_interp,
        "has_dynamic": has_dynamic,
        "has_gnu_stack": has_gnu_stack,
        "gnu_stack_exec": gnu_stack_exec,
        "has_gnu_relro": has_gnu_relro,
        "interp": interp,
        "dyn_off": dyn_off,
        "dyn_sz": dyn_sz,
        "loads": loads,
        "notes": notes,
    }


def _elf_dynamic_pie(
    stream: BinaryIO, order: str, bits: int, dyn_off: int, dyn_sz: int
) -> bool | None:
    """True/False from DT_FLAGS_1's DF_1_PIE bit; None if the segment is unreadable.

    This is what separates a position-independent executable from an ordinary
    shared object: both are ET_DYN and both may carry an interpreter, but only
    the PIE marks DF_1_PIE.
    """
    if dyn_off <= 0 or dyn_sz <= 0:
        return None
    entsize = 16 if bits == 64 else 8
    vsize = entsize // 2
    count = min(dyn_sz // entsize, _ELF_MAX_DYN)
    if count <= 0:
        return None
    stream.seek(dyn_off)
    table = stream.read(entsize * count)
    for i in range(count):
        entry = table[i * entsize : (i + 1) * entsize]
        if len(entry) < entsize:
            break
        tag = int.from_bytes(entry[0:vsize], order)  # type: ignore[arg-type]
        val = int.from_bytes(entry[vsize:entsize], order)  # type: ignore[arg-type]
        if tag == _DT_NULL:
            break
        if tag == _DT_FLAGS_1:
            return bool(val & _DF_1_PIE)
    return False


def _elf_dynamic_bind_now(
    stream: BinaryIO, order: str, bits: int, dyn_off: int, dyn_sz: int
) -> bool:
    """True when the dynamic section forces eager binding -- what turns partial
    RELRO into full. Any of three markers says so: a DT_BIND_NOW tag, DF_BIND_NOW
    in DT_FLAGS, or DF_1_NOW in DT_FLAGS_1. Bounded exactly like the PIE reader; a
    section we cannot read falls closed to False (partial), never raising.
    """
    if dyn_off <= 0 or dyn_sz <= 0:
        return False
    entsize = 16 if bits == 64 else 8
    vsize = entsize // 2
    count = min(dyn_sz // entsize, _ELF_MAX_DYN)
    if count <= 0:
        return False
    stream.seek(dyn_off)
    table = stream.read(entsize * count)
    for i in range(count):
        entry = table[i * entsize : (i + 1) * entsize]
        if len(entry) < entsize:
            break
        tag = int.from_bytes(entry[0:vsize], order)  # type: ignore[arg-type]
        val = int.from_bytes(entry[vsize:entsize], order)  # type: ignore[arg-type]
        if tag == _DT_NULL:
            break
        if tag == _DT_BIND_NOW:
            return True
        if tag == _DT_FLAGS and val & _DF_BIND_NOW:
            return True
        if tag == _DT_FLAGS_1 and val & _DF_1_NOW:
            return True
    return False


def _elf_vaddr_to_off(vaddr: int, loads: list[tuple[int, int, int]]) -> int | None:
    """Map a virtual address to its file offset through the PT_LOAD segments."""
    for seg_vaddr, seg_off, seg_filesz in loads:
        if seg_vaddr <= vaddr < seg_vaddr + seg_filesz:
            return seg_off + (vaddr - seg_vaddr)
    return None


def _elf_dynamic_names(
    stream: BinaryIO,
    order: str,
    bits: int,
    dyn_off: int,
    dyn_sz: int,
    loads: list[tuple[int, int, int]],
) -> tuple[list[str] | None, str | None, bool | None]:
    """``(needed, soname, canary)`` from the dynamic table and its string table.

    Walks the dynamic array for the DT_NEEDED string offsets, the DT_SONAME
    offset and the DT_STRTAB address, maps that address to a file offset through
    the PT_LOAD segments, and reads the names out of the dynamic string table.
    ``canary`` is whether that string table names a stack-guard symbol -- the
    same read costs nothing extra and answers the fourth checksec question.
    Bounded at every step: the entry count, the name count and the string-table
    read are all capped, so a corrupt table yields ``(None, None, None)``
    (dynamic but undetermined) rather than a large read; a dynamic image that
    names nothing yields ``([], None, False)``. DT_SONAME is present only on a
    shared object.
    """
    if dyn_off <= 0 or dyn_sz <= 0 or not loads:
        return None, None, None
    entsize = 16 if bits == 64 else 8
    vsize = entsize // 2
    count = min(dyn_sz // entsize, _ELF_MAX_DYN)
    if count <= 0:
        return None, None, None
    stream.seek(dyn_off)
    table = stream.read(entsize * count)
    needed_offsets: list[int] = []
    soname_off: int | None = None
    strtab_va: int | None = None
    strsz: int | None = None
    for i in range(count):
        entry = table[i * entsize : (i + 1) * entsize]
        if len(entry) < entsize:
            break
        tag = int.from_bytes(entry[0:vsize], order)  # type: ignore[arg-type]
        val = int.from_bytes(entry[vsize:entsize], order)  # type: ignore[arg-type]
        if tag == _DT_NULL:
            break
        if tag == _DT_NEEDED:
            if len(needed_offsets) < _ELF_MAX_NEEDED:
                needed_offsets.append(val)
        elif tag == _DT_SONAME:
            soname_off = val
        elif tag == _DT_STRTAB:
            strtab_va = val
        elif tag == _DT_STRSZ:
            strsz = val
    if strtab_va is None:
        return None, None, None
    str_off = _elf_vaddr_to_off(strtab_va, loads)
    if str_off is None:
        return None, None, None
    cap = strsz if strsz is not None and 0 < strsz <= _ELF_MAX_STRTAB else _ELF_MAX_STRTAB
    stream.seek(str_off)
    blob = stream.read(cap)

    def read_name(offset: int) -> str | None:
        if 0 <= offset < len(blob):
            end = blob.find(b"\x00", offset)
            if end == -1:
                end = len(blob)
            return blob[offset:end].decode("utf-8", errors="replace") or None
        return None

    needed = [name for off in needed_offsets if (name := read_name(off))]
    soname = read_name(soname_off) if soname_off is not None else None
    canary = any(sym in blob for sym in _ELF_CANARY_SYMBOLS)
    return needed, soname, canary


def _elf_build_id(
    stream: BinaryIO, order: str, notes: list[tuple[int, int]]
) -> str | None:
    """The GNU build-id (hex) from a PT_NOTE segment, or None if absent.

    A note record is namesz/descsz/type words then the (4-aligned) name and
    descriptor; the build-id is the descriptor of the ``GNU`` note of type
    NT_GNU_BUILD_ID. Bounded by the note count and each segment's already-capped
    size, and fail-closed: a malformed record stops the scan rather than raising.
    """
    for note_off, note_sz in notes:
        stream.seek(note_off)
        blob = stream.read(min(note_sz, _ELF_MAX_NOTE_BYTES))
        pos = 0
        for _ in range(_ELF_MAX_NOTES):
            if pos + 12 > len(blob):
                break
            namesz = int.from_bytes(blob[pos : pos + 4], order)  # type: ignore[arg-type]
            descsz = int.from_bytes(blob[pos + 4 : pos + 8], order)  # type: ignore[arg-type]
            ntype = int.from_bytes(blob[pos + 8 : pos + 12], order)  # type: ignore[arg-type]
            name_start = pos + 12
            name_end = name_start + namesz
            desc_start = name_end + (-namesz % 4)
            desc_end = desc_start + descsz
            if desc_end > len(blob):
                break
            name = blob[name_start:name_end].split(b"\x00", 1)[0]
            if ntype == _NT_GNU_BUILD_ID and name == b"GNU" and 0 < descsz <= _ELF_BUILD_ID_MAX:
                return blob[desc_start:desc_end].hex()
            pos = desc_end + (-descsz % 4)
    return None


def _elf_is_stripped(
    stream: BinaryIO, order: str, bits: int, shoff: int, shentsize: int, shnum: int
) -> bool | None:
    """True when no SHT_SYMTAB section remains; None when there is no section table.

    A dynamically linked binary keeps .dynsym for the loader, so stripping is
    specifically the absence of the full .symtab, not of all symbol tables.
    """
    if shoff <= 0 or shnum <= 0 or shnum > _ELF_MAX_SHNUM:
        return None
    want = 64 if bits == 64 else 40
    entsize = max(shentsize, want)
    stream.seek(shoff)
    table = stream.read(entsize * shnum)
    for i in range(shnum):
        entry = table[i * entsize : i * entsize + 8]
        if len(entry) < 8:
            break
        if int.from_bytes(entry[4:8], order) == _SHT_SYMTAB:  # type: ignore[arg-type]
            return False
    return True


def _macho_thin_facts(head: bytes, magic: bytes, stream: BinaryIO) -> dict[str, Any]:
    bits, order = _MACHO_THIN_MAGICS[magic]
    facts: dict[str, Any] = {"format": "macho", "bits": bits, "endianness": order}
    if len(head) >= 16:
        cputype = int.from_bytes(head[4:8], order)  # type: ignore[arg-type]
        filetype = int.from_bytes(head[12:16], order)  # type: ignore[arg-type]
        facts["arch"] = _MACHO_CPU.get(cputype, f"cpu_{cputype}")
        facts["type"] = _MACHO_FILETYPES.get(filetype, f"type_{filetype}")
    # The header flags and load commands answer the same triage questions the
    # ELF reader does: position independence, dynamic linking, which dynamic
    # linker loads the image, and which shared libraries it pulls in. The flags
    # sit at offset 24 in both the 32- and 64-bit layouts.
    if len(head) >= 28:
        ncmds = int.from_bytes(head[16:20], order)  # type: ignore[arg-type]
        sizeofcmds = int.from_bytes(head[20:24], order)  # type: ignore[arg-type]
        flags = int.from_bytes(head[24:28], order)  # type: ignore[arg-type]
        facts["pie"] = bool(flags & _MH_PIE)
        facts["linking"] = "dynamic" if flags & _MH_DYLDLINK else "static"
        # Same posture questions the ELF reader answers from PT_GNU_STACK: the
        # stack is non-executable unless the image opts in via the header flag.
        facts["nx"] = not flags & _MH_ALLOW_STACK_EXECUTION
        cmd_off = 32 if bits == 64 else 28
        cmds = _macho_read_load_commands(stream, cmd_off, sizeofcmds, head)
        lc = _macho_load_commands(cmds, order, ncmds)
        if lc["dylibs"] is not None:
            facts["dylibs"] = lc["dylibs"]
        for key in ("interpreter", "install_name", "uuid"):
            if lc[key] is not None:
                facts[key] = lc[key]
        entry = _macho_entry(lc["entryoff"], lc["segments"])
        if entry is not None:
            facts["entry"] = entry
        # FairPlay: an LC_ENCRYPTION_INFO with cryptid != 0 means the code is
        # ciphertext on disk; no command at all means not encrypted.
        facts["encrypted"] = bool(lc["cryptid"])
        canary = _macho_canary(stream, lc["symtab"])
        if canary is not None:
            facts["canary"] = canary
    return facts


def _macho_canary(stream: BinaryIO, symtab: tuple[int, int] | None) -> bool | None:
    """Whether the symbol string table names a stack-protector guard.

    A clang ``-fstack-protector`` build imports ``___stack_chk_guard`` /
    ``___stack_chk_fail`` from libSystem, so their names sit in LC_SYMTAB's
    string table -- the same substring scan the ELF reader runs over dynstr
    (Mach-O C symbols carry one more leading underscore, which a substring
    match absorbs). An image with no symbol table cannot answer, so it gets
    None (no fact) rather than a fabricated False.
    """
    if symtab is None:
        return None
    stroff, strsize = symtab
    if stroff <= 0 or strsize <= 0:
        return None
    try:
        stream.seek(stroff)
        blob = stream.read(min(strsize, _ELF_MAX_STRTAB))
    except OSError:
        return None
    if not blob:
        return None
    return any(sym in blob for sym in _ELF_CANARY_SYMBOLS)


def _macho_read_load_commands(
    stream: BinaryIO, cmd_off: int, sizeofcmds: int, head: bytes
) -> bytes:
    """Return the load-command region, from the head window or a bounded read.

    Small images keep their commands inside the header window already read; a
    larger one has them read straight from the file, capped so a corrupt
    sizeofcmds cannot force a large allocation.
    """
    if sizeofcmds <= 0:
        return b""
    cap = min(sizeofcmds, _MACHO_MAX_CMDS_BYTES)
    if cmd_off + cap <= len(head):
        return head[cmd_off : cmd_off + cap]
    try:
        stream.seek(cmd_off)
        return stream.read(cap)
    except OSError:
        return head[cmd_off:] if cmd_off < len(head) else b""


def _macho_lc_str(cmds: bytes, pos: int, cmdsize: int, order: str) -> str | None:
    """Decode a load command's lc_str (an offset into its own body)."""
    name_off = int.from_bytes(cmds[pos + 8 : pos + 12], order)  # type: ignore[arg-type]
    if 8 <= name_off < cmdsize:
        raw = cmds[pos + name_off : pos + cmdsize]
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace") or None
    return None


def _macho_uuid(raw: bytes) -> str:
    """Format 16 LC_UUID bytes as the canonical 8-4-4-4-12 hex string."""
    hexed = raw.hex()
    return f"{hexed[0:8]}-{hexed[8:12]}-{hexed[12:16]}-{hexed[16:20]}-{hexed[20:32]}"


def _macho_load_commands(cmds: bytes, order: str, ncmds: int) -> dict[str, Any]:
    """Walk the load commands for the image's identity and dependency facts.

    Returns ``dylibs`` (the LC_LOAD_DYLIB / weak / reexport names, or None when
    the command count is out of range), ``interpreter`` (LC_LOAD_DYLINKER),
    ``install_name`` (LC_ID_DYLIB, a dylib's own name -- the DT_SONAME analogue),
    ``uuid`` (LC_UUID, the build id), ``entryoff`` (LC_MAIN's file offset of
    main, or None), ``segments`` ((vmaddr, fileoff, filesize) per LC_SEGMENT
    / LC_SEGMENT_64, for mapping that offset to an address), ``symtab``
    (LC_SYMTAB's (stroff, strsize), for the canary scan) and ``cryptid``
    (LC_ENCRYPTION_INFO's crypt id, or None when the image carries none).
    Bounded by the command count and the region already sized; a command whose
    body runs past that region stops the walk.
    """
    result: dict[str, Any] = {
        "dylibs": None,
        "interpreter": None,
        "install_name": None,
        "uuid": None,
        "entryoff": None,
        "segments": [],
        "symtab": None,
        "cryptid": None,
    }
    if ncmds <= 0 or ncmds > _MACHO_MAX_LOAD_CMDS:
        return result
    names: list[str] = []
    segments: list[tuple[int, int, int]] = []
    result["dylibs"] = names
    result["segments"] = segments
    pos = 0
    for _ in range(ncmds):
        if pos + 8 > len(cmds):
            break
        cmd = int.from_bytes(cmds[pos : pos + 4], order)  # type: ignore[arg-type]
        cmdsize = int.from_bytes(cmds[pos + 4 : pos + 8], order)  # type: ignore[arg-type]
        if cmdsize < 8 or pos + cmdsize > len(cmds):
            break
        if cmd in _LC_DYLIB_CMDS and len(names) < _MACHO_MAX_DYLIBS:
            name = _macho_lc_str(cmds, pos, cmdsize, order)
            if name:
                names.append(name)
        elif cmd == _LC_LOAD_DYLINKER and result["interpreter"] is None:
            result["interpreter"] = _macho_lc_str(cmds, pos, cmdsize, order)
        elif cmd == _LC_ID_DYLIB and result["install_name"] is None:
            result["install_name"] = _macho_lc_str(cmds, pos, cmdsize, order)
        elif cmd == _LC_UUID and result["uuid"] is None and cmdsize >= 24:
            result["uuid"] = _macho_uuid(cmds[pos + 8 : pos + 24])
        elif cmd == _LC_MAIN and result["entryoff"] is None and cmdsize >= 24:
            result["entryoff"] = int.from_bytes(cmds[pos + 8 : pos + 16], order)  # type: ignore[arg-type]
        elif cmd == _LC_SYMTAB and result["symtab"] is None and cmdsize >= 24:
            # symoff/nsyms then stroff/strsize; only the string table matters
            # here -- the canary scan greps it for the stack-guard imports.
            result["symtab"] = (
                int.from_bytes(cmds[pos + 16 : pos + 20], order),  # type: ignore[arg-type]
                int.from_bytes(cmds[pos + 20 : pos + 24], order),  # type: ignore[arg-type]
            )
        elif (
            cmd in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64)
            and result["cryptid"] is None
            and cmdsize >= 20
        ):
            # cryptoff/cryptsize then cryptid, in both the 32- and 64-bit
            # layouts (the 64-bit one only appends padding).
            result["cryptid"] = int.from_bytes(cmds[pos + 16 : pos + 20], order)  # type: ignore[arg-type]
        elif cmd == _LC_SEGMENT_64 and cmdsize >= 56:
            # segname(16) then vmaddr/vmsize/fileoff/filesize as u64s.
            segments.append(
                (
                    int.from_bytes(cmds[pos + 24 : pos + 32], order),  # type: ignore[arg-type]
                    int.from_bytes(cmds[pos + 40 : pos + 48], order),  # type: ignore[arg-type]
                    int.from_bytes(cmds[pos + 48 : pos + 56], order),  # type: ignore[arg-type]
                )
            )
        elif cmd == _LC_SEGMENT and cmdsize >= 40:
            # segname(16) then vmaddr/vmsize/fileoff/filesize as u32s.
            segments.append(
                (
                    int.from_bytes(cmds[pos + 24 : pos + 28], order),  # type: ignore[arg-type]
                    int.from_bytes(cmds[pos + 32 : pos + 36], order),  # type: ignore[arg-type]
                    int.from_bytes(cmds[pos + 36 : pos + 40], order),  # type: ignore[arg-type]
                )
            )
        pos += cmdsize
    return result


def _macho_entry(entryoff: int | None, segments: list[tuple[int, int, int]]) -> int | None:
    """Map LC_MAIN's file offset of main() to the address analysts navigate to.

    LC_MAIN records where execution starts as a file offset, unlike ELF's
    e_entry which is already an address, so the segment whose file range covers
    the offset supplies the translation. No covering segment (a hostile or
    truncated image) yields None rather than a fabricated address. Legacy
    LC_UNIXTHREAD entry points (pre-10.8 binaries, whose entry hides in
    arch-specific thread state) are not decoded; those images simply carry no
    entry fact.
    """
    if entryoff is None:
        return None
    for vmaddr, fileoff, filesize in segments:
        if filesize > 0 and fileoff <= entryoff < fileoff + filesize:
            return vmaddr + (entryoff - fileoff)
    return None


def _macho_fat_facts(head: bytes) -> dict[str, Any]:
    # A fat header is defined big-endian: magic, slice count, then fat_arch rows
    # of (cputype, cpusubtype, offset, size, align) = 20 bytes each. Validate the
    # same way the classifier does so a Java .class (which shares 0xCAFEBABE)
    # yields nothing rather than a bogus universal-binary description.
    if len(head) < 12:
        return {}
    slices = int.from_bytes(head[4:8], "big")
    if not 0 < slices <= _NATIVE_MAX_FAT_ARCHS:
        return {}
    if int.from_bytes(head[8:12], "big") not in _MACHO_CPU:
        return {}
    arches: list[str] = []
    pos = 8
    for _ in range(slices):
        if pos + 8 > len(head):
            break
        cputype = int.from_bytes(head[pos : pos + 4], "big")
        arches.append(_MACHO_CPU.get(cputype, f"cpu_{cputype}"))
        pos += 20
    return {
        "format": "macho-universal",
        "endianness": "big",
        "slice_count": slices,
        "architectures": arches,
    }
