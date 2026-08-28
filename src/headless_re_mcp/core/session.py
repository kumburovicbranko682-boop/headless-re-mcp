from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import math
import re
import uuid
import zipfile
import zlib
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from threading import RLock
from typing import IO, Any, BinaryIO, Protocol
from urllib.parse import unquote_to_bytes, urlsplit

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
                # Authenticode is a whole-PE fact, native or managed, so it
                # rides alongside the .NET facts under its own key rather than
                # inside them -- a native signed PE gets a verdict too.
                authenticode = _pe_authenticode(path)
                if authenticode is not None:
                    metadata["pe"] = {"authenticode": authenticode}
                # Appended data past the last section (dropper stash), split
                # into the signature's share and the unexplained remainder.
                overlay = _pe_overlay(path)
                if overlay is not None:
                    metadata.setdefault("pe", {})["overlay"] = overlay
                # Executable magic hidden in the resource directory -- a nested
                # PE in an RT_RCDATA blob is the dropper's stage two.
                res_payloads, res_count = _pe_resource_payloads(path)
                metadata.setdefault("pe", {})["resource_payloads"] = res_payloads
                metadata["pe"]["resource_payload_count"] = res_count
                # The import/export directories -- the native PE capability
                # surface, the pair to an ELF/Mach-O's imported/exported
                # symbols. Always reported: empty lists are a real answer (a
                # static EXE with no imports, a non-DLL with no exports).
                imports, exports = _pe_capability_surface(path)
                metadata["pe"]["imports"] = imports
                metadata["pe"]["exports"] = exports
                # Subsystem, loader mitigations and entry VA off the optional
                # header -- the native PE build posture, the pair to the ELF
                # nx/relro/canary/pie and Mach-O nx/pie facts.
                metadata["pe"].update(_pe_hardening_facts(path))
                # TLS callbacks -- the PE's code-before-main, the pair to the
                # ELF/Mach-O init_funcs facts and the packer's anti-debug home.
                metadata["pe"].update(_pe_tls_facts(path))
                # The CodeView RSDS record -- the PE build fingerprint, the
                # pair to an ELF build-id / Mach-O UUID; absent is an answer.
                metadata["pe"].update(_pe_debug_fingerprint(path))
                # VS_VERSIONINFO -- the self-declared identity (versions,
                # CompanyName/ProductName strings); a claim, not a verdict.
                metadata["pe"].update(_pe_version_info(path))
                # The Rich header -- MSVC's toolchain census, the PE pair to
                # an ELF .comment and a Mach-O build-tool entry; only
                # Microsoft linkers write it, so absence is a real answer.
                metadata["pe"].update(_pe_rich_header(path))
                # Sections mapped writable and executable at once -- the PE
                # W^X violation, the pair to the native wx_segments counts;
                # an empty list is a real answer.
                metadata["pe"].update(_pe_wx_sections(path))
                # Near-random sections -- the packed-payload flags the magic
                # censuses cannot raise; empty is a real answer.
                metadata["pe"].update(_pe_high_entropy_sections(path))
                # The URL census over the whole image: ASCII literals in the
                # native sections plus UTF-16LE ones (a managed assembly's #US
                # string heap stores its C# literals wide).
                metadata["pe"].update(_file_url_facts(path))
                # Managed resources are a separate store from the PE resource
                # tree: the ManifestResource census covers the Assembly.Load
                # packer pattern.
                if metadata.get("dotnet"):
                    mres_payloads, mres_count = _dotnet_resource_payloads(path)
                    metadata["dotnet"]["resource_payloads"] = mres_payloads
                    metadata["dotnet"]["resource_payload_count"] = mres_count
                    # Near-random resources with no magic to explain them --
                    # the ConfuserEx shape: an encrypted stage-two assembly
                    # behind Assembly.Load. Empty is a real answer.
                    mres_flags, mres_flag_count = _dotnet_high_entropy_resources(path)
                    metadata["dotnet"]["high_entropy_resources"] = mres_flags
                    metadata["dotnet"]["high_entropy_resource_count"] = mres_flag_count
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
_SHT_DYNSYM = 11
_SHT_NOBITS = 8  # occupies no file bytes (.bss): its size must not extend the image
# The exported dynamic symbols -- the names a shared object (or executable)
# offers other images, read straight off the .dynsym section and its linked
# .dynstr. This is the native export surface: the pair to DT_NEEDED (imports),
# the raw-symbol complement to DT_VERDEF (versioned exports) and the analogue
# of a PE export table, an APK's exported components or a WASM export section.
# A symbol counts as exported when it is defined (a real section index, not
# SHN_UNDEF) and globally/weakly bound; the scan and the reported list are both
# bounded so a symbol-heavy library cannot make the read or the fact unbounded.
_STB_GLOBAL = 1
_STB_WEAK = 2
_SHN_UNDEF = 0
_SHN_LORESERVE = 0xFF00
_ELF_MAX_DYNSYM_SCAN = 200_000
# Executable/container magic a native section (ELF SHT_PROGBITS, or a Mach-O
# segment's section) can open with -- the native analogue of the PE resource,
# APK member, WASM data-segment and .NET ManifestResource payload censuses.
# A dropper linked as an ELF/Mach-O parks its stage two in a custom section
# (e.g. a `.payload`/`__data,__payload`) it writes out and runs; this censuses
# any section whose first bytes are one of these. Same set the PE resource
# census uses. MZ carries a 0x40-byte floor (a DOS stub is at least that long)
# so a stray "MZ" string is not read as a PE.
_NATIVE_SECTION_KINDS: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"dex\n", "dex"),
    (b"PK\x03\x04", "zip"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"MZ", "pe"),
)
_NATIVE_SECTION_SNIFF = 0x40
_NATIVE_MAX_SECTION_PAYLOADS = 64
# Shannon entropy flags packed or encrypted bytes: compressed and ciphered
# data measure near 8 bits/byte while code, tables and text sit well below 7.
# A section at or past the threshold (and big enough for the measure to mean
# anything) is the stashed-payload shape the magic-byte census cannot see --
# an encrypted stage two has no magic. radare2's `iS entropy` and pefile's
# get_entropy compute the same measure, so the gates cross-check the numbers.
_ENTROPY_THRESHOLD = 7.2
_ENTROPY_MIN_SIZE = 256
_ENTROPY_MAX_READ = 4 * 1024 * 1024
_ENTROPY_MAX_FLAGGED = 32
# Heads that already explain near-random bytes, so the entropy censuses skip
# them: executables and containers belong to the payload censuses; compressed
# media, fonts and archives are near-random by design and say so up front; a
# .NET ResourceManager blob declares its own format. An encrypted payload is
# exactly the bytes with no such self-declaration (MP4-family files declare
# via "ftyp" at offset 4 and are handled in _self_declaring_magic).
_ENTROPY_SELF_DECLARING = (
    b"dex\n",  # DEX
    b"\x7fELF",  # ELF
    b"PK\x03\x04",  # ZIP / APK / JAR
    b"MZ",  # PE
    b"\x00asm",  # WASM
    b"\xcf\xfa\xed\xfe",  # Mach-O (and the other magics below)
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xfe\xed\xfa\xce",
    b"\x89PNG",  # PNG
    b"\xff\xd8\xff",  # JPEG
    b"GIF8",  # GIF
    b"RIFF",  # WebP / WAV / AVI
    b"OggS",  # Ogg audio
    b"ID3",  # MP3 with ID3 tag
    b"\x1f\x8b",  # gzip
    b"wOFF",  # WOFF font
    b"wOF2",  # WOFF2 font
    b"\x28\xb5\x2f\xfd",  # zstd
    b"\xce\xca\xef\xbe",  # .NET ResourceManager .resources blob
)
# Plaintext network endpoints baked into the target -- the first triage
# question of any binary ("who does it talk to?"), the static pair to a HAR's
# observed requests. Only scheme-prefixed URLs count: bare hostnames drown in
# false positives, while ``https://c2.example`` is self-announcing. The charset
# is RFC 3986's (unreserved + gen-delims + sub-delims + percent), and the scan
# reads both encodings a compiled binary stores literals in: raw ASCII (C
# strings in ELF/Mach-O/PE .rodata, DEX MUTF-8, WASM data segments) and
# UTF-16LE (the .NET #US string heap, Windows wide strings). GNU ``strings``
# (and ``strings -e l``) surfaces the same literals, so the gates cross-check
# against it. Bounded: match length, listed sample and total bytes scanned are
# all capped; the count of distinct URLs stays exact within the scan budget.
_URL_MAX_LEN = 2048
_URL_MAX_LISTED = 32
_URL_SCAN_CHUNK = 1 << 20
_URL_SCAN_BUDGET = 64 * 1024 * 1024
# A deferred boundary match must fit in the carried tail whole: the longest
# possible match is a wide one, 2 bytes per character of scheme + "://" + body.
_URL_SCAN_KEEP = 2 * (_URL_MAX_LEN + 16)
_URL_BODY = rb"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]"
_URL_ASCII_RE = re.compile(
    rb"(?:https?|wss?|ftp)://" + _URL_BODY + rb"{1,%d}" % _URL_MAX_LEN,
    re.IGNORECASE,
)
_URL_WIDE_RE = re.compile(
    rb"(?:h\x00t\x00t\x00p\x00(?:s\x00)?|w\x00s\x00(?:s\x00)?|f\x00t\x00p\x00)"
    rb":\x00/\x00/\x00(?:" + _URL_BODY + rb"\x00){1,%d}" % _URL_MAX_LEN,
    re.IGNORECASE,
)
# XML namespace / schema identifiers name a *format*, not an endpoint --
# nothing ever connects to them. Every AXML manifest carries
# schemas.android.com, every PE side-by-side manifest schemas.microsoft.com,
# every XMP-tagged image ns.adobe.com/purl.org, so leaving them in would put a
# constant, meaningless cleartext "endpoint" on virtually every target. The
# gates apply the same skip list to the referee's output.
_URL_NAMESPACE_PREFIXES = (
    "http://schemas.android.com/",
    "http://schemas.microsoft.com/",
    "http://schemas.openxmlformats.org/",
    "http://www.w3.org/",
    "http://ns.adobe.com/",
    "http://purl.org/",
)
_NATIVE_MAX_MACHO_SECTIONS = 4096
_SHT_NULL = 0
_SHT_PROGBITS = 1
_ELF_MAX_SHSTRTAB = 1024 * 1024
_ELF_MAX_EXPORTS = 8192
# The .comment section collects one NUL-terminated record per compiler that
# touched the link ("GCC: (Ubuntu 13.2.0...)", "clang version ...") -- the ELF
# toolchain provenance, the pair to the WASM producers section, a Mach-O
# LC_BUILD_VERSION tool entry and a PE Rich header. readelf -p .comment prints
# the same strings, so the native gate can cross-check them.
_ELF_TOOLCHAIN_SECTION = ".comment"
_ELF_MAX_COMMENT = 64 * 1024
_ELF_MAX_TOOLCHAIN = 16
_ELF_MAX_TOOLCHAIN_CHARS = 256
_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_SONAME = 14
_DT_STRSZ = 10
# The runtime library search paths baked into the binary. DT_RPATH is the older
# tag (searched before LD_LIBRARY_PATH), DT_RUNPATH the newer (searched after);
# both are colon-separated string-table offsets, read the same way as
# DT_NEEDED/DT_SONAME. They are a first-order supply-chain/hijack triage fact --
# a writable or relative entry lets an attacker preload a library -- and
# readelf -d reports the same tags, so the native gate can cross-check them.
_DT_RPATH = 15
_DT_RUNPATH = 29
# Versioned-symbol requirements (.gnu.version_r): DT_VERNEED points at a chain
# of Verneed records, one per depended-on library, each chaining Vernaux
# records that name the version tags it demands (e.g. GLIBC_2.34 out of
# libc.so.6). This is the true minimum-runtime fact for a dynamic ELF -- the
# analogue of Mach-O's min_os -- and readelf -V prints the same chain, so the
# toolchain gate can cross-check it. The caps bound a hostile chain: no real
# binary needs more than a few dozen libraries or versions.
_DT_VERNEED = 0x6FFFFFFE
_DT_VERNEEDNUM = 0x6FFFFFFF
_ELF_MAX_VERNEED = 64
_ELF_MAX_VERNAUX = 128
# Versioned-symbol definitions (.gnu.version_d): DT_VERDEF points at a chain of
# Verdef records, one per version node the object *provides* (e.g. GLIBC_2.34
# in libc.so.6, or PROBE_1.0 in a library built with a version script). This is
# the export-side pair to DT_VERNEED -- the ABI contract a shared object
# exposes, the versioned-symbol analogue of DT_SONAME and the native counterpart
# to the exported surface an APK or a managed assembly declares. The first node
# carries VER_FLG_BASE and names the object itself; later nodes may chain a
# parent version. readelf -V prints the same "Version definition section", so
# the toolchain gate can cross-check it. Bounded like the Verneed walk.
_DT_VERDEF = 0x6FFFFFFC
_DT_VERDEFNUM = 0x6FFFFFFD
_VER_FLG_BASE = 0x1
_ELF_MAX_VERDEF = 128
_ELF_MAX_VERDAUX = 128
# The code the loader runs before handing control to the entry point (and
# after main returns): DT_INIT/DT_FINI point at the legacy single init/fini
# functions, and DT_INIT_ARRAYSZ / DT_FINI_ARRAYSZ / DT_PREINIT_ARRAYSZ give
# the byte size of the pointer arrays whose every entry gets called. Load-time
# constructors are the classic hiding place for code that fires before any
# breakpoint on main (LD_PRELOAD implants, anti-debug hooks), so whether they
# exist and how many there are is a first-order triage fact. readelf -d prints
# the same tags, so the toolchain gate can cross-check them. Only sizes are
# read -- no pointer is followed -- and the derived counts are clamped so a
# lying size yields a bounded number, not a fantastical one.
_DT_INIT = 12
_DT_FINI = 13
_DT_INIT_ARRAYSZ = 27
_DT_FINI_ARRAYSZ = 28
_DT_PREINIT_ARRAYSZ = 33
_ELF_MAX_INIT_FUNCS = 8192
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
# PF_W with PF_X on the same PT_LOAD is the W^X violation: a mapping the
# process can both write and run -- the packer/self-modifying-code tell (a
# stock toolchain never emits one). readelf -l prints the same flags column
# ("RWE"), so the native gate can cross-check the count.
_PF_W = 0x2
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
# The GNU ABI-tag note (NT_GNU_ABI_TAG): the OS the image targets and the
# minimum kernel version it needs -- the ELF counterpart to Mach-O's
# LC_BUILD_VERSION platform/min_os. readelf -n prints the same "OS: Linux,
# ABI: x.y.z", so the toolchain gate can cross-check it. Every gcc/clang build
# carries it, so it is a reliable "which Unix, how old a kernel" triage fact.
_NT_GNU_ABI_TAG = 1
_ELF_ABI_OS = {
    0: "linux",
    1: "hurd",
    2: "solaris",
    3: "freebsd",
    4: "netbsd",
    5: "syllable",
    6: "nacl",
}
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
# The @rpath search paths baked into the image -- the Mach-O DT_RPATH/DT_RUNPATH.
# Same hijack-triage weight as on ELF: a writable or relative entry lets an
# attacker plant a dylib that @rpath resolution picks up first.
_LC_RPATH = 0x8000001C
# Which Apple platform the image targets and the minimum OS / SDK it was built
# against -- the first question asked of an Apple binary (macOS or iOS? how
# old?). Modern linkers emit LC_BUILD_VERSION (platform + minos + sdk); older
# ones emit one LC_VERSION_MIN_* command whose kind names the platform.
# llvm-objdump prints the same three values, so the toolchain gate cross-checks
# them, and radare2 keys its `os` line on the same commands.
_LC_BUILD_VERSION = 0x32
_LC_VERSION_MIN_CMDS = {
    0x24: "macos",  # LC_VERSION_MIN_MACOSX
    0x25: "ios",  # LC_VERSION_MIN_IPHONEOS
    0x2F: "tvos",  # LC_VERSION_MIN_TVOS
    0x30: "watchos",  # LC_VERSION_MIN_WATCHOS
}
_MACHO_PLATFORMS = {
    1: "macos",
    2: "ios",
    3: "tvos",
    4: "watchos",
    5: "bridgeos",
    6: "maccatalyst",
    7: "ios-simulator",
    8: "tvos-simulator",
    9: "watchos-simulator",
    10: "driverkit",
    11: "visionos",
    12: "visionos-simulator",
}
# LC_BUILD_VERSION's trailing ntools entries name the toolchain that produced
# the image (clang/swift/ld and their versions) -- the Mach-O toolchain
# provenance, the pair to an ELF .comment and the WASM producers section.
# llvm-objdump --macho --all-headers prints the same tool/version rows.
_MACHO_TOOLS = {1: "clang", 2: "swift", 3: "ld", 4: "lld"}
_MACHO_MAX_TOOLS = 16
_LC_SEGMENT = 0x01
_LC_SEGMENT_64 = 0x19
# initprot carrying both write and execute is the Mach-O W^X violation, the
# pair to a RWE PT_LOAD: a mapping the process can write and run, which no
# stock Apple toolchain emits. llvm-objdump prints the same initprot field.
_VM_PROT_WRITE = 0x2
_VM_PROT_EXECUTE = 0x4
# The embedded code signature (a linkedit_data_command naming where the
# SuperBlob lives). Whether an image is signed at all -- and by whom -- is the
# macOS analogue of the APK signer facts: the CodeDirectory inside carries the
# signing identifier, the team id and the ad-hoc flag, and its digest is what
# Apple's tooling pins (the cdhash). All CS structures are big-endian.
_LC_CODE_SIGNATURE = 0x1D
_CS_SUPERBLOB_MAGIC = 0xFADE0CC0
_CS_CODEDIRECTORY_MAGIC = 0xFADE0C02
_CS_SLOT_CODEDIRECTORY = 0
_CS_FLAG_ADHOC = 0x2
_CS_MAX_BLOBS = 64
_CS_MAX_NAME = 256
# An embedded signature is a few KB (ad-hoc) to a few tens of KB (a real CMS
# chain plus entitlements); this only refuses a pathological datasize.
_CS_MAX_SIG_BYTES = 4 * 1024 * 1024
_CS_HASH_TYPES = {1: "sha1", 2: "sha256", 3: "sha256_truncated", 4: "sha384"}
_MACHO_MAX_LOAD_CMDS = 4096
_MACHO_MAX_DYLIBS = 64
# The symbol surface of a Mach-O image, split off LC_SYMTAB's nlist entries
# with the N_EXT (external) bit set: type N_SECT is defined in a section here
# (an export), type N_UNDF is dyld's to resolve from a linked dylib (an
# import). Together they are the Mach-O counterpart to the ELF .dynsym facts --
# the same sets llvm-nm --defined-only / --undefined-only --extern-only list.
# N_TYPE masks the type field of n_type; the scan and reported lists are
# bounded so a symbol-heavy image cannot force a large read or an unbounded fact.
_N_EXT = 0x01
_N_TYPE = 0x0E
_N_SECT = 0x0E
_N_UNDF = 0x00
# N_STAB masks the three bits that mark a debug-map (STABS) symbol -- the
# -g source/line entries `strip` removes. A local defined symbol (N_SECT with
# N_EXT clear) is the other thing `strip` takes; the presence of either is
# what "not stripped" means for a Mach-O, the counterpart to an ELF .symtab.
_N_STAB = 0xE0
_MACHO_MAX_NSYMS_SCAN = 200_000
_MACHO_MAX_EXPORTS = 8192
# The load-time constructor surface, the Mach-O counterpart of ELF's
# DT_INIT_ARRAY: dyld calls every pointer in a section typed
# S_MOD_INIT_FUNC_POINTERS before the entry point (and the term pointers
# after), and newer chained-fixup images carry 32-bit offsets in an
# S_INIT_FUNC_OFFSETS section instead. The section type lives in the low byte
# of the section flags; only the declared sizes are read -- no pointer is
# followed -- and the derived counts are clamped like the ELF ones.
_S_SECTION_TYPE_MASK = 0xFF
_S_MOD_INIT_FUNC_POINTERS = 0x09
_S_MOD_TERM_FUNC_POINTERS = 0x0A
_S_INIT_FUNC_OFFSETS = 0x16
_MACHO_MAX_INIT_FUNCS = 8192
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
# The platform itself accepts at most ten v2/v3 signers per APK.
_APK_MAX_SIGNERS = 10

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
    # Two more <application> posture flags: whether app data is exposed to
    # `adb backup` and whether plaintext HTTP is permitted -- both first-order
    # mobile-pentest findings, both read the same way debuggable is.
    0x01010280: "allowBackup",
    0x010104EC: "usesCleartextTraffic",
    # <uses-library android:required=...>: whether a missing shared library
    # blocks install (default true) or is optional. Its id, so a stripped
    # required attribute still resolves alongside the library's name.
    0x0101028E: "required",
    # android:exported on a component (activity/service/receiver/provider):
    # whether another app can reach it -- the component's export status, read
    # by id so it resolves even when aapt2 keeps only the resource map.
    0x01010010: "exported",
    # The <data> attributes of an intent-filter (framework ids from
    # frameworks/base core/res public.xml): together with an ACTION_VIEW they
    # declare which URIs open the app -- its deep links.
    0x01010027: "scheme",
    0x01010028: "host",
    0x0101002A: "path",
    0x0101002B: "pathPrefix",
    0x0101002C: "pathPattern",
}
# A shared library the app declares it needs on the device (<uses-library>),
# the Android analogue of a native DT_NEEDED / a managed AssemblyRef; capped
# like permissions so a hostile manifest cannot make the fact list unbounded.
_AXML_MAX_USES_LIBRARIES = 4096
# The intent-filter markers that make an <activity> the app's launcher -- its
# entry point, the Android analogue of an ELF's e_entry or a .NET entry token.
# An activity is launchable when one intent-filter carries both.
_ANDROID_ACTION_MAIN = "android.intent.action.MAIN"
_ANDROID_CATEGORY_LAUNCHER = "android.intent.category.LAUNCHER"
# The four component kinds another app can reach -- the app's exported attack
# surface, the mobile analogue of an ELF's exported dynamic symbols. A
# component is exported when android:exported="true", or (when the attribute
# is absent) when it declares an <intent-filter>; an explicit "false" closes
# it regardless. Bounded so a manifest with thousands of components cannot
# make the fact list unbounded.
_AXML_COMPONENT_TAGS = frozenset(
    {"activity", "activity-alias", "service", "receiver", "provider"}
)
_AXML_MAX_COMPONENTS = 4096
# Deep links: an activity intent-filter with ACTION_VIEW whose <data> declares
# a URI scheme is remotely reachable -- a browser link, QR code or another
# app's URI can start it. That makes it the remotely-triggerable subset of the
# exported surface, the mobile analogue of an HTML form action. Each <data>
# element with a scheme is one reported link, exactly as declared; the list
# and the per-filter element scan are bounded like every other manifest fact.
_ANDROID_ACTION_VIEW = "android.intent.action.VIEW"
_AXML_DEEP_LINK_TAGS = frozenset({"activity", "activity-alias"})
_AXML_MAX_DEEP_LINKS = 4096
_AXML_MAX_FILTER_DATAS = 256

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
# The map_list enumerates every structural section the DEX carries, each a
# (type, count) the loader itself reads. It is the DEX structural census, the
# Dalvik analogue of a WASM section table -- and its debug_info_item entry is
# the "how much does the analyst get for free" fact: the source-line and
# local-variable records a -g / debuggable build ships, the pair to DWARF and
# a PDB. Names match androguard's TypeMapItem so the gate compares directly.
_DEX_MAP_TYPE_NAMES: dict[int, str] = {
    0x0000: "header_item",
    0x0001: "string_id_item",
    0x0002: "type_id_item",
    0x0003: "proto_id_item",
    0x0004: "field_id_item",
    0x0005: "method_id_item",
    0x0006: "class_def_item",
    0x0007: "call_site_id_item",
    0x0008: "method_handle_item",
    0x1000: "map_list",
    0x1001: "type_list",
    0x1002: "annotation_set_ref_list",
    0x1003: "annotation_set_item",
    0x2000: "class_data_item",
    0x2001: "code_item",
    0x2002: "string_data_item",
    0x2003: "debug_info_item",
    0x2004: "annotation_item",
    0x2005: "encoded_array_item",
    0x2006: "annotations_directory_item",
    0xF000: "hiddenapi_class_data_item",
}
# A map_list has one entry per section type; the spec caps it well under this.
_DEX_MAX_MAP_ITEMS = 64
# method_ids rows are indexed by 16-bit operands in Dalvik instructions, so a
# single DEX holds at most 65536; a header claiming more is walked no further.
_DEX_MAX_METHOD_IDS = 65_536

# A bundled native library (lib/<abi>/*.so) is the app's JNI boundary: the same
# tool-free ELF reader a native session uses runs over each member's bytes, so
# an APK session knows which Java methods land in native code without any tool.
# Bounded like the DEX walk: at most this many members, each read up to the DEX
# byte cap, and at most this many Java_* names surfaced per library.
_APK_MAX_NATIVE_LIBS = 64
_APK_MAX_JAVA_NATIVES = 256
_JNI_ONLOAD = "JNI_OnLoad"
_JNI_EXPORT_PREFIX = "Java_"

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
    signed_v2, signed_v3, signers = _apk_signature_schemes(path)
    payloads, payload_count = _apk_embedded_payloads(path)
    entropy_flags, entropy_count = _apk_high_entropy_members(path)
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
            # Who signed it, not just that someone did: the SHA-256 of each
            # signer's certificate, per scheme -- the identity Android pins.
            "signers": signers,
            # Bytes glued on before the ZIP container (the Janus smuggling
            # shape): 0 for a clean archive, None when unmeasurable.
            "prepended_size": _apk_prepended_size(path),
            # Bytes glued on after the EOCD record and its comment: Android's
            # own parser rejects them, naive extractors read right past them.
            "appended_size": _apk_appended_size(path),
            "manifest": _apk_manifest_facts_from_apk(path),
            "dex": _apk_dex_facts(path),
            # The JNI surface of each bundled .so, parsed with the same ELF
            # reader a native session gets -- the Java<->native boundary.
            "native_libs": _apk_native_lib_facts(path),
            # Executable/container magic in members outside its canonical
            # home -- a DEX or ELF under assets/ is the dropper stage-two
            # shape. The count is exact; the listed sample is bounded.
            "embedded_payloads": payloads,
            "embedded_payload_count": payload_count,
            # Decompressed members that measure near-random with no magic to
            # explain it -- the encrypted-payload shape the magic census
            # cannot see. The count is exact; the listed sample is bounded.
            "high_entropy_members": entropy_flags,
            "high_entropy_member_count": entropy_count,
            # The network endpoints baked into the package, read from every
            # member's decompressed bytes -- the URL census, deduplicated
            # package-wide; sample bounded, count exact within budget.
            **_apk_url_facts(path),
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
    external_classes: set[str] = set()
    external_method_count = 0
    signatures: list[dict[str, str]] = []
    map_counts: dict[str, int] = {}
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
                # Alongside it, the verdict on the header's own integrity
                # claims -- meaningful only when the whole member was read.
                complete = read_cap == _DEX_MAX_BYTES and len(data) < _DEX_MAX_BYTES
                entry: dict[str, Any] = {"dex": name, "sha1": facts["signature"]}
                entry.update(_dex_integrity(data, facts, complete))
                signatures.append(entry)
                if len(data) > _DEX_HEADER_SIZE:
                    # The structural census needs the whole member (the
                    # map_list lives in the data section); summed across
                    # members like the other counts.
                    for section, count in _dex_map_counts(data, facts["map_off"]).items():
                        map_counts[section] = map_counts.get(section, 0) + count
                    if len(class_names) < _DEX_MAX_TOTAL_NAMES:
                        for cname in _dex_class_names(data, facts):
                            class_names.add(cname)
                            if len(class_names) >= _DEX_MAX_TOTAL_NAMES:
                                break
                    ext_names, ext_count = _dex_external_method_refs(data, facts)
                    external_method_count += ext_count
                    for ename in ext_names:
                        if len(external_classes) >= _DEX_MAX_TOTAL_NAMES:
                            break
                        external_classes.add(ename)
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
        "external_classes": sorted(external_classes),
        "external_method_count": external_method_count,
        "signatures": signatures,
        # The DEX structural census (map_list), summed across members -- the
        # Dalvik analogue of a WASM section table.
        "map_counts": map_counts,
        # How many methods ship source-line/local-variable debug info -- what
        # a -g / debuggable build carries and a release build does not, the
        # DEX pair to DWARF, a PDB and the WASM name section. Zero is a real
        # "no debug info" answer.
        "debug_info_items": map_counts.get("debug_info_item", 0),
    }


def _dex_map_counts(data: bytes, map_off: int) -> dict[str, int]:
    """The DEX map_list as ``{section type name: count}``.

    The map_list is a u32 size then that many 12-byte entries (u16 type, u16
    unused, u32 count, u32 offset) -- the structural census the loader reads,
    the Dalvik analogue of a WASM section table. The debug_info_item entry is
    the debug-availability fact. Bounded and fail-closed: the entry count is
    capped, an out-of-range offset yields ``{}``, and an unknown type is named
    ``unknown_<hex>`` rather than dropped so the census stays total.
    """
    if map_off <= 0 or map_off + 4 > len(data):
        return {}
    size = int.from_bytes(data[map_off : map_off + 4], "little")
    if size <= 0 or size > _DEX_MAX_MAP_ITEMS:
        return {}
    counts: dict[str, int] = {}
    pos = map_off + 4
    for _ in range(size):
        if pos + 12 > len(data):
            return {}
        type_id = int.from_bytes(data[pos : pos + 2], "little")
        count = int.from_bytes(data[pos + 4 : pos + 8], "little")
        pos += 12
        name = _DEX_MAP_TYPE_NAMES.get(type_id, f"unknown_{type_id:#06x}")
        counts[name] = counts.get(name, 0) + count
    return counts


def _dex_integrity(data: bytes, header: dict[str, Any], complete: bool) -> dict[str, Any]:
    """Verify a DEX member's own integrity claims; locate any appended bytes.

    The header stamps three claims about the file it heads: ``file_size`` (how
    many bytes the DEX is), ``checksum`` (adler32 over everything past byte
    12) and ``signature`` (SHA-1 over everything past byte 32) -- both sums
    taken over the ``file_size`` bytes the header describes. Recomputing them
    tells repack-and-patch tampering apart from a clean build: dexlib-based
    tooling refreshes the sums, a raw hex patch leaves them stale, and ART
    refuses a mismatch outright. Bytes beyond ``file_size`` are the DEX's own
    overlay -- the member reads normally while carrying a stowaway, the same
    smuggling shape as data appended to a PE or prepended to the APK itself.

    Fail-closed: when the member was not read in full, or ``file_size`` is
    smaller than a header or larger than the bytes present, every verdict is
    None -- never a guessed pass, never an invented overlay.
    """
    unmeasured: dict[str, Any] = {"checksum_ok": None, "signature_ok": None, "overlay": None}
    declared = header["file_size"]
    if not complete or declared < _DEX_HEADER_SIZE or declared > len(data):
        return unmeasured
    body = data[:declared]
    overlay = None
    if declared < len(data):
        overlay = {"offset": declared, "size": len(data) - declared}
    return {
        "checksum_ok": (zlib.adler32(body[12:]) & 0xFFFFFFFF) == header["checksum"],
        "signature_ok": hashlib.sha1(body[32:]).hexdigest() == header["signature"],
        "overlay": overlay,
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
        # The header's own integrity claims: the adler32 over everything past
        # byte 12, and how many bytes the file says it is. Verified (and any
        # excess reported as overlay) by _dex_integrity when the whole member
        # was read.
        "checksum": int.from_bytes(header[8:12], "little"),
        "file_size": int.from_bytes(header[32:36], "little"),
        # The map_list offset: the structural census (every section type and
        # count), read only when the whole member is in hand.
        "map_off": int.from_bytes(header[52:56], "little"),
        "string_count": string_count,
        "string_ids_off": int.from_bytes(header[60:64], "little"),
        "type_count": int.from_bytes(header[64:68], "little"),
        "type_ids_off": int.from_bytes(header[68:72], "little"),
        "method_count": method_count,
        "method_ids_off": int.from_bytes(header[92:96], "little"),
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


def _dex_external_method_refs(data: bytes, header: dict[str, Any]) -> tuple[set[str], int]:
    """Classes this DEX calls into but does not define, and how many such refs.

    The method_ids table names every method the bytecode can reference, and
    class_defs names every class defined here; a row whose class is not defined
    is the import surface -- which framework/API classes the code reaches for,
    the Android analogue of an ELF undefined dynamic symbol or a .NET P/Invoke.
    Only ``L`` class descriptors count: an array-typed row (``[I.clone()``) names
    a built-in, not an API class. Every lookup is bounds-checked, so a corrupt
    table yields fewer rows rather than raising.
    """
    string_ids_off = header["string_ids_off"]
    string_ids_size = header["string_count"]
    type_ids_off = header["type_ids_off"]
    type_ids_size = header["type_count"]
    defined: set[int] = set()
    for i in range(min(header["class_count"], _DEX_MAX_NAMES)):
        cd = header["class_defs_off"] + i * 32
        if cd + 4 > len(data):
            break
        defined.add(int.from_bytes(data[cd : cd + 4], "little"))
    names: set[str] = set()
    count = 0
    descriptors: dict[int, str | None] = {}
    for i in range(min(header["method_count"], _DEX_MAX_METHOD_IDS)):
        row = header["method_ids_off"] + i * 8
        if row + 8 > len(data):
            break
        class_idx = int.from_bytes(data[row : row + 2], "little")
        if class_idx in defined or class_idx >= type_ids_size:
            continue
        if class_idx not in descriptors:
            descriptors[class_idx] = None
            t = type_ids_off + class_idx * 4
            if t + 4 <= len(data):
                desc_idx = int.from_bytes(data[t : t + 4], "little")
                if desc_idx < string_ids_size:
                    s = string_ids_off + desc_idx * 4
                    if s + 4 <= len(data):
                        descriptors[class_idx] = _dex_read_mutf8(
                            data, int.from_bytes(data[s : s + 4], "little")
                        )
        descriptor = descriptors[class_idx]
        if descriptor and descriptor.startswith("L") and descriptor.endswith(";"):
            count += 1
            names.add(_dex_descriptor_to_name(descriptor))
    return names, count


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


def _apk_native_lib_facts(path: Path) -> list[dict[str, Any]]:
    """The JNI surface of every bundled native library, one record per .so.

    Each ``lib/<abi>/*.so`` member is parsed with the same tool-free ELF reader
    a native session uses, surfacing the facts that matter at the Java<->native
    boundary: identity (arch, soname, build-id when stamped), the dependency
    list (DT_NEEDED), and the binding surface -- exported ``Java_*`` symbols
    (statically registered native methods, whose mangled names encode the Java
    methods they implement) and ``JNI_OnLoad`` (dynamic registration: native
    methods exist that no export names) -- plus ``wx_segments``, the W^X
    violation count the packed-or-protected .so shape carries (Android
    packers routinely ship such libraries; a stock NDK build counts zero).
    Bounded and fail-closed: at most _APK_MAX_NATIVE_LIBS members, each read
    up to the DEX byte cap, and a member that is not parseable ELF is skipped
    rather than raising.
    """
    libs: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(path) as archive:
            members = sorted(
                name
                for name in archive.namelist()
                if name.startswith("lib/") and name.endswith(".so") and name.count("/") >= 2
            )
            for name in members[:_APK_MAX_NATIVE_LIBS]:
                try:
                    if archive.getinfo(name).file_size > _DEX_MAX_BYTES:
                        continue
                    with archive.open(name) as handle:
                        data = handle.read(_DEX_MAX_BYTES)
                except (OSError, zipfile.BadZipFile, KeyError):
                    continue
                if not data.startswith(b"\x7fELF"):
                    continue
                stream = io.BytesIO(data)
                facts = _elf_facts(stream.read(_NATIVE_HEADER_BYTES), stream)
                if not facts.get("bits"):
                    continue
                exports: list[str] = facts.get("exported_symbols", [])
                record: dict[str, Any] = {
                    "path": name,
                    "abi": name.split("/")[1],
                    "arch": facts.get("arch"),
                    "soname": facts.get("soname"),
                    "needed": facts.get("needed", []),
                    "jni_onload": _JNI_ONLOAD in exports,
                    "java_natives": [
                        sym for sym in exports if sym.startswith(_JNI_EXPORT_PREFIX)
                    ][:_APK_MAX_JAVA_NATIVES],
                }
                if facts.get("build_id") is not None:
                    record["build_id"] = facts["build_id"]
                # The W^X census the ELF reader already ran: present whenever
                # the member has program headers (every linked .so does).
                if "wx_segments" in facts:
                    record["wx_segments"] = facts["wx_segments"]
                libs.append(record)
    except (OSError, zipfile.BadZipFile):
        return []
    return libs


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


def _apk_prepended_size(path: Path) -> int | None:
    """Bytes prepended before the ZIP container starts, or None if unmeasurable.

    Every offset a ZIP records is relative to the container's own start, so
    when data is glued on in front -- the Janus smuggling shape
    (CVE-2017-13156: a DEX prepended to a signed APK, one file that is both) --
    the central directory's actual file position exceeds the offset the EOCD
    records by exactly the prepended byte count. That difference is the same
    "concat" the stdlib zipfile computes to keep reading such archives, and
    what Info-ZIP's unzip warns about as "extra bytes at beginning". 0 means a
    clean container; None means the shape could not be measured (no EOCD, a
    lying comment length, or ZIP64), never a guess.
    """
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            tail_len = min(size, _ZIP_EOCD_MIN + _ZIP_MAX_COMMENT)
            handle.seek(size - tail_len)
            tail = handle.read(tail_len)
    except OSError:
        return None
    eocd = tail.rfind(_ZIP_EOCD_SIGNATURE)
    if eocd < 0 or eocd + _ZIP_EOCD_MIN > len(tail):
        return None
    comment_len = int.from_bytes(tail[eocd + 20 : eocd + 22], "little")
    if eocd + _ZIP_EOCD_MIN + comment_len != len(tail):
        return None
    cd_size = int.from_bytes(tail[eocd + 12 : eocd + 16], "little")
    cd_offset = int.from_bytes(tail[eocd + 16 : eocd + 20], "little")
    if _ZIP64_SENTINEL in (cd_size, cd_offset):
        return None
    actual_cd = (size - tail_len + eocd) - cd_size
    if actual_cd < 0 or actual_cd < cd_offset:
        return None
    return actual_cd - cd_offset


def _apk_appended_size(path: Path) -> int | None:
    """Bytes glued on after the EOCD record and its comment, or None.

    The mirror image of _apk_prepended_size: a ZIP ends where its end-of-
    central-directory record's declared comment ends, so bytes past that point
    belong to no member, no directory, and no signature -- a stash appended
    with `cat`. The asymmetry that makes this worth reporting: Android's own
    parser (apksigner, libziparchive) requires the comment to reach exactly to
    EOF and rejects such a file as "not a ZIP archive", while Info-ZIP's unzip
    and Python's zipfile scan backwards for the EOCD magic and silently read
    right past the stash. One artifact, two parsers, two verdicts.

    The scan walks EOCD candidates from the end of the file backwards and
    takes the first whose record is self-consistent (comment fits inside the
    file, central directory size/offset arithmetic holds), so stash bytes that
    happen to contain the magic cannot spoof the record. 0 means the container
    ends where it claims to; None means no credible EOCD was found.
    """
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            tail_len = min(size, _ZIP_EOCD_MIN + 2 * _ZIP_MAX_COMMENT)
            handle.seek(size - tail_len)
            tail = handle.read(tail_len)
    except OSError:
        return None
    eocd = len(tail)
    while (eocd := tail.rfind(_ZIP_EOCD_SIGNATURE, 0, eocd)) >= 0:
        if eocd + _ZIP_EOCD_MIN > len(tail):
            continue
        comment_len = int.from_bytes(tail[eocd + 20 : eocd + 22], "little")
        declared_end = eocd + _ZIP_EOCD_MIN + comment_len
        if declared_end > len(tail):
            # The comment would run past EOF: not a credible record.
            continue
        cd_size = int.from_bytes(tail[eocd + 12 : eocd + 16], "little")
        cd_offset = int.from_bytes(tail[eocd + 16 : eocd + 20], "little")
        if _ZIP64_SENTINEL in (cd_size, cd_offset):
            return None
        actual_cd = (size - tail_len + eocd) - cd_size
        if actual_cd < 0 or actual_cd < cd_offset:
            # The directory cannot fit in front of this record: magic bytes
            # inside the stash, not the real EOCD. Keep walking backwards.
            continue
        return len(tail) - declared_end
    return None


# Executable/container magic worth flagging when found outside its canonical
# home inside an APK. MZ additionally requires a DOS-header-sized head so two
# letters of prose cannot read as a Windows executable.
_APK_PAYLOAD_KINDS: tuple[tuple[bytes, str], ...] = (
    (b"dex\n", "dex"),
    (b"\x7fELF", "elf"),
    (b"PK\x03\x04", "zip"),
    (b"MZ", "pe"),
)
# The places a DEX and an ELF legitimately live: classesN.dex at the archive
# root (covered by the dex facts) and lib/<abi>/*.so (covered by native_libs).
_APK_CANONICAL_DEX_RE = re.compile(r"classes\d*\.dex")
_APK_MAX_PAYLOAD_MEMBERS = 4096
_APK_MAX_PAYLOADS = 32
# Total decompressed bytes the APK entropy census will measure: a member is
# read to at most _ENTROPY_MAX_READ, and a hostile archive full of huge
# members cannot make the census inflate more than this in aggregate.
_APK_ENTROPY_BUDGET = 64 * 1024 * 1024


def _apk_embedded_payloads(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Members whose bytes open with executable magic outside its home.

    The dropper stage-two shape: a second DEX under ``assets/`` for a runtime
    DexClassLoader, a raw ELF shipped as a "data" file, a whole APK nested for
    later install. The canonical locations -- ``classes*.dex`` at the root and
    ``lib/<abi>/*.so`` -- already have dedicated facts, so only members
    *outside* them are listed. This is a census, not a verdict: a legitimate
    ZIP-based asset appears here too, named and sized, for the analyst to
    triage.

    Bounded and fail-closed: at most the first 0x40 bytes of each member are
    read (streamed, not fully decompressed), the member scan and the reported
    list are capped, and an unreadable member (encrypted, exotic compression)
    is skipped rather than raised on.
    """
    payloads: list[dict[str, Any]] = []
    count = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:_APK_MAX_PAYLOAD_MEMBERS]:
                name = info.filename
                if info.is_dir():
                    continue
                if _APK_CANONICAL_DEX_RE.fullmatch(name):
                    continue
                if name.startswith("lib/") and name.endswith(".so"):
                    continue
                try:
                    with archive.open(info) as member:
                        head = member.read(0x40)
                except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
                    continue
                kind = next(
                    (k for magic, k in _APK_PAYLOAD_KINDS if head.startswith(magic)), None
                )
                if kind == "pe" and len(head) < 0x40:
                    kind = None
                if kind is None:
                    continue
                count += 1
                if len(payloads) < _APK_MAX_PAYLOADS:
                    payloads.append({"path": name, "kind": kind, "size": info.file_size})
    except (OSError, zipfile.BadZipFile):
        return [], 0
    return payloads, count


def _apk_high_entropy_members(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Members whose decompressed bytes measure near-random with no magic.

    The Android packer shape the embedded-payload census cannot see: an
    encrypted classes.dex (or native stage) parked under ``assets/`` opens
    with no magic at all, so only the Shannon measure gives it away. Measured
    over each member's *decompressed* bytes -- a deflated text file's raw
    stream looks random too, but what the app reads back is the text.

    Skipped up front: the canonical homes with their own facts (classes*.dex,
    lib/<abi>/*.so), META-INF/ (signature files are DER-wrapped key material,
    self-declared by location), and members whose magic already explains the
    randomness (executables for the payload census, compressed media and
    fonts). Bounded and fail-closed: per-member and aggregate read budgets,
    a capped member scan, an exact count with a capped list, and unreadable
    members are skipped rather than raised on.
    """
    flagged: list[dict[str, Any]] = []
    count = 0
    budget = _APK_ENTROPY_BUDGET
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:_APK_MAX_PAYLOAD_MEMBERS]:
                if budget < _ENTROPY_MIN_SIZE:
                    break
                name = info.filename
                if info.is_dir() or info.file_size < _ENTROPY_MIN_SIZE:
                    continue
                if _APK_CANONICAL_DEX_RE.fullmatch(name):
                    continue
                if name.startswith("lib/") and name.endswith(".so"):
                    continue
                if name.startswith("META-INF/"):
                    continue
                try:
                    with archive.open(info) as member:
                        head = member.read(0x40)
                        if _self_declaring_magic(head):
                            continue
                        data = head + member.read(min(_ENTROPY_MAX_READ, budget) - len(head))
                except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
                    continue
                budget -= len(data)
                entropy = _shannon_entropy(data)
                if entropy >= _ENTROPY_THRESHOLD:
                    count += 1
                    if len(flagged) < _ENTROPY_MAX_FLAGGED:
                        flagged.append(
                            {"path": name, "entropy": round(entropy, 2), "size": info.file_size}
                        )
    except (OSError, zipfile.BadZipFile):
        return [], 0
    return flagged, count


def _apk_url_facts(path: Path) -> dict[str, Any]:
    """The URL census over every member's *decompressed* bytes.

    An APK stores its members deflated, so the raw archive bytes hide the
    string literals a flat binary would show -- the endpoints in a
    classes.dex string pool or an assets/ config only exist after inflation.
    Every member is walked (a URL is a finding wherever it sits, including a
    signing certificate's OCSP/CRL endpoints under META-INF/), deduplicated
    across the whole package. Bounded and fail-closed like the entropy walk:
    a capped member scan, one aggregate read budget, and an unreadable member
    contributes nothing.
    """
    found: dict[str, None] = {}
    budget = _URL_SCAN_BUDGET
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:_APK_MAX_PAYLOAD_MEMBERS]:
                if budget <= 0:
                    break
                if info.is_dir():
                    continue
                try:
                    with archive.open(info) as member:
                        budget -= _scan_urls(member, found, budget)
                except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
                    continue
    except (OSError, zipfile.BadZipFile):
        return _url_facts({})
    return _url_facts(found)


def _apk_signature_schemes(path: Path) -> tuple[bool, bool, list[dict[str, Any]]]:
    """Return ``(signed_v2, signed_v3, signers)`` from the APK Signing Block.

    ``signers`` answers *who* signed the package, not just that someone did:
    one entry per signer per scheme, carrying the SHA-256 of the signing
    certificate's DER bytes -- the same digest ``apksigner verify
    --print-certs`` prints, and the identity Android pins for updates.

    Fail-closed: any structural surprise (a comment, ZIP64, a truncated or
    oversized block) yields ``(False, False, [])`` so this cheap identity fact
    never raises on a hostile or unusual archive.
    """
    unsigned: tuple[bool, bool, list[dict[str, Any]]] = (False, False, [])
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            tail_len = min(size, _ZIP_EOCD_MIN + _ZIP_MAX_COMMENT)
            handle.seek(size - tail_len)
            tail = handle.read(tail_len)
            eocd = tail.rfind(_ZIP_EOCD_SIGNATURE)
            if eocd < 0 or eocd + _ZIP_EOCD_MIN > len(tail):
                return unsigned
            comment_len = int.from_bytes(tail[eocd + 20 : eocd + 22], "little")
            if eocd + _ZIP_EOCD_MIN + comment_len != len(tail):
                # The record does not end the file where its comment length
                # says: not the real EOCD (or an archive shape we do not read).
                return unsigned
            cd_size = int.from_bytes(tail[eocd + 12 : eocd + 16], "little")
            cd_offset = int.from_bytes(tail[eocd + 16 : eocd + 20], "little")
            if _ZIP64_SENTINEL in (cd_size, cd_offset):
                return unsigned
            if cd_offset < 24 or cd_offset > size:
                return unsigned
            handle.seek(cd_offset - 16)
            if handle.read(16) != _APK_SIG_BLOCK_MAGIC:
                return unsigned
            handle.seek(cd_offset - 24)
            block_size = int.from_bytes(handle.read(8), "little")
            if not 24 <= block_size <= _APK_SIG_BLOCK_MAX:
                return unsigned
            block_start = cd_offset - 8 - block_size
            if block_start < 0:
                return unsigned
            handle.seek(block_start)
            block = handle.read(block_size + 8)
    except OSError:
        return unsigned
    pairs = _apk_signing_block_pairs(block)
    signed_v2 = _APK_SIG_SCHEME_V2_ID in pairs
    signed_v3 = _APK_SIG_SCHEME_V3_ID in pairs or _APK_SIG_SCHEME_V3_1_ID in pairs
    signers: list[dict[str, Any]] = []
    for scheme, block_id in (("v2", _APK_SIG_SCHEME_V2_ID), ("v3", _APK_SIG_SCHEME_V3_ID)):
        value = pairs.get(block_id)
        if value is not None:
            signers += [
                {"scheme": scheme, "cert_sha256": digest}
                for digest in _apk_signer_cert_digests(value)
            ]
    return (signed_v2, signed_v3, signers)


def _apk_signing_block_pairs(block: bytes) -> dict[int, bytes]:
    """Walk the ID-value pairs of a read APK Signing Block, first ID wins."""
    pairs: dict[int, bytes] = {}
    # block = [uint64 size][pairs...][uint64 size][16-byte magic]; the trailing
    # size + magic are the last 24 bytes and the leading size is the first 8.
    cursor = 8
    end = len(block) - 24
    while cursor + 8 <= end:
        pair_len = int.from_bytes(block[cursor : cursor + 8], "little")
        if pair_len < 4 or cursor + 8 + 4 > len(block):
            break
        pair_id = int.from_bytes(block[cursor + 8 : cursor + 12], "little")
        value_end = min(cursor + 8 + pair_len, end)
        pairs.setdefault(pair_id, block[cursor + 12 : value_end])
        cursor += 8 + pair_len
    return pairs


def _apk_signer_cert_digests(value: bytes) -> list[str]:
    """SHA-256 of each signer's signing certificate in a v2/v3 scheme block.

    Both schemes share the layout down to the certificates (every length a
    uint32-LE): the value is a length-prefixed sequence of signers; a signer
    opens with its signed-data, which opens with the digests sequence and then
    the certificates sequence (v3 appends SDK bounds after both, which this
    walk never reaches). The first certificate is the signing certificate --
    the rest are its chain -- and apksigner's printed SHA-256 digest is over
    exactly these DER bytes, so the two views compare hex for hex.

    Fail-closed and bounded: a truncated or lying length keeps the digests
    already read, and no more than the platform's own signer cap is walked.
    """

    def u32(at: int, limit: int) -> int | None:
        if at + 4 > limit:
            return None
        return int.from_bytes(value[at : at + 4], "little")

    digests: list[str] = []
    signers_len = u32(0, len(value))
    if signers_len is None:
        return digests
    signers_end = min(4 + signers_len, len(value))
    pos = 4
    while pos + 4 <= signers_end and len(digests) < _APK_MAX_SIGNERS:
        signer_len = u32(pos, signers_end)
        if signer_len is None or signer_len <= 0:
            break
        signer_end = min(pos + 4 + signer_len, signers_end)
        # signer -> signed_data -> (digests, certificates, ...).
        signed_data_len = u32(pos + 4, signer_end)
        if signed_data_len is None:
            break
        signed_data_end = min(pos + 8 + signed_data_len, signer_end)
        digests_len = u32(pos + 8, signed_data_end)
        if digests_len is None:
            break
        certs_at = pos + 12 + digests_len
        certs_len = u32(certs_at, signed_data_end)
        if certs_len is not None:
            certs_end = min(certs_at + 4 + certs_len, signed_data_end)
            cert_len = u32(certs_at + 4, certs_end)
            if cert_len is not None and certs_at + 8 + cert_len <= certs_end:
                cert = value[certs_at + 8 : certs_at + 8 + cert_len]
                digests.append(hashlib.sha256(cert).hexdigest())
        pos += 4 + signer_len
    return digests


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
    uses_libraries: list[dict[str, Any]] = []
    debuggable: bool | None = None
    test_only: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext: bool | None = None
    # The custom Application subclass (<application android:name>): it is
    # instantiated before any component runs, so it is Android's code-before-
    # main -- the analogue of an ELF DT_INIT or a Mach-O __mod_init_func, and
    # the classic home of a packer's unpacking stub.
    application_name: str | None = None
    # Launcher (entry-point) detection is a small state machine over the flat
    # element walk: remember the current <activity>'s name, and whether the
    # intent-filter currently open has declared both MAIN and LAUNCHER. Both in
    # one filter marks that activity launchable -- MAIN in one filter and
    # LAUNCHER in another does not, so the pair resets on each intent-filter.
    launcher_activity: str | None = None
    current_activity: str | None = None
    filter_main = False
    filter_launcher = False
    # Exported-component tracking: a component's export status depends on its
    # <intent-filter> children, which appear after its start element, so the
    # open component is only finalized when the next component starts or the
    # walk ends. ``exported`` is the explicit android:exported (None = absent);
    # ``has_filter`` records whether any intent-filter was seen for it.
    exported_components: list[dict[str, Any]] = []
    comp_type: str | None = None
    comp_name: str | None = None
    comp_exported: bool | None = None
    comp_has_filter = False
    # Deep-link tracking rides the same deferred-flush pattern: a filter's
    # ACTION_VIEW and its <data> children can appear in any order, so the open
    # filter's data elements are collected and only judged when the filter
    # closes (the next intent-filter, the next component, or the walk's end).
    deep_links: list[dict[str, Any]] = []
    filter_view = False
    filter_datas: list[dict[str, Any]] = []

    def flush_filter() -> None:
        nonlocal filter_view, filter_datas
        if (
            comp_type in _AXML_DEEP_LINK_TAGS
            and comp_name
            and filter_view
        ):
            for entry in filter_datas:
                # Only a <data> that names a scheme is a URI the activity
                # opens; a mimeType-only element is content-type routing.
                if entry.get("scheme") and len(deep_links) < _AXML_MAX_DEEP_LINKS:
                    deep_links.append({"activity": comp_name, **entry})
        filter_view = False
        filter_datas = []

    def flush_component() -> None:
        nonlocal comp_type, comp_name, comp_exported, comp_has_filter
        flush_filter()
        if comp_type is not None and comp_name:
            # Explicit exported wins; otherwise an intent-filter makes it
            # reachable (the pre-Android-12 implicit default triage assumes).
            is_exported = comp_exported if comp_exported is not None else comp_has_filter
            if is_exported and len(exported_components) < _AXML_MAX_COMPONENTS:
                exported_components.append(
                    {
                        "type": comp_type,
                        "name": comp_name,
                        "has_intent_filter": comp_has_filter,
                    }
                )
        comp_type = comp_name = None
        comp_exported = None
        comp_has_filter = False

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
            elif name == "uses-library" and len(uses_libraries) < _AXML_MAX_USES_LIBRARIES:
                lib = _axml_str(attrs, "name")
                if lib:
                    # android:required defaults to true when the attribute is
                    # absent -- a missing library then blocks install.
                    required = _axml_bool(attrs, "required")
                    uses_libraries.append(
                        {"name": lib, "required": True if required is None else required}
                    )
            elif name == "application":
                if application_name is None:
                    application_name = _axml_str(attrs, "name")
                if debuggable is None:
                    debuggable = _axml_bool(attrs, "debuggable")
                if test_only is None:
                    test_only = _axml_bool(attrs, "testOnly")
                if allow_backup is None:
                    allow_backup = _axml_bool(attrs, "allowBackup")
                if uses_cleartext is None:
                    uses_cleartext = _axml_bool(attrs, "usesCleartextTraffic")
            elif name in _AXML_COMPONENT_TAGS:
                # A new component subtree closes the previous one (components do
                # not nest), then opens this one. Its android:name is the
                # reachable component (an alias too -- that is what gets
                # launched), and android:exported its explicit export status.
                flush_component()
                comp_type = name
                comp_name = _axml_str(attrs, "name")
                comp_exported = _axml_bool(attrs, "exported")
                current_activity = comp_name if name in ("activity", "activity-alias") else None
                filter_main = filter_launcher = False
            elif name == "intent-filter":
                flush_filter()
                comp_has_filter = True
                filter_main = filter_launcher = False
            elif name == "action":
                action = _axml_str(attrs, "name")
                if action == _ANDROID_ACTION_MAIN:
                    filter_main = True
                elif action == _ANDROID_ACTION_VIEW:
                    filter_view = True
            elif name == "category":
                if _axml_str(attrs, "name") == _ANDROID_CATEGORY_LAUNCHER:
                    filter_launcher = True
            elif name == "data" and len(filter_datas) < _AXML_MAX_FILTER_DATAS:
                # One record per <data> element, exactly as declared; the
                # optional URI parts are included only when present.
                entry = {
                    key: _axml_str(attrs, attr)
                    for key, attr in (
                        ("scheme", "scheme"),
                        ("host", "host"),
                        ("path", "path"),
                        ("path_prefix", "pathPrefix"),
                        ("path_pattern", "pathPattern"),
                    )
                    if _axml_str(attrs, attr) is not None
                }
                if entry:
                    filter_datas.append(entry)
            if launcher_activity is None and current_activity and filter_main and filter_launcher:
                launcher_activity = current_activity
        pos += csize
    # The last component subtree has no following start element to close it.
    flush_component()
    facts: dict[str, Any] = {
        "package": package,
        "version_code": version_code,
        "version_name": version_name,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": sorted(set(permissions)),
        # Device shared libraries the app declares it needs (<uses-library>),
        # each with whether it is required -- the manifest-level dependency list,
        # in declaration order. Empty for an app that needs none.
        "uses_libraries": uses_libraries,
        # The custom Application subclass, instantiated before any component
        # runs -- the app's code-before-main, where packers put their stub.
        # None when the manifest names none (the framework default class).
        "application_name": application_name,
        # The launchable activity (entry point), reported as declared in the
        # manifest -- None for a library/service-only APK with no launcher.
        "launcher_activity": launcher_activity,
        # The exported components other apps can reach -- the app's attack
        # surface, in declaration order. Each carries its type, declared name
        # and whether the export comes with an intent-filter. Empty for an app
        # that exposes nothing.
        "exported_components": exported_components,
        # The URIs that open the app: each ACTION_VIEW intent-filter <data>
        # with a scheme, bound to its activity, in declaration order -- the
        # remotely-triggerable subset of the exported surface. Empty for an
        # app that handles no links.
        "deep_links": deep_links,
    }
    # Security-posture flags are reported only when the manifest declares them:
    # their framework defaults are version-dependent, so an explicit value is a
    # fact while absence is not something to guess at.
    if debuggable is not None:
        facts["debuggable"] = debuggable
    if test_only is not None:
        facts["test_only"] = test_only
    if allow_backup is not None:
        facts["allow_backup"] = allow_backup
    if uses_cleartext is not None:
        facts["uses_cleartext_traffic"] = uses_cleartext
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
# The "target_features" custom section (tool-conventions Linking.md, emitted by
# LLVM/clang and rustc) lists the WebAssembly features the module was built
# against: each entry is a one-byte prefix -- '+' used, '-' disallowed, '='
# required -- followed by a feature name (simd128, bulk-memory, atomics, ...).
# The used/required set is the engine capability the module needs to run, so
# it is WASM's minimum-runtime fact -- the analogue of an ELF DT_VERNEED, a
# Mach-O min_os or a .NET target_framework. wasm-objdump -x prints the same
# list, so the WASM gate can cross-check it. Real modules declare well under
# this many; the cap only bounds a hostile section.
_WASM_MAX_FEATURES = 64
_WASM_FEATURE_PREFIXES = {0x2B: "+", 0x2D: "-", 0x3D: "="}
# Executable/container magic worth flagging when it is the initial content of a
# data segment: a WASM module that ships a PE/ELF/DEX/ZIP -- or another WASM --
# in its linear memory is the dropper shape (the module writes the segment out
# and hands it to the host to run). MZ needs a DOS-header-sized head so two
# letters of embedded text cannot read as a Windows executable.
_WASM_PAYLOAD_KINDS: tuple[tuple[bytes, str], ...] = (
    (b"\x00asm", "wasm"),
    (b"\x7fELF", "elf"),
    (b"dex\n", "dex"),
    (b"PK\x03\x04", "zip"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"MZ", "pe"),
)
_WASM_MAX_DATA_SEGMENTS = 4096
_WASM_MAX_DATA_PAYLOADS = 32


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
    export names that identify what the module needs and exposes, the linear
    memory footprint (min/max pages, imported or defined), the start function
    (the entry point run at instantiation), and the debug names (module /
    function) an unstripped build carries, the same way describe_apk does for
    a package.

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
    defined_memories: list[dict[str, Any]] = []
    data_payloads: list[dict[str, Any]] = []
    data_payload_count = 0
    entropy_flags: list[dict[str, Any]] = []
    entropy_count = 0
    producers: dict[str, list[str]] | None = None
    target_features: list[dict[str, Any]] | None = None
    name_facts: dict[str, Any] = {}
    has_start = False
    start_index: int | None = None
    well_formed = True
    pos = 8
    parsed_end = 8  # end of the last fully parsed section (the header at least)
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
            elif section_id == 5:
                defined_memories = _wasm_memories(data, body_start, body_end)
            elif section_id == 11:
                data_payloads, data_payload_count = _wasm_data_payloads(
                    data, body_start, body_end
                )
                entropy_flags, entropy_count = _wasm_high_entropy_segments(
                    data, body_start, body_end
                )
        elif section_id == 8:
            has_start = True
            # The section body is one LEB128 function index. A truncated or
            # empty body keeps has_start (the section exists) but names no
            # function -- the index read must not cross into the next section.
            index, idx_end, ok_start = _read_leb_u32(data, body_start)
            if ok_start and idx_end <= body_end and start_index is None:
                start_index = index
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
                # "target_features" is the module's minimum-runtime fact: the
                # engine features it was built to require (simd128, atomics, ...).
                elif cname == "target_features" and target_features is None:
                    target_features = _wasm_target_features(
                        data, name_pos + name_len, body_end
                    )
        pos = body_end
        parsed_end = body_end
        walked += 1
    # Bytes past the last well-formed section -- the WASM analogue of a PE/ELF
    # overlay. A module is a header plus back-to-back sections, so anything the
    # section walk cannot account for was appended after (or broke) the module
    # the engine sees. Reported only when the whole file was read and the walk
    # stopped on the data, not on its own section cap, so a bounded stop cannot
    # masquerade as appended payload.
    overlay: dict[str, int] | None = None
    if not truncated and walked < _WASM_MAX_SECTIONS and parsed_end < len(data):
        overlay = {"offset": parsed_end, "size": len(data) - parsed_end}
    # The module's whole linear-memory footprint: imported memories (which come
    # first in the index space) then the ones the Memory section defines. Each
    # is min/max pages of 64 KiB, whether the host must supply it or the module
    # ships it -- the WASM analogue of a native segment's size.
    memories: list[dict[str, Any]] = [
        {
            "min": imp["min"],
            "max": imp["max"],
            "shared": imp.get("shared", False),
            "imported": True,
        }
        for imp in imports
        if imp["kind"] == "memory"
    ]
    memories += defined_memories
    # The start function: the module's entry point, run automatically at
    # instantiation before any export is callable -- the WASM analogue of an
    # ELF e_entry or a .NET entry-point token. Reported by index (the only
    # identity the binary format guarantees; the space counts imported
    # functions first) plus the debug name when the name section carries one.
    # The URL census over the module bytes already in hand: literals sit
    # uncompressed in data segments (and import/export names), so one pass
    # over ``data`` is the whole answer.
    url_found: dict[str, None] = {}
    _collect_urls(data, len(data) + 1, url_found)
    start_function: dict[str, Any] | None = None
    if start_index is not None:
        start_function = {"index": start_index}
        start_name = next(
            (
                entry["name"]
                for entry in name_facts.get("function_names", [])
                if entry["index"] == start_index
            ),
            None,
        )
        if start_name:
            start_function["name"] = start_name
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
            "start_function": start_function,
            "memories": memories,
            "custom_sections": custom_sections,
            "producers": producers,
            # The engine features the module requires (target_features custom
            # section): WASM's minimum-runtime fact. None when the section is
            # absent (a build that did not record it); a list otherwise, each
            # entry a feature name and its prefix ('+' used, '=' required,
            # '-' disallowed).
            "target_features": target_features,
            "module_name": name_facts.get("module_name"),
            "function_name_count": name_facts.get("function_name_count"),
            "function_names": name_facts.get("function_names", []),
            "exports": exports,
            "imports": imports,
            # Executable/container magic at the head of a data segment -- a
            # module carrying a PE/ELF/DEX/ZIP (or nested WASM) in its linear
            # memory is the dropper shape. Count is exact; the list is bounded.
            "data_payloads": data_payloads,
            "data_payload_count": data_payload_count,
            # Segments that measure near-random with no magic to explain it --
            # the encrypted-payload shape staged in linear memory that the
            # magic census cannot see. Count exact; the list is bounded.
            "high_entropy_segments": entropy_flags,
            "high_entropy_segment_count": entropy_count,
            # The network endpoints baked into the module -- the URL census,
            # sample bounded, count exact over the parsed bytes.
            **_url_facts(url_found),
            # Data past the last well-formed section: None for a clean module,
            # else {offset, size} of the residue (appended payload or a broken
            # tail -- well_formed says which module the engine would accept).
            "overlay": overlay,
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
# Maps with embedded sources routinely run to tens of megabytes; read that much
# and no more, and refuse (resolved=False) anything larger.
_JS_MAP_MAX_BYTES = 32 * 1024 * 1024


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
    source_map_facts: dict[str, Any] | None = None
    last = None
    for match in _JS_SOURCEMAP_RE.finditer(data):
        last = match
    if last is not None:
        url = last.group(1).decode("utf-8", errors="replace")
        if url.startswith("data:"):
            source_map_inline = True
        else:
            source_map = url[:_JS_SOURCEMAP_MAX]
        source_map_facts = _js_source_map_facts(path.parent, url)
    return {
        "js": {
            "size": size,
            "line_count": line_count,
            "max_line_length": max_line_length,
            "source_map": source_map,
            "source_map_inline": source_map_inline,
            # What the referenced map actually delivers -- above all whether
            # the original sources ship inside it (the source-recovery prize).
            "source_map_facts": source_map_facts,
            "truncated": truncated,
        }
    }


def _js_source_map_facts(base: Path, url: str) -> dict[str, Any]:
    """What the sourceMappingURL actually delivers, or resolved=False.

    A map directive is only a claim; the prize is the map itself -- and above
    all whether the original sources travel inside it (``sourcesContent``), the
    difference between recovering the pre-minification codebase outright and
    merely getting file names and line numbers. An inline ``data:`` URI is
    decoded in place; an external reference is read next to the script under
    the same containment rules the SRI verdict uses (plain relative path, no
    escape from the directory tree, bounded size). Everything else -- a remote
    URL, a missing or oversized file, malformed JSON -- is ``resolved: False``,
    never a guess: the claim exists but nothing local backs it.
    """
    if url.startswith("data:"):
        facts: dict[str, Any] = {"kind": "inline"}
        payload = _js_data_uri_bytes(url)
    else:
        facts = {"kind": "external"}
        payload = _js_local_map_bytes(base, url)
    doc: Any = None
    if payload is not None:
        try:
            doc = json.loads(payload)
        except ValueError:
            doc = None
    if not isinstance(doc, dict):
        facts["resolved"] = False
        return facts
    facts["resolved"] = True
    version = doc.get("version")
    facts["version"] = version if isinstance(version, int) else None
    raw_sources = doc.get("sources")
    sources = raw_sources if isinstance(raw_sources, list) else []
    facts["sources_count"] = len(sources)
    raw_contents = doc.get("sourcesContent")
    contents = raw_contents if isinstance(raw_contents, list) else []
    embedded = sum(1 for item in contents if isinstance(item, str))
    if sources and embedded >= len(sources):
        facts["sources_content"] = "embedded"
    elif embedded:
        facts["sources_content"] = "partial"
    else:
        facts["sources_content"] = "absent"
    raw_names = doc.get("names")
    facts["names_count"] = len(raw_names) if isinstance(raw_names, list) else 0
    mappings = doc.get("mappings")
    facts["mappings"] = isinstance(mappings, str) and bool(mappings)
    return facts


def _js_data_uri_bytes(url: str) -> bytes | None:
    """Decode a data: URI's payload (base64 or percent-encoded), bounded."""
    header, _, payload = url.partition(",")
    if not payload or len(payload) > _JS_MAP_MAX_BYTES:
        return None
    if header.rsplit(";", 1)[-1].lower() == "base64":
        try:
            return base64.b64decode(payload, validate=True)
        except ValueError:
            return None
    return unquote_to_bytes(payload)


def _js_local_map_bytes(base: Path, url: str) -> bytes | None:
    """Read the map file an external reference names, under containment rules.

    Only a plain relative path into the script's own directory tree is read --
    the layout a captured site or an extracted bundle has on disk. A query
    string or fragment on the reference (cache busters) is ignored, the same
    way a server would.
    """
    parts = urlsplit(url)
    if parts.scheme or parts.netloc or not parts.path or parts.path.startswith("/"):
        return None
    try:
        candidate = (base / parts.path).resolve()
        if not candidate.is_relative_to(base.resolve()):
            return None
        if not candidate.is_file() or candidate.stat().st_size > _JS_MAP_MAX_BYTES:
            return None
        return candidate.read_bytes()
    except OSError:
        return None


_HAR_MAX_BYTES = 64 * 1024 * 1024
_HAR_MAX_ENTRIES = 200_000
# Distinct hosts are a strong "what did this capture touch" fact; list a bounded
# sample and always report the true count alongside it.
_HAR_MAX_HOSTS = 64
# Executable and container magic at the start of a decoded body. Every prefix
# is 4+ bytes except MZ, which additionally requires a DOS-header-sized body so
# prose that merely opens with the letters cannot read as an executable.
_HAR_MAGIC_KINDS: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"\x00asm", "wasm"),
    (b"PK\x03\x04", "zip"),
    (b"dex\n", "dex"),
    (b"\x1f\x8b", "gzip"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xfe\xed\xfa\xce", "macho"),
    # CAFEBABE opens both a fat Mach-O and a Java class file; one honest name.
    (b"\xca\xfe\xba\xbe", "java_class_or_fat_macho"),
    (b"MZ", "pe"),
)
# MIME types whose bodies a browser treats as text: binary executable bytes
# under one of these claims is the smuggling shape worth flagging.
_HAR_TEXTY_MIMES = frozenset(
    {
        "application/javascript",
        "application/x-javascript",
        "application/json",
        "application/xml",
        "image/svg+xml",
    }
)
_HAR_MAX_MASQUERADES = 32
_HAR_MAX_URL = 512


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
    # Capture-completeness tallies: how many responses declare a body, and of
    # those, how many actually carry it, how many were stripped, and how many
    # carry a body whose length disagrees with the declared size.
    responses_with_body = 0
    bodies_captured = 0
    bodies_stripped = 0
    bodies_size_mismatch = 0
    # The same completeness question for what the client uploaded: how many
    # requests carried a body (POST/PUT payloads), and whether the capture
    # kept it, scrubbed it, or truncated it.
    requests_with_body = 0
    request_bodies_captured = 0
    request_bodies_stripped = 0
    request_bodies_size_mismatch = 0
    # Bodies whose bytes open with executable/container magic while the
    # declared mimeType claims text -- the drive-by / smuggling shape.
    masquerade_count = 0
    masquerades: list[dict[str, Any]] = []
    truncated = len(entries) > _HAR_MAX_ENTRIES
    for entry in entries[:_HAR_MAX_ENTRIES]:
        if not isinstance(entry, dict):
            continue
        entry_url: str | None = None
        request = entry.get("request")
        if isinstance(request, dict):
            method = request.get("method")
            if isinstance(method, str) and method:
                methods[method.upper()] = methods.get(method.upper(), 0) + 1
            url = request.get("url")
            if isinstance(url, str):
                entry_url = url
                host = urlsplit(url).hostname
                if host:
                    hosts.add(host)
            body_size = request.get("bodySize")
            if isinstance(body_size, int) and body_size > 0:
                requests_with_body += 1
                measured = _har_postdata_length(request.get("postData"))
                if measured is None:
                    request_bodies_stripped += 1
                else:
                    request_bodies_captured += 1
                    if measured != body_size:
                        request_bodies_size_mismatch += 1
        response = entry.get("response")
        if isinstance(response, dict):
            status = response.get("status")
            if isinstance(status, int) and 100 <= status <= 599:
                status_classes[f"{status // 100}xx"] = (
                    status_classes.get(f"{status // 100}xx", 0) + 1
                )
            content = response.get("content")
            if isinstance(content, dict) and isinstance(content.get("size"), int):
                size = content["size"]
                total_response_bytes += max(size, 0)
                if size > 0:
                    responses_with_body += 1
                    measured = _har_body_length(content)
                    if measured is None:
                        bodies_stripped += 1
                    else:
                        bodies_captured += 1
                        if measured != size:
                            bodies_size_mismatch += 1
            if isinstance(content, dict):
                mime = content.get("mimeType")
                if isinstance(mime, str) and mime and _har_texty_mime(mime):
                    body = _har_body_bytes(content)
                    kind = _har_sniff_kind(body) if body is not None else None
                    if kind is not None:
                        masquerade_count += 1
                        if len(masquerades) < _HAR_MAX_MASQUERADES:
                            masquerades.append(
                                {
                                    "url": (entry_url or "")[:_HAR_MAX_URL],
                                    "mime_type": mime[:128],
                                    "sniffed": kind,
                                }
                            )
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
            # Is this capture whole, or a body-stripped/truncated copy? For
            # every response declaring a non-empty body: bodies_captured carry
            # one whose decoded length matches content.size, bodies_stripped
            # declare a size but ship no text (the privacy-scrubbed share),
            # and bodies_size_mismatch ship text whose length disagrees (a
            # truncated or re-encoded capture). All zero but responses_with_body
            # positive means a size-only export like this project's own.
            "body_integrity": {
                "responses_with_body": responses_with_body,
                "bodies_captured": bodies_captured,
                "bodies_stripped": bodies_stripped,
                "bodies_size_mismatch": bodies_size_mismatch,
            },
            # The same verdict for uploaded bodies (POST/PUT payloads),
            # keyed off request.bodySize vs postData.text: a capture may keep
            # every response yet scrub the credentials a login POSTed.
            "request_body_integrity": {
                "requests_with_body": requests_with_body,
                "bodies_captured": request_bodies_captured,
                "bodies_stripped": request_bodies_stripped,
                "bodies_size_mismatch": request_bodies_size_mismatch,
            },
            # Responses whose captured bytes open with executable or container
            # magic while the declared mimeType claims text -- a PE behind
            # text/html is the drive-by / HTML-smuggling shape. The count is
            # exact; the listed sample is bounded.
            "mime_masquerade_count": masquerade_count,
            "mime_masquerades": masquerades,
            "truncated": truncated,
        }
    }


def _har_texty_mime(mime: str) -> bool:
    """True when the declared type claims a body a browser renders as text."""
    base = mime.split(";", 1)[0].strip().lower()
    return base.startswith("text/") or base in _HAR_TEXTY_MIMES


def _har_body_bytes(content: dict[str, Any]) -> bytes | None:
    """The decoded response body bytes, or None when absent or undecodable.

    Unlike :func:`_har_body_length` (whose -1 keeps corrupt base64 visible to
    the integrity tally), a body that does not decode yields None here: magic
    sniffing needs real bytes, and a guess would be worse than silence.
    """
    text = content.get("text")
    if not isinstance(text, str) or text == "":
        return None
    encoding = content.get("encoding")
    if isinstance(encoding, str) and encoding.lower() == "base64":
        try:
            return base64.b64decode(text, validate=True)
        except ValueError:
            return None
    return text.encode("utf-8")


def _har_sniff_kind(data: bytes) -> str | None:
    """The executable/container format the body's opening bytes declare.

    MZ alone is two letters of prose; a real DOS/PE header is at least 0x40
    bytes, so shorter bodies never read as ``pe``.
    """
    for magic, kind in _HAR_MAGIC_KINDS:
        if data.startswith(magic):
            if kind == "pe" and len(data) < 0x40:
                return None
            return kind
    return None


def _har_body_length(content: dict[str, Any]) -> int | None:
    """The decoded byte length of a HAR response body, or None when absent.

    Per HAR 1.2, ``content.text`` is the response body and ``content.size`` its
    length in bytes; a ``base64`` ``encoding`` means text is the base64 of the
    raw bytes, otherwise it is the decoded text whose UTF-8 length is the byte
    count the size claims. Returns the measured length so the caller can compare
    it with the declared size, None when no body text is present (the stripped
    case), and -1 for a body that claims base64 but does not decode -- a corrupt
    capture that can equal no honest size.
    """
    text = content.get("text")
    if not isinstance(text, str) or text == "":
        return None
    encoding = content.get("encoding")
    if isinstance(encoding, str) and encoding.lower() == "base64":
        try:
            return len(base64.b64decode(text, validate=True))
        except ValueError:
            return -1
    return len(text.encode("utf-8"))


def _har_postdata_length(post_data: Any) -> int | None:
    """The decoded byte length of a HAR request body, or None when absent.

    The request analogue of :func:`_har_body_length`: ``request.postData.text``
    is the uploaded body and ``request.bodySize`` its byte length, so a real
    browser records both for a POST. Returns the measured length (base64 when
    ``postData.encoding`` says so, else the UTF-8 byte count) to compare with
    bodySize, None when the size is declared but no text was kept (the scrubbed
    credential case), and -1 for base64 that does not decode.
    """
    if not isinstance(post_data, dict):
        return None
    text = post_data.get("text")
    if not isinstance(text, str) or text == "":
        return None
    encoding = post_data.get("encoding")
    if isinstance(encoding, str) and encoding.lower() == "base64":
        try:
            return len(base64.b64decode(text, validate=True))
        except ValueError:
            return -1
    return len(text.encode("utf-8"))


_HTML_SUFFIXES = frozenset({".html", ".htm"})
_HTML_MAX_BYTES = 16 * 1024 * 1024
# Cap the recorded script/host lists (and the title) so a page with thousands
# of tags cannot make the identity facts large; the totals are always exact.
_HTML_MAX_ITEMS = 256
_HTML_MAX_TITLE = 256
# The tags that contribute a named field to the form they sit in. <button>
# is excluded: it submits, it is not data the page collects.
_HTML_FIELD_TAGS = frozenset({"input", "textarea", "select"})
# The digest algorithms Subresource Integrity defines (W3C SRI); anything else
# in an integrity token is unknown to browsers too and stays unverified.
_SRI_ALGORITHMS: dict[str, Callable[..., Any]] = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


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
        self.form_total = 0
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self.sri_total = 0
        self.sri: list[dict[str, Any]] = []

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
                self._add_sri("script", src, attr.get("integrity"))
            else:
                self.inline_script_total += 1
        elif tag == "link":
            if "stylesheet" in (attr.get("rel") or "").lower():
                self.stylesheet_total += 1
                href = attr.get("href")
                self._add_host(href)
                if href:
                    self._add_sri("stylesheet", href, attr.get("integrity"))
        elif tag == "iframe":
            self.iframe_total += 1
            self._add_host(attr.get("src"))
        elif tag == "form":
            # Where the page sends what it collects -- the submit surface. The
            # method defaults to GET exactly as a browser submits it, and a
            # cross-origin action is a host the page reaches like any other.
            self.form_total += 1
            form: dict[str, Any] = {
                "action": attr.get("action"),
                "method": (attr.get("method") or "get").strip().lower(),
                "input_names": [],
            }
            self._add_host(attr.get("action"))
            if len(self.forms) < _HTML_MAX_ITEMS:
                self.forms.append(form)
                self._form = form
            else:
                self._form = None
        elif tag in _HTML_FIELD_TAGS and self._form is not None:
            # Only named fields are submitted, so only they identify the form.
            name = attr.get("name")
            if name and len(self._form["input_names"]) < _HTML_MAX_ITEMS:
                self._form["input_names"].append(name)
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

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

    def _add_sri(self, tag: str, url: str, integrity: str | None) -> None:
        """Record each Subresource Integrity token pinned on a loaded resource.

        The attribute is a whitespace-separated token list (a browser accepts
        the resource if any token of the strongest algorithm matches); one
        entry per token keeps every pin auditable on its own.
        """
        if not integrity:
            return
        for token in integrity.split():
            self.sri_total += 1
            if len(self.sri) < _HTML_MAX_ITEMS:
                self.sri.append({"tag": tag, "url": url, "integrity": token})


def describe_html(path: Path) -> dict[str, Any]:
    """Cheap, stdlib-only facts about an HTML page (no browser).

    Where a page loads its code from is the first thing a web reverser maps:
    how many scripts it pulls, how many are external versus inline, which hosts
    those and its stylesheets and iframes reach, the forms it submits (action,
    method and the named fields it collects), and the page title. stdlib
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
    for entry in parser.sri:
        entry["ok"] = _sri_verdict(path.parent, entry["url"], entry["integrity"])
    return {
        "html": {
            "title": parser.title,
            "script_count": parser.script_total,
            "external_script_count": parser.external_script_total,
            "inline_script_count": parser.inline_script_total,
            "external_scripts": parser.external_scripts,
            "stylesheet_count": parser.stylesheet_total,
            "iframe_count": parser.iframe_total,
            "form_count": parser.form_total,
            "forms": parser.forms,
            # The page's integrity pins: one entry per SRI token on a script
            # or stylesheet, with the verdict of recomputing the digest over
            # the local file the URL names -- True (the pin matches, the
            # browser would load it), False (it would refuse: the asset was
            # modified after the pin, or vice versa), or None when the asset
            # is not a file next to the page (a remote URL, a missing or
            # out-of-tree path) or the token is not one a browser accepts.
            "sri_count": parser.sri_total,
            "sri": parser.sri,
            "external_host_count": len(parser.hosts),
            "external_hosts": sorted(parser.hosts)[:_HTML_MAX_ITEMS],
            "truncated": size > _HTML_MAX_BYTES,
        }
    }


def _sri_verdict(base: Path, url: str, token: str) -> bool | None:
    """Recompute one Subresource Integrity pin against the file it names.

    A True/False verdict needs the same two things a browser needs: a token it
    understands (a W3C SRI algorithm, a well-formed base64 digest of that
    algorithm's size) and the resource bytes. The bytes are only at hand when
    the URL is a plain relative path naming a file inside the page's own
    directory tree -- the captured-site layout. Anything else (an absolute or
    root-relative URL, a traversal escaping the tree, a missing or oversized
    file, an alien token) is None: unverified, never guessed. False is the
    load a browser would block -- the asset next to the page no longer matches
    the hash the page pins.
    """
    algorithm, _, encoded = token.partition("-")
    digest_fn = _SRI_ALGORITHMS.get(algorithm.lower())
    if digest_fn is None or not encoded:
        return None
    try:
        # A token may carry ?options after the digest, per the SRI grammar.
        expected = base64.b64decode(encoded.split("?", 1)[0], validate=True)
    except ValueError:
        return None
    if len(expected) != digest_fn().digest_size:
        return None
    parts = urlsplit(url)
    if parts.scheme or parts.netloc or not parts.path or parts.path.startswith("/"):
        return None
    try:
        candidate = (base / parts.path).resolve()
        if not candidate.is_relative_to(base.resolve()):
            return None
        if not candidate.is_file() or candidate.stat().st_size > _HTML_MAX_BYTES:
            return None
        data = candidate.read_bytes()
    except OSError:
        return None
    digest: bytes = digest_fn(data).digest()
    return digest == expected


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


def _wasm_target_features(data: bytes, pos: int, body_end: int) -> list[dict[str, Any]]:
    """The [prefix, feature] entries from a target_features custom section.

    The layout (tool-conventions Linking.md) is a vector of entries, each a
    one-byte prefix ('+' used, '-' disallowed, '=' required) followed by a
    feature name -- the WebAssembly features the module was built against, so
    the used/required set is the engine capability it needs to run. Bounded and
    fail-closed like the producers reader: caps on the entry count and name
    length, an unknown prefix or a malformed tail stops the walk with what
    parsed cleanly rather than raising.
    """
    count, pos, ok = _read_leb_u32(data, pos)
    if not ok:
        return []
    out: list[dict[str, Any]] = []
    for _ in range(min(count, _WASM_MAX_FEATURES)):
        if pos >= body_end:
            break
        prefix = _WASM_FEATURE_PREFIXES.get(data[pos])
        name, pos = _read_wasm_name(data, pos + 1)
        if prefix is None or name is None or pos > body_end:
            break
        out.append({"feature": name[:_WASM_MAX_PRODUCER_CHARS], "prefix": prefix})
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
        entry: dict[str, Any] = {
            "module": module,
            "name": field,
            "kind": _WASM_EXTERNAL_KINDS.get(kind, f"kind_{kind}"),
        }
        if kind == 2:  # an imported memory carries its own size limits
            minimum, maximum, shared, pos, ok = _read_wasm_limits(data, pos + 1, body_end)
            entry["min"] = minimum
            entry["max"] = maximum
            entry["shared"] = shared
        else:
            pos, ok = _skip_wasm_import_desc(data, pos + 1, kind, body_end)
        out.append(entry)
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
        _, _, _, pos, ok = _read_wasm_limits(data, pos, body_end)
        return pos, ok
    if kind == 2:  # memory: limits
        _, _, _, pos, ok = _read_wasm_limits(data, pos, body_end)
        return pos, ok
    return pos, False


def _wasm_memories(data: bytes, body_start: int, body_end: int) -> list[dict[str, Any]]:
    """Limits of each memory the Memory section (id 5) defines."""
    count, pos, ok = _read_leb_u32(data, body_start)
    if not ok:
        return []
    out: list[dict[str, Any]] = []
    for _ in range(min(count, _WASM_MAX_NAMES)):
        minimum, maximum, shared, pos, ok = _read_wasm_limits(data, pos, body_end)
        if not ok or pos > body_end:
            break
        out.append({"min": minimum, "max": maximum, "shared": shared, "imported": False})
    return out


def _wasm_data_segments(data: bytes, body_start: int, body_end: int) -> list[tuple[int, int, int]]:
    """``(index, payload offset, payload length)`` per data segment (section 11).

    Each segment is a mode flag, an optional memory index and offset
    expression (for the active modes), then a vector of raw bytes -- the
    initial contents of linear memory. The shared walk under the payload and
    entropy censuses: bounded, and a malformed segment stops the walk
    (returning what parsed cleanly) rather than raising.
    """
    count, pos, ok = _read_leb_u32(data, body_start)
    if not ok:
        return []
    segments: list[tuple[int, int, int]] = []
    for index in range(min(count, _WASM_MAX_DATA_SEGMENTS)):
        if pos >= body_end:
            break
        flag, pos, ok = _read_leb_u32(data, pos)
        if not ok:
            break
        # flag bit 0: passive (no offset expr); bit 1: explicit memory index.
        if flag & 0x02:
            _memidx, pos, ok = _read_leb_u32(data, pos)
            if not ok:
                break
        if not flag & 0x01:  # active: skip the constant offset expression
            pos, ok = _wasm_skip_const_expr(data, pos, body_end)
            if not ok:
                break
        seg_len, pos, ok = _read_leb_u32(data, pos)
        if not ok or pos + seg_len > body_end:
            break
        segments.append((index, pos, seg_len))
        pos += seg_len
    return segments


def _wasm_data_payloads(
    data: bytes, body_start: int, body_end: int
) -> tuple[list[dict[str, Any]], int]:
    """Data segments (section 11) whose bytes open with executable magic.

    A segment whose bytes begin with a PE/ELF/DEX/ZIP (or nested WASM) magic
    is the dropper payload the module would write out and run: this lists
    segment index, kind and byte length. The reported list is capped; the
    count is exact over the walked segments.
    """
    payloads: list[dict[str, Any]] = []
    found = 0
    for index, offset, seg_len in _wasm_data_segments(data, body_start, body_end):
        head = data[offset : offset + min(seg_len, 0x40)]
        kind = next((k for magic, k in _WASM_PAYLOAD_KINDS if head.startswith(magic)), None)
        if kind == "pe" and len(head) < 0x40:
            kind = None
        if kind is None:
            continue
        found += 1
        if len(payloads) < _WASM_MAX_DATA_PAYLOADS:
            payloads.append({"segment": index, "kind": kind, "size": seg_len})
    return payloads, found


def _wasm_high_entropy_segments(
    data: bytes, body_start: int, body_end: int
) -> tuple[list[dict[str, Any]], int]:
    """Data segments whose bytes measure near-random with no magic.

    The WASM arm of the entropy census: an encrypted or compressed payload
    staged in linear memory (for the module to inflate and hand to the host)
    opens with no magic at all, so only the Shannon measure gives it away.
    Segments whose head self-declares route to their own census instead --
    executables to the payload census, media to nothing (an emscripten
    ``--embed-file`` asset is near-random by design and says so). Bounds are
    the shared census ones: a size floor, a per-segment read cap, an exact
    count with a capped list.
    """
    flagged: list[dict[str, Any]] = []
    count = 0
    for index, offset, seg_len in _wasm_data_segments(data, body_start, body_end):
        if seg_len < _ENTROPY_MIN_SIZE:
            continue
        if _self_declaring_magic(data[offset : offset + 0x40]):
            continue
        entropy = _shannon_entropy(data[offset : offset + min(seg_len, _ENTROPY_MAX_READ)])
        if entropy >= _ENTROPY_THRESHOLD:
            count += 1
            if len(flagged) < _ENTROPY_MAX_FLAGGED:
                flagged.append({"segment": index, "entropy": round(entropy, 2), "size": seg_len})
    return flagged, count


def _wasm_skip_const_expr(data: bytes, pos: int, body_end: int) -> tuple[int, bool]:
    """Skip a WASM constant expression, returning ``(pos_after_end, ok)``.

    A data segment's offset is a constant expression terminated by the ``end``
    opcode (0x0B). Only the handful of instructions a constant expression may
    contain are decoded -- the numeric consts, ``global.get`` and the reference
    consts -- so the walk lands exactly on the byte after ``end`` and never
    mistakes payload bytes for the terminator.
    """
    steps = 0
    while pos < body_end and steps < 64:
        opcode = data[pos]
        pos += 1
        steps += 1
        if opcode == 0x0B:  # end
            return pos, True
        if opcode in (0x41, 0x42):  # i32.const / i64.const: signed LEB
            _value, pos, ok = _read_leb_s64(data, pos, body_end)
            if not ok:
                return pos, False
        elif opcode == 0x43:  # f32.const
            pos += 4
        elif opcode == 0x44:  # f64.const
            pos += 8
        elif opcode in (0x23, 0xD2):  # global.get / ref.func: u32 LEB
            _value, pos, ok = _read_leb_u32(data, pos)
            if not ok:
                return pos, False
        elif opcode == 0xD0:  # ref.null: one heap-type byte
            pos += 1
        else:
            # An opcode a constant expression should not carry: bail rather
            # than guess where the expression ends.
            return pos, False
    return pos, False


def _read_leb_s64(data: bytes, pos: int, body_end: int) -> tuple[int, int, bool]:
    """Read a signed LEB128 (max 10 bytes) -> (value, next_pos, ok)."""
    result = 0
    shift = 0
    for _ in range(10):
        if pos >= body_end:
            return (0, pos, False)
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:  # sign-extend
                result |= -(1 << shift)
            return (result, pos, True)
    return (0, pos, False)


def _read_wasm_limits(
    data: bytes, pos: int, body_end: int
) -> tuple[int | None, int | None, bool, int, bool]:
    """Decode a WASM ``limits`` into ``(min, max, shared, pos, ok)``.

    A limits is a flag byte then a minimum, with a maximum only when the flag's
    low bit is set; the second bit marks a shared (threads) memory. This is how
    both a memory/table import descriptor and the defined memory/table sections
    encode their sizes, so one reader serves both.
    """
    if pos >= body_end:
        return None, None, False, pos, False
    flag = data[pos]
    minimum, pos, ok = _read_leb_u32(data, pos + 1)
    maximum: int | None = None
    if ok and flag & 0x01:  # a maximum follows
        maximum, pos, ok = _read_leb_u32(data, pos)
    return (minimum if ok else None), maximum, bool(flag & 0x02), pos, ok


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
# The security data directory (IMAGE_DIRECTORY_ENTRY_SECURITY). Unlike every
# other directory its first field is a *file offset*, not an RVA, to the
# WIN_CERTIFICATE table that carries the Authenticode PKCS#7 blob at the file
# tail. wCertificateType 0x0002 is WIN_CERT_TYPE_PKCS_SIGNED_DATA (Authenticode).
_PE_SECURITY_DIR = 4
_WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
_WIN_CERT_TYPES = {
    0x0001: "x509",
    0x0002: "pkcs_signed_data",
    0x0003: "reserved_1",
    0x0004: "ts_stack_signed",
}
_PE_MAX_SECTIONS = 96
# The resource data directory (index 2) roots a tree a Windows dropper hides
# stage two in -- a nested PE in an RT_RCDATA blob, released and run at
# runtime. These bound the walk of a hostile or malformed tree.
_PE_RESOURCE_DIR = 2
_PE_RES_MAX_DEPTH = 8
_PE_RES_MAX_ENTRIES = 8192
_PE_RES_MAX_PAYLOADS = 64
_PE_RES_MAX_TREE = 32 * 1024 * 1024
# The RT_VERSION resource (type 16) carries VS_VERSIONINFO -- the PE's
# self-declared identity: the numeric file/product versions and the
# CompanyName/ProductName/OriginalFilename strings Explorer shows and malware
# routinely fakes. The pair to an APK's package identity, a .NET assembly
# version and an ELF/Mach-O soname/install_name.
_PE_RT_VERSION = 16
_VS_FIXED_SIG = 0xFEEF04BD
_VS_FIXED_SIZE = 52
_PE_MAX_VERSION_BLOB = 64 * 1024
_PE_MAX_VERSION_STRINGS = 32
_PE_MAX_VERSION_CHARS = 256
# The Rich header: MSVC's XOR-masked toolchain census between the DOS stub and
# the PE header (DanS ^ key, three masked zeros, (comp.id ^ key, count ^ key)
# pairs, "Rich", key). Each comp.id is a product id (high word) and build
# number (low word) -- the PE toolchain provenance, the pair to an ELF
# .comment, a Mach-O build-tool entry and the WASM producers section. Only
# MSVC-family linkers write it; pefile's parse_rich_header referees the gate.
_PE_RICH_MARKER = b"Rich"
_PE_DANS = 0x536E6144  # 'DanS' as a little-endian dword
_PE_MAX_RICH_ENTRIES = 64
_PE_MAX_RICH_SCAN = 0x1000
# Section characteristics carrying both write and execute: the PE W^X
# violation, the pair to a RWE PT_LOAD and a rwx Mach-O segment -- the shape a
# packer's unpack-into section (UPX0) takes and no stock toolchain emits.
# pefile exposes the same Characteristics field, so it referees the gate.
_PE_SCN_MEM_EXECUTE = 0x2000_0000
_PE_SCN_MEM_WRITE = 0x8000_0000
_PE_RES_MAX_NAME = 128
# The standard RT_* resource type ids, so a flagged payload names the resource
# it hid in (RT_RCDATA is the dropper's usual choice, but a PE in a "bitmap" is
# just as much a lie).
_PE_RESOURCE_TYPES = {
    1: "cursor",
    2: "bitmap",
    3: "icon",
    4: "menu",
    5: "dialog",
    6: "string",
    7: "fontdir",
    8: "font",
    9: "accelerator",
    10: "rcdata",
    11: "messagetable",
    12: "group_cursor",
    14: "group_icon",
    16: "version",
    17: "dlginclude",
    19: "plugplay",
    20: "vxd",
    21: "anicursor",
    22: "aniicon",
    23: "html",
    24: "manifest",
}
# Executable/container magic worth flagging as the head of a resource blob.
# MZ needs a DOS-header-sized head so a two-byte coincidence is not a PE.
_PE_RESOURCE_KINDS: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"dex\n", "dex"),
    (b"PK\x03\x04", "zip"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"MZ", "pe"),
)
# The import (index 1) and export (index 0) data directories -- the native PE
# capability surface, the pair to an ELF/Mach-O's imported/exported symbols. The
# import table names which functions from which DLLs the loader must resolve
# (the strongest triage signal after arch: what the binary can actually do); the
# export table names what a DLL offers. Both walks are bounded so a hostile or
# malformed table degrades to shorter lists rather than an unbounded read.
_PE_IMPORT_DIR = 1
_PE_EXPORT_DIR = 0
_PE_MAX_IMPORT_DLLS = 256
_PE_MAX_IMPORTS_PER_DLL = 4096
_PE_MAX_EXPORTS = 8192
_PE_MAX_SYMBOL_NAME = 512
_PE_MAX_IMPORT_FILE = 128 * 1024 * 1024
# The debug data directory (index 6) carries the CodeView RSDS record -- the
# native PE build fingerprint, the pair to an ELF build-id and a Mach-O UUID:
# a per-build PDB GUID plus age (together the symbol-server key) and the PDB
# path the linker baked in, which routinely leaks user and project names.
_PE_DEBUG_DIR = 6
_PE_DEBUG_ENTRY_SIZE = 28
_PE_MAX_DEBUG_ENTRIES = 32
_PE_DEBUG_TYPE_CODEVIEW = 2
# RSDS sig (4) + GUID (16) + age (4) + at least a NUL for the path, up to a
# bounded path length.
_PE_MIN_RSDS = 25
_PE_MAX_RSDS = 1024 + 24
# The TLS data directory (index 9) carries the PE's code-before-main: the
# loader runs every AddressOfCallBacks entry before the entry point -- the pair
# to an ELF DT_INIT_ARRAY and a Mach-O __mod_init_func section, and the classic
# home for a packer's anti-debug checks. The callback walk is bounded so a
# hostile array degrades to a shorter count rather than an unbounded read.
_PE_TLS_DIR = 9
_PE_MAX_TLS_CALLBACKS = 64
# Subsystem and DllCharacteristics sit at the same optional-header offsets for
# PE32 and PE32+ (the layouts only diverge at ImageBase and the tail); together
# they are the native PE build posture -- the pair to ELF nx/relro/canary/pie
# and Mach-O nx/pie. The DllCharacteristics bits are the loader mitigation
# contract that winchecksec and `dumpbin /headers` decode.
_PE_ENTRY_RVA_OFF = 16
# MajorOperatingSystemVersion/MinorOperatingSystemVersion and the subsystem
# version pair: the minimum Windows the image declares it needs -- the PE
# minimum-runtime fact, the pair to Mach-O's min_os, the ELF ABI-tag
# min_kernel and an APK's min_sdk. The loader actually enforces the subsystem
# pair, so malware lying here bricks itself; pefile reads the same fields.
_PE_OS_VERSION_OFF = 40
_PE_SUBSYS_VERSION_OFF = 48
_PE_SUBSYSTEM_OFF = 68
_PE_DLLCHARACTERISTICS_OFF = 70
_PE_SUBSYSTEMS = {
    0: "unknown",
    1: "native",
    2: "gui",
    3: "console",
    5: "os2_console",
    7: "posix_console",
    8: "native_win9x",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
    13: "efi_rom",
    14: "xbox",
    16: "windows_boot_application",
}
_PE_DLL_MITIGATIONS: tuple[tuple[int, str], ...] = (
    (0x0020, "high_entropy_va"),  # HIGH_ENTROPY_VA: 64-bit ASLR entropy
    (0x0040, "aslr"),  # DYNAMICBASE: image can be rebased at load
    (0x0080, "force_integrity"),  # FORCE_INTEGRITY: signature enforced at load
    (0x0100, "nx"),  # NX_COMPAT: DEP-compatible
    (0x0400, "no_seh"),  # NO_SEH: image uses no structured exception handlers
    (0x1000, "appcontainer"),  # APPCONTAINER: must run in an AppContainer
    (0x4000, "cfg"),  # GUARD_CF: Control Flow Guard instrumented
)
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


def _pe_authenticode(path: Path) -> dict[str, Any] | None:
    """Whether a PE carries an embedded Authenticode signature, and its range.

    The Windows analogue of the Mach-O code-signature and APK-signer facts:
    the first triage question for a Windows binary is *is it signed*, answered
    tool-free from the security data directory. That directory (index 4) is
    unique -- its first field is a file offset, not an RVA, to the
    WIN_CERTIFICATE table appended at the file tail -- so no section mapping is
    needed. Reports whether a signature is present, where it sits
    (offset/size), the certificate type (Authenticode is pkcs_signed_data) and
    revision, and whether the declared blob actually fits the file, which a
    truncated or lying directory would fail.

    Returns None only for a non-PE or an unreadable header, so a valid PE
    always gets a verdict -- ``{"signed": False}`` for the common unsigned
    case, distinct from metadata a native reader never produced.
    """
    try:
        with path.open("rb") as stream:
            dos = stream.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return None
            stream.seek(int.from_bytes(dos[0x3C:0x40], "little"))
            coff = stream.read(24)
            if len(coff) < 24 or coff[:4] != b"PE\x00\x00":
                return None
            optional = stream.read(int.from_bytes(coff[20:22], "little"))
            magic = int.from_bytes(optional[0:2], "little") if len(optional) >= 2 else 0
            if magic == 0x10B:  # PE32
                dir_count_off = 92
            elif magic == 0x20B:  # PE32+
                dir_count_off = 108
            else:
                return None
            if dir_count_off + 4 > len(optional):
                return None
            dir_count = int.from_bytes(optional[dir_count_off : dir_count_off + 4], "little")
            if dir_count <= _PE_SECURITY_DIR:
                return {"signed": False}
            entry = dir_count_off + 4 + _PE_SECURITY_DIR * 8
            if entry + 8 > len(optional):
                return {"signed": False}
            cert_offset = int.from_bytes(optional[entry : entry + 4], "little")
            cert_size = int.from_bytes(optional[entry + 4 : entry + 8], "little")
            if cert_offset == 0 or cert_size == 0:
                return {"signed": False}
            file_size = path.stat().st_size
            within_file = cert_offset + cert_size <= file_size
            revision: int | None = None
            cert_type: int | None = None
            if within_file:
                # WIN_CERTIFICATE: dwLength (u32), wRevision (u16), wCertificateType (u16).
                stream.seek(cert_offset)
                header = stream.read(8)
                if len(header) >= 8:
                    revision = int.from_bytes(header[4:6], "little")
                    cert_type = int.from_bytes(header[6:8], "little")
    except OSError:
        return None
    result: dict[str, Any] = {
        "signed": True,
        "offset": cert_offset,
        "size": cert_size,
        "within_file": within_file,
    }
    if cert_type is not None:
        result["type"] = _WIN_CERT_TYPES.get(cert_type, f"type_{cert_type}")
        result["authenticode"] = cert_type == _WIN_CERT_TYPE_PKCS_SIGNED_DATA
    if revision is not None:
        result["revision"] = f"{revision >> 8}.{revision & 0xFF}"
    return result


def _pe_overlay(path: Path) -> dict[str, Any] | None:
    """Appended data past the last PE section -- the classic dropper stash.

    The PE analogue of the ELF/Mach-O/WASM overlay fact: a PE on disk ends at
    the furthest raw section end, so bytes beyond that were glued on. One PE
    twist the other formats lack: an Authenticode signature is *also* appended
    (the WIN_CERTIFICATE the security directory points at), and that trailing
    block is legitimate. So the overlay is split -- ``certificate_size`` is the
    part accounted for by the signature, ``extra_size`` the genuinely
    unexplained remainder that a self-extractor or a smuggled payload would
    occupy. ``extra_size`` of 0 with a non-zero ``certificate_size`` is a
    normally-signed image; ``extra_size`` above 0 is the triage signal.

    Fail-closed: the image end is clamped to the file size (a lying section
    size cannot invent an overlay) and None is returned when nothing trails the
    last section.
    """
    try:
        with path.open("rb") as stream:
            dos = stream.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return None
            e_lfanew = int.from_bytes(dos[0x3C:0x40], "little")
            stream.seek(e_lfanew)
            coff = stream.read(24)
            if len(coff) < 24 or coff[:4] != b"PE\x00\x00":
                return None
            num_sections = min(int.from_bytes(coff[6:8], "little"), _PE_MAX_SECTIONS)
            opt_size = int.from_bytes(coff[20:22], "little")
            optional = stream.read(opt_size)
            magic = int.from_bytes(optional[0:2], "little") if len(optional) >= 2 else 0
            if magic == 0x10B:
                dir_count_off = 92
            elif magic == 0x20B:
                dir_count_off = 108
            else:
                return None
            sections = _pe_sections(stream.read(num_sections * 40))
            file_size = path.stat().st_size
            # The headers themselves are a floor: a section-less PE still ends
            # after its optional header and section table.
            image_end = e_lfanew + 24 + opt_size + num_sections * 40
            for _va, _span, raw_ptr, raw_size in sections:
                if raw_size > 0:
                    image_end = max(image_end, raw_ptr + raw_size)
            image_end = min(image_end, file_size)
            if image_end >= file_size:
                return None
            cert_offset = cert_size = 0
            if dir_count_off + 4 <= len(optional):
                dir_count = int.from_bytes(optional[dir_count_off : dir_count_off + 4], "little")
                if dir_count > _PE_SECURITY_DIR:
                    entry = dir_count_off + 4 + _PE_SECURITY_DIR * 8
                    if entry + 8 <= len(optional):
                        cert_offset = int.from_bytes(optional[entry : entry + 4], "little")
                        cert_size = int.from_bytes(optional[entry + 4 : entry + 8], "little")
    except OSError:
        return None
    total = file_size - image_end
    # How much of the trailing block is the signature: its overlap with the
    # region past the last section, clamped so a cert outside the file or ahead
    # of the image end contributes nothing.
    certificate_size = 0
    if cert_offset and cert_size:
        overlap_lo = max(cert_offset, image_end)
        overlap_hi = min(cert_offset + cert_size, file_size)
        certificate_size = max(0, overlap_hi - overlap_lo)
    return {
        "offset": image_end,
        "size": total,
        "certificate_size": certificate_size,
        "extra_size": total - certificate_size,
    }


_DOTNET_MAX_FILE = 128 * 1024 * 1024
_DOTNET_MANIFEST_RESOURCE = 0x28
_DOTNET_IMPLEMENTATION_TABLES = (0x26, 0x23, 0x27)
_DOTNET_MAX_RESOURCE_ROWS = 4096
_DOTNET_MAX_RESOURCE_PAYLOADS = 64


def _dotnet_embedded_resources(path: Path) -> tuple[bytes, list[tuple[str, int, int]]]:
    """``(raw file bytes, [(name, byte offset, length)])`` per embedded resource.

    The shared walk under the .NET resource censuses -- and the place .NET
    packers lean on hardest: a protector stores the real, encrypted or
    compressed, stage-two assembly as an embedded ManifestResource, then loads
    it with ``Assembly.Load`` at runtime. This walks the ManifestResource
    table (0x28) for rows with a null Implementation (embedded in this module,
    not forwarded to another file) and resolves each one's length-prefixed
    blob in the CLI header's Resources directory to a file offset and length.

    Bounded and fail-closed: the whole read is capped, the table walk is
    bounded, and any structural surprise yields what parsed cleanly rather
    than raising.
    """
    from headless_re_mcp.dotnet.tables import coded_index_size, table_row_size

    empty: tuple[bytes, list[tuple[str, int, int]]] = (b"", [])
    try:
        size = path.stat().st_size
        if size > _DOTNET_MAX_FILE:
            return empty
        with path.open("rb") as stream:
            raw = stream.read(_DOTNET_MAX_FILE)
    except OSError:
        return empty
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        return empty
    e_lfanew = int.from_bytes(raw[0x3C:0x40], "little")
    if e_lfanew + 24 > len(raw) or raw[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return empty
    coff = raw[e_lfanew : e_lfanew + 24]
    num_sections = min(int.from_bytes(coff[6:8], "little"), _PE_MAX_SECTIONS)
    opt_size = int.from_bytes(coff[20:22], "little")
    opt_start = e_lfanew + 24
    optional = raw[opt_start : opt_start + opt_size]
    magic = int.from_bytes(optional[0:2], "little") if len(optional) >= 2 else 0
    if magic == 0x10B:
        dir_count_off = 92
    elif magic == 0x20B:
        dir_count_off = 108
    else:
        return raw, []
    if dir_count_off + 4 > len(optional):
        return raw, []
    dir_count = int.from_bytes(optional[dir_count_off : dir_count_off + 4], "little")
    if dir_count <= _PE_COM_DESCRIPTOR_DIR:
        return raw, []
    com_entry = dir_count_off + 4 + _PE_COM_DESCRIPTOR_DIR * 8
    if com_entry + 8 > len(optional):
        return raw, []
    clr_rva = int.from_bytes(optional[com_entry : com_entry + 4], "little")
    if clr_rva == 0:
        return raw, []
    sect_start = opt_start + opt_size
    sections = _pe_sections(raw[sect_start : sect_start + num_sections * 40])
    clr_off = _pe_rva_to_offset(sections, clr_rva)
    if clr_off is None or clr_off + 32 > len(raw):
        return raw, []
    cor20 = raw[clr_off : clr_off + 32]
    meta_rva = int.from_bytes(cor20[8:12], "little")
    res_rva = int.from_bytes(cor20[24:28], "little")
    res_size = int.from_bytes(cor20[28:32], "little")
    if res_rva == 0 or res_size == 0:
        return raw, []  # no managed Resources directory: nothing embedded
    meta_off = _pe_rva_to_offset(sections, meta_rva)
    res_base = _pe_rva_to_offset(sections, res_rva)
    if meta_off is None or res_base is None:
        return raw, []
    stream_map = _clr_stream_map(raw, meta_off)
    tables_span = stream_map.get("#~") or stream_map.get("#-")
    strings_span = stream_map.get("#Strings")
    if tables_span is None:
        return raw, []
    tables = raw[meta_off + tables_span[0] : meta_off + tables_span[0] + tables_span[1]]
    strings = b""
    if strings_span is not None:
        strings = raw[meta_off + strings_span[0] : meta_off + strings_span[0] + strings_span[1]]
    if len(tables) < 24:
        return raw, []
    heap_sizes = tables[6]
    string_index_size = 4 if (heap_sizes & 0x01) else 2
    guid_index_size = 4 if (heap_sizes & 0x02) else 2
    blob_index_size = 4 if (heap_sizes & 0x04) else 2
    valid = int.from_bytes(tables[8:16], "little")
    cursor = 24
    row_counts: dict[int, int] = {}
    for bit in range(64):
        if valid & (1 << bit):
            if cursor + 4 > len(tables):
                return raw, []
            row_counts[bit] = int.from_bytes(tables[cursor : cursor + 4], "little")
            cursor += 4
    # Clamp each count to what the stream could hold (same rule as the metadata
    # enumerator): an absurd count would re-size coded indexes and desync the
    # walk of every table behind it.
    max_rows = max((len(tables) - cursor) // 2, 0)
    row_counts = {bit: min(count, max_rows) for bit, count in row_counts.items()}
    if _DOTNET_MANIFEST_RESOURCE not in row_counts:
        return raw, []
    # Sum row sizes of every present table below ManifestResource to land on it.
    table_offset = cursor
    for bit in sorted(row_counts):
        row_size = table_row_size(
            row_counts, string_index_size, blob_index_size, guid_index_size, bit
        )
        if row_size is None:
            return raw, []
        if bit >= _DOTNET_MANIFEST_RESOURCE:
            break
        table_offset += row_size * row_counts[bit]
    row_size_28 = table_row_size(
        row_counts, string_index_size, blob_index_size, guid_index_size, _DOTNET_MANIFEST_RESOURCE
    )
    if row_size_28 is None:
        return raw, []
    implementation_size = coded_index_size(row_counts, _DOTNET_IMPLEMENTATION_TABLES, 2)

    def string_at(index: int) -> str:
        if index <= 0 or index >= len(strings):
            return ""
        end = strings.find(b"\0", index)
        return strings[index : (end if end >= 0 else len(strings))].decode(
            "utf-8", errors="replace"
        )

    resources: list[tuple[str, int, int]] = []
    rows = min(row_counts[_DOTNET_MANIFEST_RESOURCE], _DOTNET_MAX_RESOURCE_ROWS)
    for i in range(rows):
        row = table_offset + i * row_size_28
        if row + row_size_28 > len(tables):
            break
        blob_offset = int.from_bytes(tables[row : row + 4], "little")
        name_index = int.from_bytes(tables[row + 8 : row + 8 + string_index_size], "little")
        impl_at = row + 8 + string_index_size
        implementation = int.from_bytes(tables[impl_at : impl_at + implementation_size], "little")
        if implementation != 0:
            continue  # forwarded to another file/assembly: not embedded here
        entry = res_base + blob_offset
        if entry + 4 > len(raw):
            continue
        blob_len = int.from_bytes(raw[entry : entry + 4], "little")
        resources.append((string_at(name_index), entry + 4, blob_len))
    return raw, resources


def _dotnet_resource_payloads(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Embedded managed resources whose bytes open with executable magic.

    The .NET analogue of the PE resource, APK ``assets/`` and WASM
    data-segment censuses: each flagged entry names the resource, the sniffed
    kind and the byte size. A census, not a verdict: a legitimate embedded
    assembly or zipped asset lists here too, for triage. Only the first 0x40
    bytes of each resource are sniffed and the reported list is capped.
    """
    raw, resources = _dotnet_embedded_resources(path)
    payloads: list[dict[str, Any]] = []
    found = 0
    for name, offset, blob_len in resources:
        head = raw[offset : offset + min(blob_len, 0x40)]
        kind = next((k for m, k in _PE_RESOURCE_KINDS if head.startswith(m)), None)
        if kind == "pe" and len(head) < 0x40:
            kind = None
        if kind is None:
            continue
        found += 1
        if len(payloads) < _DOTNET_MAX_RESOURCE_PAYLOADS:
            payloads.append({"name": name, "kind": kind, "size": blob_len})
    return payloads, found


def _dotnet_high_entropy_resources(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Embedded resources whose bytes measure near-random with no magic.

    The .NET arm of the entropy census -- and the exact ConfuserEx /
    .NET-Reactor shape: the protected stage-two assembly is stored encrypted
    or compressed as a ManifestResource and inflated at runtime, so it opens
    with no magic and only the Shannon measure gives it away. A resource whose
    head self-declares routes to its own census instead (executables to the
    payload census; a ResourceManager ``.resources`` blob or media file
    explains itself). Bounds are the shared census ones: a size floor, a
    per-resource read cap, an exact count with a capped list.
    """
    raw, resources = _dotnet_embedded_resources(path)
    flagged: list[dict[str, Any]] = []
    count = 0
    for name, offset, blob_len in resources:
        if blob_len < _ENTROPY_MIN_SIZE or offset + blob_len > len(raw):
            continue
        if _self_declaring_magic(raw[offset : offset + 0x40]):
            continue
        entropy = _shannon_entropy(raw[offset : offset + min(blob_len, _ENTROPY_MAX_READ)])
        if entropy >= _ENTROPY_THRESHOLD:
            count += 1
            if len(flagged) < _ENTROPY_MAX_FLAGGED:
                flagged.append({"name": name, "entropy": round(entropy, 2), "size": blob_len})
    return flagged, count


def _clr_stream_map(raw: bytes, meta_off: int) -> dict[str, tuple[int, int]]:
    """Parse the metadata root's stream headers into ``{name: (offset, size)}``.

    Offsets are relative to the metadata root (``meta_off``). Bounded and
    fail-closed: a truncated or lying root yields whatever parsed cleanly.
    """
    root = raw[meta_off : meta_off + 20]
    if len(root) < 20 or root[:4] != _CLR_METADATA_MAGIC:
        return {}
    version_len = int.from_bytes(root[12:16], "little")
    if not 0 <= version_len <= _CLR_MAX_VERSION_LEN:
        return {}
    pos = meta_off + 16 + version_len  # skip version string
    if pos + 4 > len(raw):
        return {}
    stream_count = int.from_bytes(raw[pos + 2 : pos + 4], "little")
    pos += 4
    out: dict[str, tuple[int, int]] = {}
    for _ in range(min(stream_count, 32)):
        if pos + 8 > len(raw):
            break
        offset = int.from_bytes(raw[pos : pos + 4], "little")
        length = int.from_bytes(raw[pos + 4 : pos + 8], "little")
        pos += 8
        end = raw.find(b"\0", pos)
        if end < 0:
            break
        name = raw[pos:end].decode("ascii", errors="replace")
        pos = end + 1
        pos = (pos + 3) & ~3  # names are padded to a 4-byte boundary
        out[name] = (offset, length)
    return out


def _pe_header_view(
    raw: bytes,
) -> tuple[int, int, int, list[tuple[int, int, int, int]]] | None:
    """``(magic, dir_count, dir_array_off, sections)`` for a PE, or None.

    ``dir_array_off`` is the offset in ``raw`` where the data-directory array
    begins; ``sections`` is the parsed section table for RVA->offset mapping.
    Shared by the import/export walk; fail-closed on any malformed header.
    """
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        return None
    e_lfanew = int.from_bytes(raw[0x3C:0x40], "little")
    if e_lfanew < 0 or e_lfanew + 24 > len(raw) or raw[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = raw[e_lfanew : e_lfanew + 24]
    num_sections = min(int.from_bytes(coff[6:8], "little"), _PE_MAX_SECTIONS)
    opt_size = int.from_bytes(coff[20:22], "little")
    opt_start = e_lfanew + 24
    optional = raw[opt_start : opt_start + opt_size]
    magic = int.from_bytes(optional[0:2], "little") if len(optional) >= 2 else 0
    if magic == 0x10B:
        dir_count_off = 92
    elif magic == 0x20B:
        dir_count_off = 108
    else:
        return None
    if dir_count_off + 4 > len(optional):
        return None
    dir_count = int.from_bytes(optional[dir_count_off : dir_count_off + 4], "little")
    dir_array_off = opt_start + dir_count_off + 4
    sect_start = opt_start + opt_size
    sections = _pe_sections(raw[sect_start : sect_start + num_sections * 40])
    return magic, dir_count, dir_array_off, sections


def _pe_read_cstr(raw: bytes, off: int | None, cap: int) -> str:
    """A NUL-terminated ASCII string at ``off`` in ``raw``, bounded by ``cap``."""
    if off is None or off <= 0 or off >= len(raw):
        return ""
    end = raw.find(b"\x00", off, off + cap + 1)
    if end < 0:
        end = min(off + cap, len(raw))
    return raw[off:end].decode("ascii", errors="replace")


def _pe_capability_surface(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """``(imports, exports)`` read straight off the PE import/export directories.

    The native PE capability surface -- the pair to an ELF/Mach-O's imported and
    exported symbols, and the strongest triage signal after arch: which native
    functions from which DLLs the loader must bind (what the binary can actually
    do), and, for a DLL, what it offers back. ``imports`` is a list of
    ``{"dll", "functions"}`` in import-table order (the shape pefile and dumpbin
    render); ``exports`` is the sorted export-name table. Ordinal-only imports
    read as ``#N``.

    Bounded and fail-closed: the whole read is capped, the descriptor walk, the
    per-DLL thunk walk and both reported lists are bounded, and any structural
    surprise yields whatever parsed cleanly rather than raising.
    """
    try:
        if path.stat().st_size > _PE_MAX_IMPORT_FILE:
            return [], []
        with path.open("rb") as stream:
            raw = stream.read(_PE_MAX_IMPORT_FILE)
    except OSError:
        return [], []
    view = _pe_header_view(raw)
    if view is None:
        return [], []
    magic, dir_count, dir_off, sections = view
    imports = _pe_imports(raw, magic, dir_count, dir_off, sections)
    exports = _pe_exports(raw, dir_count, dir_off, sections)
    return imports, exports


def _pe_imports(
    raw: bytes,
    magic: int,
    dir_count: int,
    dir_off: int,
    sections: list[tuple[int, int, int, int]],
) -> list[dict[str, Any]]:
    """The import directory (index 1) as ``[{"dll", "functions"}, ...]``."""
    if dir_count <= _PE_IMPORT_DIR:
        return []
    entry = dir_off + _PE_IMPORT_DIR * 8
    if entry + 8 > len(raw):
        return []
    imp_rva = int.from_bytes(raw[entry : entry + 4], "little")
    if imp_rva == 0:
        return []
    desc_off = _pe_rva_to_offset(sections, imp_rva)
    if desc_off is None:
        return []
    thunk_size = 8 if magic == 0x20B else 4
    ordinal_flag = (1 << 63) if magic == 0x20B else (1 << 31)
    rva_mask = 0x7FFFFFFFFFFFFFFF if magic == 0x20B else 0x7FFFFFFF
    imports: list[dict[str, Any]] = []
    for i in range(_PE_MAX_IMPORT_DLLS):
        desc = desc_off + i * 20  # IMAGE_IMPORT_DESCRIPTOR is 20 bytes
        if desc + 20 > len(raw):
            break
        oft = int.from_bytes(raw[desc : desc + 4], "little")  # OriginalFirstThunk (ILT)
        name_rva = int.from_bytes(raw[desc + 12 : desc + 16], "little")
        first_thunk = int.from_bytes(raw[desc + 16 : desc + 20], "little")  # IAT
        if oft == 0 and name_rva == 0 and first_thunk == 0:
            break  # the all-zero descriptor terminates the array
        dll = _pe_read_cstr(raw, _pe_rva_to_offset(sections, name_rva), _PE_MAX_SYMBOL_NAME)
        # Prefer the import lookup table (import names survive here even after
        # the loader overwrites the IAT with addresses); fall back to the IAT.
        thunk_rva = oft or first_thunk
        thunk_off = _pe_rva_to_offset(sections, thunk_rva) if thunk_rva else None
        functions: list[str] = []
        if thunk_off is not None:
            for j in range(_PE_MAX_IMPORTS_PER_DLL):
                thunk = thunk_off + j * thunk_size
                if thunk + thunk_size > len(raw):
                    break
                value = int.from_bytes(raw[thunk : thunk + thunk_size], "little")
                if value == 0:
                    break  # the zero thunk terminates this DLL's list
                if value & ordinal_flag:
                    functions.append(f"#{value & 0xFFFF}")  # import by ordinal
                    continue
                hint_off = _pe_rva_to_offset(sections, value & rva_mask)
                # IMAGE_IMPORT_BY_NAME: a 2-byte hint then the ASCII name.
                name = _pe_read_cstr(
                    raw, hint_off + 2 if hint_off is not None else None, _PE_MAX_SYMBOL_NAME
                )
                if name:
                    functions.append(name)
        imports.append({"dll": dll, "functions": functions})
    return imports


def _pe_exports(
    raw: bytes,
    dir_count: int,
    dir_off: int,
    sections: list[tuple[int, int, int, int]],
) -> list[str]:
    """The export name table (index 0) as a sorted list of names."""
    if dir_count <= _PE_EXPORT_DIR:
        return []
    entry = dir_off + _PE_EXPORT_DIR * 8
    if entry + 8 > len(raw):
        return []
    exp_rva = int.from_bytes(raw[entry : entry + 4], "little")
    if exp_rva == 0:
        return []
    exp_off = _pe_rva_to_offset(sections, exp_rva)
    if exp_off is None or exp_off + 40 > len(raw):
        return []
    num_names = int.from_bytes(raw[exp_off + 24 : exp_off + 28], "little")
    names_rva = int.from_bytes(raw[exp_off + 32 : exp_off + 36], "little")
    names_off = _pe_rva_to_offset(sections, names_rva)
    if names_off is None:
        return []
    exports: list[str] = []
    for i in range(min(num_names, _PE_MAX_EXPORTS)):
        pointer = names_off + i * 4
        if pointer + 4 > len(raw):
            break
        name_off = _pe_rva_to_offset(sections, int.from_bytes(raw[pointer : pointer + 4], "little"))
        name = _pe_read_cstr(raw, name_off, _PE_MAX_SYMBOL_NAME)
        if name:
            exports.append(name)
    return sorted(exports)


def _pe_hardening_facts(path: Path) -> dict[str, Any]:
    """Subsystem, loader mitigations and entry VA off the PE optional header.

    The native PE build posture -- the pair to the ELF nx/relro/canary/pie and
    Mach-O nx/pie facts. ``subsystem`` answers what kind of program this is
    (gui, console, a native driver, an EFI image); the DllCharacteristics bits
    are the loader mitigation contract (DYNAMICBASE -> ``aslr``, NX_COMPAT ->
    ``nx``, GUARD_CF -> ``cfg``, plus high-entropy 64-bit ASLR, forced
    integrity, AppContainer and no-SEH); ``os_version`` and
    ``subsystem_version`` are the minimum Windows the image declares it needs
    (the PE minimum-runtime fact, the pair to Mach-O's min_os and the ELF
    ABI-tag min_kernel -- the loader enforces the subsystem pair); ``entry``
    is AddressOfEntryPoint rebased to the preferred image base -- the address
    an analyst lands on first, mirroring the ELF/Mach-O ``entry`` facts --
    and is omitted when the header declares none (a resource-only DLL).

    Fail-closed: a non-PE or an optional header too short to carry the fields
    yields ``{}`` rather than guessed values.
    """
    try:
        with path.open("rb") as stream:
            dos = stream.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return {}
            stream.seek(int.from_bytes(dos[0x3C:0x40], "little"))
            coff = stream.read(24)
            if len(coff) < 24 or coff[:4] != b"PE\x00\x00":
                return {}
            optional = stream.read(int.from_bytes(coff[20:22], "little"))
    except OSError:
        return {}
    magic = int.from_bytes(optional[0:2], "little") if len(optional) >= 2 else 0
    if magic == 0x10B:
        base_off, base_len = 28, 4  # PE32: 32-bit ImageBase after BaseOfData
    elif magic == 0x20B:
        base_off, base_len = 24, 8  # PE32+: 64-bit ImageBase, no BaseOfData
    else:
        return {}
    if len(optional) < _PE_DLLCHARACTERISTICS_OFF + 2:
        return {}
    subsystem = int.from_bytes(
        optional[_PE_SUBSYSTEM_OFF : _PE_SUBSYSTEM_OFF + 2], "little"
    )
    dllchar = int.from_bytes(
        optional[_PE_DLLCHARACTERISTICS_OFF : _PE_DLLCHARACTERISTICS_OFF + 2], "little"
    )
    facts: dict[str, Any] = {
        "subsystem": _PE_SUBSYSTEMS.get(subsystem, f"subsystem_{subsystem}"),
        "os_version": _pe_u16_pair(optional, _PE_OS_VERSION_OFF),
        "subsystem_version": _pe_u16_pair(optional, _PE_SUBSYS_VERSION_OFF),
    }
    for bit, name in _PE_DLL_MITIGATIONS:
        facts[name] = bool(dllchar & bit)
    entry_rva = int.from_bytes(optional[_PE_ENTRY_RVA_OFF : _PE_ENTRY_RVA_OFF + 4], "little")
    if entry_rva:
        image_base = int.from_bytes(optional[base_off : base_off + base_len], "little")
        facts["entry"] = image_base + entry_rva
    return facts


def _pe_u16_pair(optional: bytes, offset: int) -> str:
    """Two little-endian u16s at ``offset`` rendered dotted ("major.minor")."""
    major = int.from_bytes(optional[offset : offset + 2], "little")
    minor = int.from_bytes(optional[offset + 2 : offset + 4], "little")
    return f"{major}.{minor}"


def _pe_image_base(raw: bytes, magic: int, dir_off: int) -> int | None:
    """The preferred ImageBase, located back from the data-directory offset.

    ``_pe_header_view`` hands back where the directory array starts; the
    NumberOfRvaAndSizes field sits 4 bytes before it at a magic-dependent
    offset into the optional header, which pins down where ImageBase lives
    (32-bit at +28 for PE32, 64-bit at +24 for PE32+).
    """
    opt_start = dir_off - 4 - (108 if magic == 0x20B else 92)
    lo = opt_start + (24 if magic == 0x20B else 28)
    hi = opt_start + 32
    if lo < 0 or hi > len(raw):
        return None
    return int.from_bytes(raw[lo:hi], "little")


def _pe_tls_facts(path: Path) -> dict[str, Any]:
    """The TLS-callback surface -- the PE's code-before-main -- as ``{"tls": ...}``.

    The pair to the ELF ``init_funcs`` (DT_INIT/init-array counts), the Mach-O
    ``init_funcs`` (mod-init pointer counts), the .NET module initializer and
    the Android custom Application class: the loader runs every TLS callback
    before the entry point, which is where packers put anti-debug checks and
    droppers their first-stage logic. Reports whether a TLS directory exists at
    all and how many callbacks its AddressOfCallBacks array holds -- a present
    directory with zero callbacks is ordinary thread-local data, a nonzero
    count is code the entry-point-first analyst would miss.

    AddressOfCallBacks and the callback entries are VAs, not RVAs, so the walk
    rebases them off the preferred ImageBase before mapping through the section
    table. Bounded and fail-closed: the whole read is capped, the array walk is
    capped, and a VA below the image base or outside every section yields the
    presence bit with a zero count rather than a guess; only a non-PE yields
    ``{}``.
    """
    try:
        if path.stat().st_size > _PE_MAX_IMPORT_FILE:
            return {}
        with path.open("rb") as stream:
            raw = stream.read(_PE_MAX_IMPORT_FILE)
    except OSError:
        return {}
    view = _pe_header_view(raw)
    if view is None:
        return {}
    magic, dir_count, dir_off, sections = view
    facts: dict[str, Any] = {"present": False, "callbacks": 0}
    entry = dir_off + _PE_TLS_DIR * 8
    if dir_count <= _PE_TLS_DIR or entry + 8 > len(raw):
        return {"tls": facts}
    tls_rva = int.from_bytes(raw[entry : entry + 4], "little")
    if tls_rva == 0:
        return {"tls": facts}
    facts["present"] = True
    ptr = 8 if magic == 0x20B else 4
    tls_off = _pe_rva_to_offset(sections, tls_rva)
    # IMAGE_TLS_DIRECTORY: four pointer-wide fields (raw-data start/end, index,
    # AddressOfCallBacks) then two DWORDs; only the callbacks field matters.
    if tls_off is None or tls_off + 4 * ptr > len(raw):
        return {"tls": facts}
    callbacks_va = int.from_bytes(raw[tls_off + 3 * ptr : tls_off + 4 * ptr], "little")
    image_base = _pe_image_base(raw, magic, dir_off)
    if callbacks_va == 0 or image_base is None or callbacks_va < image_base:
        return {"tls": facts}
    array_off = _pe_rva_to_offset(sections, callbacks_va - image_base)
    if array_off is None:
        return {"tls": facts}
    count = 0
    for i in range(_PE_MAX_TLS_CALLBACKS):
        slot = array_off + i * ptr
        if slot + ptr > len(raw):
            break
        if int.from_bytes(raw[slot : slot + ptr], "little") == 0:
            break  # the zero pointer terminates the callback array
        count += 1
    facts["callbacks"] = count
    return {"tls": facts}


def _pe_debug_fingerprint(path: Path) -> dict[str, Any]:
    """The CodeView RSDS record off the debug directory, as ``{"pdb": ...}``.

    The native PE build fingerprint -- the pair to an ELF build-id and a Mach-O
    UUID, and the same fact ``dotnet.inspect`` reports for managed assemblies,
    now tool-free for every PE: the per-build PDB GUID and age (``signature``
    is their concatenation, the exact string symstore and every symbol server
    index the PDB by) and the PDB path the linker baked in, which routinely
    leaks user and project names. Walks the IMAGE_DEBUG_DIRECTORY entries (data
    directory 6) for the first CodeView (type 2) record, preferring the entry's
    file pointer and falling back to its RVA when a linker left the pointer 0.

    Bounded and fail-closed: the whole read is capped, the entry walk and the
    declared blob size are bounded, and an absent directory, a foreign
    (non-RSDS) record or a truncated blob yields ``{}`` -- no fingerprint is a
    real answer -- rather than a guess or an exception.
    """
    try:
        if path.stat().st_size > _PE_MAX_IMPORT_FILE:
            return {}
        with path.open("rb") as stream:
            raw = stream.read(_PE_MAX_IMPORT_FILE)
    except OSError:
        return {}
    view = _pe_header_view(raw)
    if view is None:
        return {}
    _magic, dir_count, dir_off, sections = view
    entry = dir_off + _PE_DEBUG_DIR * 8
    if dir_count <= _PE_DEBUG_DIR or entry + 8 > len(raw):
        return {}
    table_rva = int.from_bytes(raw[entry : entry + 4], "little")
    table_size = int.from_bytes(raw[entry + 4 : entry + 8], "little")
    if table_rva == 0 or table_size < _PE_DEBUG_ENTRY_SIZE:
        return {}
    table_off = _pe_rva_to_offset(sections, table_rva)
    if table_off is None:
        return {}
    for i in range(min(table_size // _PE_DEBUG_ENTRY_SIZE, _PE_MAX_DEBUG_ENTRIES)):
        rec = raw[table_off + i * _PE_DEBUG_ENTRY_SIZE : table_off + (i + 1) * _PE_DEBUG_ENTRY_SIZE]
        if len(rec) < _PE_DEBUG_ENTRY_SIZE:
            break
        if int.from_bytes(rec[12:16], "little") != _PE_DEBUG_TYPE_CODEVIEW:
            continue
        size = int.from_bytes(rec[16:20], "little")
        addr_rva = int.from_bytes(rec[20:24], "little")
        ptr_raw = int.from_bytes(rec[24:28], "little")
        if size < _PE_MIN_RSDS or size > _PE_MAX_RSDS:
            continue
        # The record's raw data is addressed both ways; the file pointer is
        # authoritative on disk, the RVA the fallback when it is 0.
        offsets = (ptr_raw or None, _pe_rva_to_offset(sections, addr_rva) if addr_rva else None)
        for off in offsets:
            if off is None or off + size > len(raw):
                continue
            blob = raw[off : off + size]
            if blob[:4] != b"RSDS":
                continue
            guid = uuid.UUID(bytes_le=blob[4:20])
            age = int.from_bytes(blob[20:24], "little")
            pdb_path = blob[24:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            return {
                "pdb": {
                    "guid": str(guid),
                    "age": age,
                    "path": pdb_path or None,
                    "signature": f"{guid.hex.upper()}{age:X}",
                }
            }
    return {}


def _pe_wx_sections(path: Path) -> dict[str, Any]:
    """Sections both writable and executable -- as ``{"wx_sections": [names]}``.

    The PE W^X violation, the pair to the ELF and Mach-O ``wx_segments``
    counts: a section the loader maps so the process can write it and then run
    it, which is what a packer's unpack-into section (UPX0's shape) needs and
    no stock compiler emits. Named, because on PE the section name is the
    triage handle an analyst greps for.

    Reported for every PE whose section table parses -- an empty list is a
    real "nothing writable is executable" answer -- and absent only when the
    headers are malformed. Bounded by the section-count cap; fail-closed.
    """
    try:
        if path.stat().st_size > _PE_MAX_IMPORT_FILE:
            return {}
        raw = path.read_bytes()
    except OSError:
        return {}
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        return {}
    e_lfanew = int.from_bytes(raw[0x3C:0x40], "little")
    if e_lfanew < 0 or e_lfanew + 24 > len(raw) or raw[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return {}
    num_sections = min(int.from_bytes(raw[e_lfanew + 6 : e_lfanew + 8], "little"), _PE_MAX_SECTIONS)
    opt_size = int.from_bytes(raw[e_lfanew + 20 : e_lfanew + 22], "little")
    table = e_lfanew + 24 + opt_size
    names: list[str] = []
    for index in range(num_sections):
        base = table + index * 40
        if base + 40 > len(raw):
            break
        characteristics = int.from_bytes(raw[base + 36 : base + 40], "little")
        if characteristics & _PE_SCN_MEM_WRITE and characteristics & _PE_SCN_MEM_EXECUTE:
            names.append(raw[base : base + 8].rstrip(b"\x00").decode("ascii", errors="replace"))
    return {"wx_sections": names}


def _pe_high_entropy_sections(path: Path) -> dict[str, Any]:
    """Near-random PE sections -- as ``{"high_entropy_sections": [flags]}``.

    The PE arm of the entropy census, the pair to the ELF and Mach-O flags:
    a packed executable's stub is ordinary code, but the payload it inflates
    lives in a section whose bytes measure near 8 bits per byte (UPX1's
    shape) -- the stash the resource and section magic censuses cannot see
    when the payload is compressed or encrypted. Measured over each
    section's raw file bytes, exactly what pefile's get_entropy reads, so
    the gate can compare number for number.

    Reported for every PE whose section table parses -- an empty list is a
    real "nothing packed here" answer -- and absent only when the headers
    are malformed. Bounds and thresholds are the shared census ones.
    """
    try:
        if path.stat().st_size > _PE_MAX_IMPORT_FILE:
            return {}
        raw = path.read_bytes()
    except OSError:
        return {}
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        return {}
    e_lfanew = int.from_bytes(raw[0x3C:0x40], "little")
    if e_lfanew < 0 or e_lfanew + 24 > len(raw) or raw[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return {}
    num_sections = min(int.from_bytes(raw[e_lfanew + 6 : e_lfanew + 8], "little"), _PE_MAX_SECTIONS)
    opt_size = int.from_bytes(raw[e_lfanew + 20 : e_lfanew + 22], "little")
    table = e_lfanew + 24 + opt_size
    sections: list[tuple[str, int, int]] = []
    for index in range(num_sections):
        base = table + index * 40
        if base + 40 > len(raw):
            break
        name = raw[base : base + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        raw_size = int.from_bytes(raw[base + 16 : base + 20], "little")
        raw_ptr = int.from_bytes(raw[base + 20 : base + 24], "little")
        sections.append((name, raw_ptr, raw_size))
    return {"high_entropy_sections": _entropy_flags(io.BytesIO(raw), sections)}


def _pe_rich_header(path: Path) -> dict[str, Any]:
    """The Rich header -- MSVC's toolchain census -- as ``{"rich_header": ...}``.

    Every object the Microsoft linker consumed leaves one row in the XOR-masked
    block between the DOS stub and the PE header: a product id naming the tool
    (compiler, masm, the linker itself, per-version), the tool's build number
    and how many objects it contributed. The PE toolchain provenance, the pair
    to an ELF .comment, a Mach-O build-tool entry and the WASM producers
    section -- and a classic attribution artifact, since the census survives
    even a fully stripped build.

    The mask (the "checksum" dword after the ``Rich`` marker) is only trusted
    once unmasking backwards reaches the ``DanS`` sentinel; a stray ``Rich``
    string without one is not a Rich header. Bounded and fail-closed: the scan
    stays inside the pre-PE-header bytes, the backwards walk and the entry
    list are capped, and absence -- every gcc-, mingw- or mcs-built image --
    is a real answer, since only MSVC-family linkers write the census.
    """
    try:
        with path.open("rb") as stream:
            head = stream.read(_PE_MAX_RICH_SCAN)
    except OSError:
        return {}
    if len(head) < 0x40 or head[:2] != b"MZ":
        return {}
    e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
    end = min(e_lfanew, len(head))
    if end <= 0x40:
        return {}
    region = head[:end]
    rich_at = region.rfind(_PE_RICH_MARKER)
    if rich_at < 0 or rich_at + 8 > len(region):
        return {}
    key = int.from_bytes(region[rich_at + 4 : rich_at + 8], "little")

    def unmask(offset: int) -> int:
        return int.from_bytes(region[offset : offset + 4], "little") ^ key

    dans_at = -1
    pos = rich_at - 8
    while pos >= 0x40 and rich_at - pos <= 8 * (_PE_MAX_RICH_ENTRIES + 2):
        if unmask(pos) == _PE_DANS:
            dans_at = pos
            break
        pos -= 8
    if dans_at < 0:
        return {}
    # The census rows sit between DanS's 16-byte prologue (the sentinel plus
    # three masked-zero pads) and the Rich marker, one (comp.id, count) pair
    # of dwords each; comp.id splits into product id and build number.
    entries: list[dict[str, int]] = []
    for entry_at in range(dans_at + 16, rich_at - 7, 8):
        if len(entries) >= _PE_MAX_RICH_ENTRIES:
            break
        comp = unmask(entry_at)
        entries.append(
            {"product_id": comp >> 16, "build": comp & 0xFFFF, "count": unmask(entry_at + 4)}
        )
    return {"rich_header": {"checksum": key, "entries": entries}}


def _pe_version_info(path: Path) -> dict[str, Any]:
    """VS_VERSIONINFO -- the PE's self-declared identity -- as ``{"version_info": ...}``.

    The pair to an APK's package identity, a .NET assembly version and an
    ELF/Mach-O soname/install_name: the numeric file and product versions from
    VS_FIXEDFILEINFO and the StringFileInfo table (CompanyName, ProductName,
    OriginalFilename, FileDescription, ...) that Explorer's Details pane shows.
    Self-declared, so a claim to triage, not a verdict -- malware routinely
    fakes a Microsoft identity here, which is exactly why the strings must be
    on the record next to the signature facts that could back them.

    Bounded and fail-closed: the resource walk to the RT_VERSION leaf is depth-
    and entry-capped, the blob and every string are size-capped, and a PE
    without the resource (or with one that decodes to nothing) carries no fact
    -- absence is a real answer.
    """
    try:
        if path.stat().st_size > _PE_MAX_IMPORT_FILE:
            return {}
        with path.open("rb") as stream:
            raw = stream.read(_PE_MAX_IMPORT_FILE)
    except OSError:
        return {}
    view = _pe_header_view(raw)
    if view is None:
        return {}
    _magic, dir_count, dir_off, sections = view
    blob = _pe_version_blob(raw, dir_count, dir_off, sections)
    if blob is None:
        return {}
    parsed = _vs_versioninfo(blob)
    if parsed is None:
        return {}
    return {"version_info": parsed}


def _pe_version_blob(
    raw: bytes,
    dir_count: int,
    dir_off: int,
    sections: list[tuple[int, int, int, int]],
) -> bytes | None:
    """The first RT_VERSION leaf's bytes out of the resource tree, or None."""
    entry = dir_off + _PE_RESOURCE_DIR * 8
    if dir_count <= _PE_RESOURCE_DIR or entry + 8 > len(raw):
        return None
    res_rva = int.from_bytes(raw[entry : entry + 4], "little")
    res_size = int.from_bytes(raw[entry + 4 : entry + 8], "little")
    if res_rva == 0 or res_size == 0:
        return None
    res_base = _pe_rva_to_offset(sections, res_rva)
    if res_base is None:
        return None
    tree = raw[res_base : res_base + min(res_size, _PE_RES_MAX_TREE)]

    def first_leaf(node_off: int, depth: int) -> bytes | None:
        # Under the RT_VERSION type node: name then language levels, ending in
        # an IMAGE_RESOURCE_DATA_ENTRY whose bytes live inside the tree.
        if depth > _PE_RES_MAX_DEPTH or node_off + 16 > len(tree):
            return None
        named = int.from_bytes(tree[node_off + 12 : node_off + 14], "little")
        idd = int.from_bytes(tree[node_off + 14 : node_off + 16], "little")
        cursor = node_off + 16
        for _ in range(min(named + idd, _PE_RES_MAX_ENTRIES)):
            if cursor + 8 > len(tree):
                return None
            offset_field = int.from_bytes(tree[cursor + 4 : cursor + 8], "little")
            cursor += 8
            if offset_field & 0x80000000:
                found = first_leaf(offset_field & 0x7FFFFFFF, depth + 1)
                if found is not None:
                    return found
                continue
            if offset_field + 16 > len(tree):
                continue
            data_rva = int.from_bytes(tree[offset_field : offset_field + 4], "little")
            size = int.from_bytes(tree[offset_field + 4 : offset_field + 8], "little")
            if res_rva <= data_rva and data_rva - res_rva + size <= len(tree):
                start = data_rva - res_rva
                return tree[start : start + min(size, _PE_MAX_VERSION_BLOB)]
        return None

    if len(tree) < 16:
        return None
    named = int.from_bytes(tree[12:14], "little")
    idd = int.from_bytes(tree[14:16], "little")
    cursor = 16
    for _ in range(min(named + idd, _PE_RES_MAX_ENTRIES)):
        if cursor + 8 > len(tree):
            return None
        name_field = int.from_bytes(tree[cursor : cursor + 4], "little")
        offset_field = int.from_bytes(tree[cursor + 4 : cursor + 8], "little")
        cursor += 8
        if name_field == _PE_RT_VERSION and offset_field & 0x80000000:
            return first_leaf(offset_field & 0x7FFFFFFF, 1)
    return None


def _vs_block(blob: bytes, pos: int) -> tuple[int, int, str, int] | None:
    """``(end, value_len, key, value_pos)`` for the version block at ``pos``.

    Every VS_VERSIONINFO node shares one shape: wLength, wValueLength, wType,
    a NUL-terminated UTF-16 key, then 32-bit padding before the value.
    """
    if pos + 6 > len(blob):
        return None
    w_length = int.from_bytes(blob[pos : pos + 2], "little")
    if w_length < 6:
        return None
    end = min(pos + w_length, len(blob))
    value_len = int.from_bytes(blob[pos + 2 : pos + 4], "little")
    key_end = pos + 6
    while key_end + 2 <= end and blob[key_end : key_end + 2] != b"\x00\x00":
        key_end += 2
    key = blob[pos + 6 : key_end].decode("utf-16-le", errors="replace")
    value_pos = (key_end + 2 + 3) & ~3
    return end, value_len, key, value_pos


def _vs_versioninfo(blob: bytes) -> dict[str, Any] | None:
    """The decoded VS_VERSIONINFO facts, or None when the blob is not one."""
    root = _vs_block(blob, 0)
    if root is None:
        return None
    end, value_len, key, value_pos = root
    if key != "VS_VERSION_INFO":
        return None
    strings: dict[str, str] = {}
    out: dict[str, Any] = {"file_version": None, "product_version": None, "strings": strings}
    has_fixed = (
        value_len >= _VS_FIXED_SIZE
        and value_pos + _VS_FIXED_SIZE <= len(blob)
        and int.from_bytes(blob[value_pos : value_pos + 4], "little") == _VS_FIXED_SIG
    )
    if has_fixed:

        def dotted(at: int) -> str:
            ms = int.from_bytes(blob[value_pos + at : value_pos + at + 4], "little")
            ls = int.from_bytes(blob[value_pos + at + 4 : value_pos + at + 8], "little")
            return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"

        out["file_version"] = dotted(8)
        out["product_version"] = dotted(16)
    pos = (value_pos + value_len + 3) & ~3
    while pos + 6 <= end:  # the children: StringFileInfo and VarFileInfo
        child = _vs_block(blob, pos)
        if child is None:
            break
        child_end, _len, child_key, table_pos = child
        if child_key == "StringFileInfo":
            _vs_string_tables(blob, table_pos, child_end, strings)
        if child_end <= pos:
            break
        pos = (child_end + 3) & ~3
    if out["file_version"] is None and not strings:
        return None  # a version resource that decodes to nothing is no identity
    return out


def _vs_string_tables(blob: bytes, pos: int, end: int, strings: dict[str, str]) -> None:
    """Collect String entries from every StringTable under StringFileInfo."""
    while pos + 6 <= end:
        table = _vs_block(blob, pos)
        if table is None:
            return
        table_end, _len, _key, entry_pos = table
        while entry_pos + 6 <= table_end:
            block = _vs_block(blob, entry_pos)
            if block is None:
                return
            block_end, _vlen, name, text_pos = block
            if name and name not in strings and len(strings) < _PE_MAX_VERSION_STRINGS:
                text_end = text_pos
                while text_end + 2 <= block_end and blob[text_end : text_end + 2] != b"\x00\x00":
                    text_end += 2
                value = blob[text_pos:text_end].decode("utf-16-le", errors="replace")
                strings[name[:_PE_MAX_VERSION_CHARS]] = value[:_PE_MAX_VERSION_CHARS]
            if block_end <= entry_pos:
                return
            entry_pos = (block_end + 3) & ~3
        if table_end <= pos:
            return
        pos = (table_end + 3) & ~3


def _pe_resource_payloads(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Resources whose bytes open with executable magic -- the dropper's stash.

    The Windows analogue of the APK ``assets/`` and WASM data-segment censuses:
    the resource directory (data directory index 2) is where a dropper hides
    stage two -- a nested PE in an RT_RCDATA blob it writes to disk and runs, an
    ELF payload for a cross-platform loader, a ZIP of tooling. Each flagged
    entry names the resource type it hid under (RT_RCDATA, or a "bitmap" that
    is really a PE), the sniffed kind and the resource's byte size. A census,
    not a verdict: a legitimate archive resource lists here too, for triage.

    Bounded and fail-closed: the tree walk is capped in depth, entries and
    reported payloads; only the first 0x40 bytes of each resource are read; and
    any structural surprise yields what parsed cleanly rather than raising.
    """
    try:
        with path.open("rb") as stream:
            dos = stream.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return [], 0
            e_lfanew = int.from_bytes(dos[0x3C:0x40], "little")
            stream.seek(e_lfanew)
            coff = stream.read(24)
            if len(coff) < 24 or coff[:4] != b"PE\x00\x00":
                return [], 0
            num_sections = min(int.from_bytes(coff[6:8], "little"), _PE_MAX_SECTIONS)
            opt_size = int.from_bytes(coff[20:22], "little")
            optional = stream.read(opt_size)
            magic = int.from_bytes(optional[0:2], "little") if len(optional) >= 2 else 0
            if magic == 0x10B:
                dir_count_off = 92
            elif magic == 0x20B:
                dir_count_off = 108
            else:
                return [], 0
            if dir_count_off + 4 > len(optional):
                return [], 0
            dir_count = int.from_bytes(optional[dir_count_off : dir_count_off + 4], "little")
            if dir_count <= _PE_RESOURCE_DIR:
                return [], 0
            entry = dir_count_off + 4 + _PE_RESOURCE_DIR * 8
            if entry + 8 > len(optional):
                return [], 0
            res_rva = int.from_bytes(optional[entry : entry + 4], "little")
            res_size = int.from_bytes(optional[entry + 4 : entry + 8], "little")
            if res_rva == 0 or res_size == 0:
                return [], 0
            sections = _pe_sections(stream.read(num_sections * 40))
            res_base = _pe_rva_to_offset(sections, res_rva)
            if res_base is None:
                return [], 0
            stream.seek(res_base)
            tree = stream.read(min(res_size, _PE_RES_MAX_TREE))
    except OSError:
        return [], 0

    payloads: list[dict[str, Any]] = []
    counters = {"found": 0, "entries": 0}

    def sniff(data_rva: int, size: int, type_label: str, name_label: str) -> None:
        # A resource's bytes live inside the .rsrc section it was read from, so
        # its RVA resolves within the tree buffer; a data entry pointing
        # elsewhere is malformed and skipped.
        if not res_rva <= data_rva < res_rva + len(tree):
            return
        ro = data_rva - res_rva
        head = tree[ro : ro + min(size, 0x40)]
        kind = next((k for m, k in _PE_RESOURCE_KINDS if head.startswith(m)), None)
        if kind == "pe" and len(head) < 0x40:
            kind = None
        if kind is None:
            return
        counters["found"] += 1
        if len(payloads) < _PE_RES_MAX_PAYLOADS:
            payloads.append(
                {"type": type_label, "name": name_label, "kind": kind, "size": size}
            )

    def entry_label(name_field: int) -> str:
        if name_field & 0x80000000:  # a UTF-16 string at a resource-relative offset
            so = name_field & 0x7FFFFFFF
            if so + 2 <= len(tree):
                length = int.from_bytes(tree[so : so + 2], "little")
                raw = tree[so + 2 : so + 2 + min(length, _PE_RES_MAX_NAME) * 2]
                return raw.decode("utf-16-le", errors="replace")
            return "?"
        return str(name_field)

    def walk(node_off: int, depth: int, type_label: str, name_label: str) -> None:
        if depth > _PE_RES_MAX_DEPTH or node_off + 16 > len(tree):
            return
        named = int.from_bytes(tree[node_off + 12 : node_off + 14], "little")
        idd = int.from_bytes(tree[node_off + 14 : node_off + 16], "little")
        cursor = node_off + 16
        for _ in range(named + idd):
            if counters["entries"] >= _PE_RES_MAX_ENTRIES or cursor + 8 > len(tree):
                return
            counters["entries"] += 1
            name_field = int.from_bytes(tree[cursor : cursor + 4], "little")
            offset_field = int.from_bytes(tree[cursor + 4 : cursor + 8], "little")
            cursor += 8
            label = entry_label(name_field)
            if depth == 0:  # the top level names the resource TYPE
                type_here = _PE_RESOURCE_TYPES.get(name_field, label) if not (
                    name_field & 0x80000000
                ) else label
                name_here = name_label
            else:
                type_here = type_label
                name_here = label if depth == 1 else name_label
            if offset_field & 0x80000000:  # a subdirectory
                walk(offset_field & 0x7FFFFFFF, depth + 1, type_here, name_here)
            elif offset_field + 16 <= len(tree):  # an IMAGE_RESOURCE_DATA_ENTRY
                data_rva = int.from_bytes(tree[offset_field : offset_field + 4], "little")
                size = int.from_bytes(tree[offset_field + 4 : offset_field + 8], "little")
                sniff(data_rva, size, type_here, name_here)

    walk(0, 0, "", "")
    return payloads, counters["found"]


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
    facts: dict[str, Any] = {}
    try:
        with path.open("rb") as stream:
            head = stream.read(_NATIVE_HEADER_BYTES)
            if head.startswith(b"\x7fELF"):
                facts = _elf_facts(head, stream)
            else:
                magic = head[:4]
                if magic in _MACHO_THIN_MAGICS:
                    facts = _macho_thin_facts(head, magic, stream)
                elif magic == _MACHO_FAT_MAGIC:
                    facts = _macho_fat_facts(head)
    except OSError:
        return {}
    if not facts:
        return {}
    # The URL census over the whole image -- string literals live in .rodata /
    # __cstring, uncompressed, so the raw bytes are the right place to look.
    facts.update(_file_url_facts(path))
    return {"native": facts}


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
        shstrndx = int.from_bytes(head[0x3E:0x40], order)  # type: ignore[arg-type]
    else:
        phoff = int.from_bytes(head[0x1C:0x20], order)  # type: ignore[arg-type]
        phentsize = int.from_bytes(head[0x2A:0x2C], order)  # type: ignore[arg-type]
        phnum = int.from_bytes(head[0x2C:0x2E], order)  # type: ignore[arg-type]
        shoff = int.from_bytes(head[0x20:0x24], order)  # type: ignore[arg-type]
        shentsize = int.from_bytes(head[0x2E:0x30], order)  # type: ignore[arg-type]
        shnum = int.from_bytes(head[0x30:0x32], order)  # type: ignore[arg-type]
        shstrndx = int.from_bytes(head[0x32:0x34], order)  # type: ignore[arg-type]
    program = _elf_program_headers(stream, order, bits, phoff, phentsize, phnum)
    if program is not None:
        facts["linking"] = "dynamic" if program["has_dynamic"] else "static"
        if program["has_dynamic"]:
            pie = _elf_dynamic_pie(stream, order, bits, program["dyn_off"], program["dyn_sz"])
            names = _elf_dynamic_names(
                stream, order, bits, program["dyn_off"], program["dyn_sz"], program["loads"]
            )
            if names is not None:
                facts["needed"] = names["needed"]
                facts["canary"] = names["canary"]
                if names["soname"] is not None:
                    facts["soname"] = names["soname"]
                if names["rpath"] is not None:
                    facts["rpath"] = names["rpath"]
                if names["runpath"] is not None:
                    facts["runpath"] = names["runpath"]
                # The version tags the loader must satisfy per library -- the
                # ELF minimum-runtime fact (readelf -V shows the same chain).
                # Absent for a binary with no versioned imports.
                if names["version_needs"]:
                    facts["version_needs"] = names["version_needs"]
                # The version nodes the object provides (DT_VERDEF) -- its
                # exported ABI contract, present on a versioned shared object.
                # readelf -V shows the same "Version definition section".
                if names["version_defs"]:
                    facts["version_defs"] = names["version_defs"]
                # The load-time constructor/destructor surface -- the code
                # that runs before the entry point (readelf -d shows the same
                # INIT/INIT_ARRAYSZ tags). Always present for a parsed dynamic
                # table: "no constructors" is a real answer.
                facts["init_funcs"] = names["init_funcs"]
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
        # PT_LOAD mappings both writable and executable -- the W^X violation
        # a packer or self-modifying loader needs and a stock toolchain never
        # emits. Always present alongside nx: zero is a real answer.
        facts["wx_segments"] = program["wx_loads"]
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
        # Target OS and minimum kernel from the GNU ABI-tag note -- the ELF
        # analogue of Mach-O's platform/min_os, cross-checked against readelf -n.
        abi_os, min_kernel = _elf_abi_tag(stream, order, program["notes"])
        if abi_os is not None:
            facts["abi_os"] = abi_os
            facts["min_kernel"] = min_kernel
    stripped = _elf_is_stripped(stream, order, bits, shoff, shentsize, shnum)
    if stripped is not None:
        facts["stripped"] = stripped
    # The dynamic symbol surface, read off .dynsym/.dynstr the way readelf
    # --dyn-syms and nm -D do: exports (the object's public API) and imports
    # (the undefined symbols the loader must resolve -- the capability signal,
    # at symbol granularity, that DT_NEEDED only gives per library). Either
    # fact is present only when non-empty, so a static binary with no .dynsym
    # omits both.
    exports, imports = _elf_dynamic_symbols(stream, order, bits, shoff, shentsize, shnum)
    if exports:
        facts["exported_symbols"] = exports
    if imports:
        facts["imported_symbols"] = imports
    # Appended data past everything the headers map -- the PE overlay analogue,
    # where self-extractors and droppers park payloads. Absent means none.
    overlay = _elf_overlay(stream, order, bits, phoff, phentsize, phnum, shoff, shentsize, shnum)
    if overlay is not None:
        facts["overlay"] = overlay
    # Sections whose bytes open with executable magic -- the section-level
    # payload census (a nested PE/ELF/ZIP in a custom section a dropper writes
    # out), the native pair to the PE resource and WASM data-segment censuses.
    # Reported whenever there is a section table to walk (like `stripped`); an
    # empty census is then a real "nothing hidden in a section" answer, while a
    # header-only object with no section table omits the fact entirely.
    if shoff > 0 and 0 < shnum <= _ELF_MAX_SHNUM:
        sections = _elf_named_sections(stream, order, bits, shoff, shentsize, shnum, shstrndx)
        section_payloads, section_count = _elf_section_payloads(stream, sections)
        facts["section_payloads"] = section_payloads
        facts["section_payload_count"] = section_count
        # DWARF debug sections -- the native pair to the PE/.NET PDB facts:
        # what a -g build ships and a release build does not. Empty is a real
        # "no debug info" answer.
        facts["debug_info"] = _debug_info_facts([(n, size) for n, _t, _o, size in sections])
        # Compiler records out of .comment -- the toolchain provenance, the
        # pair to the WASM producers section; absent stays absent.
        toolchain = _elf_toolchain(stream, sections)
        if toolchain:
            facts["toolchain"] = toolchain
        # Sections whose bytes measure near-random -- the packed-payload
        # flags the magic-byte census cannot raise. Empty is a real answer.
        facts["high_entropy_sections"] = _entropy_flags(
            stream,
            [
                (name, off, size)
                for name, stype, off, size in sections
                if stype not in (_SHT_NULL, _SHT_NOBITS)
            ],
        )


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
    wx_loads = 0
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
        if p_type == _PT_LOAD:
            # Writable and executable at once: the W^X violation, counted
            # even for a file-less mapping (the bytes arrive at runtime).
            if p_flags & _PF_W and p_flags & _PF_X:
                wx_loads += 1
            if p_filesz > 0:
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
        "wx_loads": wx_loads,
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
) -> dict[str, Any] | None:
    """The string-table facts from the dynamic table, or None if unreadable.

    Walks the dynamic array for the DT_NEEDED string offsets, the DT_SONAME /
    DT_RPATH / DT_RUNPATH offsets and the DT_STRTAB address, maps that address
    to a file offset through the PT_LOAD segments, and reads the names out of
    the dynamic string table. ``canary`` is whether that string table names a
    stack-guard symbol -- the same read costs nothing extra and answers the
    fourth checksec question. ``rpath``/``runpath`` are the colon-separated
    library search paths split into lists. ``init_funcs`` is the load-time
    constructor/destructor surface off the same walk: whether DT_INIT/DT_FINI
    exist and how many entries the init/fini/preinit pointer arrays declare.
    Bounded at every step: the entry count, the name count and the
    string-table read are all capped, so a corrupt table yields ``None``
    (dynamic but undetermined) rather than a large read; a dynamic image that
    names nothing yields empty/None values. DT_SONAME is present only on a
    shared object.
    """
    if dyn_off <= 0 or dyn_sz <= 0 or not loads:
        return None
    entsize = 16 if bits == 64 else 8
    vsize = entsize // 2
    count = min(dyn_sz // entsize, _ELF_MAX_DYN)
    if count <= 0:
        return None
    stream.seek(dyn_off)
    table = stream.read(entsize * count)
    needed_offsets: list[int] = []
    soname_off: int | None = None
    rpath_off: int | None = None
    runpath_off: int | None = None
    strtab_va: int | None = None
    strsz: int | None = None
    verneed_va: int | None = None
    verneed_num: int | None = None
    verdef_va: int | None = None
    verdef_num: int | None = None
    has_init = has_fini = False
    init_array_sz = fini_array_sz = preinit_array_sz = 0
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
        elif tag == _DT_RPATH:
            rpath_off = val
        elif tag == _DT_RUNPATH:
            runpath_off = val
        elif tag == _DT_STRTAB:
            strtab_va = val
        elif tag == _DT_STRSZ:
            strsz = val
        elif tag == _DT_VERNEED:
            verneed_va = val
        elif tag == _DT_VERNEEDNUM:
            verneed_num = val
        elif tag == _DT_VERDEF:
            verdef_va = val
        elif tag == _DT_VERDEFNUM:
            verdef_num = val
        elif tag == _DT_INIT:
            has_init = val != 0
        elif tag == _DT_FINI:
            has_fini = val != 0
        elif tag == _DT_INIT_ARRAYSZ:
            init_array_sz = val
        elif tag == _DT_FINI_ARRAYSZ:
            fini_array_sz = val
        elif tag == _DT_PREINIT_ARRAYSZ:
            preinit_array_sz = val
    if strtab_va is None:
        return None
    str_off = _elf_vaddr_to_off(strtab_va, loads)
    if str_off is None:
        return None
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

    def read_paths(offset: int | None) -> list[str] | None:
        if offset is None:
            return None
        value = read_name(offset)
        if value is None:
            return None
        return [part for part in value.split(":") if part]

    version_needs: list[dict[str, Any]] = []
    if verneed_va is not None:
        vn_off = _elf_vaddr_to_off(verneed_va, loads)
        if vn_off is not None:
            version_needs = _elf_version_needs(stream, order, vn_off, verneed_num, read_name)

    version_defs: list[dict[str, Any]] = []
    if verdef_va is not None:
        vd_off = _elf_vaddr_to_off(verdef_va, loads)
        if vd_off is not None:
            version_defs = _elf_version_defs(stream, order, vd_off, verdef_num, read_name)

    # The array counts are the declared byte sizes over the pointer width
    # (vsize is exactly the ELF class's pointer size); only the size fields
    # are read, so a lying size costs nothing but is clamped to stay sane.
    def array_count(size: int) -> int:
        return min(max(size, 0) // vsize, _ELF_MAX_INIT_FUNCS)

    return {
        "needed": [name for off in needed_offsets if (name := read_name(off))],
        "soname": read_name(soname_off) if soname_off is not None else None,
        "rpath": read_paths(rpath_off),
        "runpath": read_paths(runpath_off),
        "version_needs": version_needs,
        "version_defs": version_defs,
        "canary": any(sym in blob for sym in _ELF_CANARY_SYMBOLS),
        "init_funcs": {
            "has_init": has_init,
            "has_fini": has_fini,
            "init_array": array_count(init_array_sz),
            "fini_array": array_count(fini_array_sz),
            "preinit_array": array_count(preinit_array_sz),
        },
    }


def _elf_version_needs(
    stream: BinaryIO,
    order: str,
    off: int,
    declared: int | None,
    read_name: Callable[[int], str | None],
) -> list[dict[str, Any]]:
    """The Verneed chain: which version tags of which libraries the loader
    must satisfy before the binary runs (e.g. GLIBC_2.34 out of libc.so.6).

    Each 16-byte Verneed record names one library (``vn_file``) and chains
    ``vn_cnt`` 16-byte Vernaux records, each naming one required version tag
    (``vna_name``); ``vn_next``/``vna_next`` are the relative hops between
    records. Every count and hop is bounded and a malformed record stops the
    walk, so a hostile chain degrades to a shorter list rather than a large
    read or an unbounded loop.
    """
    results: list[dict[str, Any]] = []
    count = min(declared, _ELF_MAX_VERNEED) if declared else _ELF_MAX_VERNEED
    pos = off
    for _ in range(count):
        stream.seek(pos)
        record = stream.read(16)
        if len(record) < 16:
            break
        vn_version = int.from_bytes(record[0:2], order)  # type: ignore[arg-type]
        vn_cnt = int.from_bytes(record[2:4], order)  # type: ignore[arg-type]
        vn_file = int.from_bytes(record[4:8], order)  # type: ignore[arg-type]
        vn_aux = int.from_bytes(record[8:12], order)  # type: ignore[arg-type]
        vn_next = int.from_bytes(record[12:16], order)  # type: ignore[arg-type]
        if vn_version != 1:  # the only revision ever defined; anything else is garbage
            break
        versions: list[str] = []
        aux_pos = pos + vn_aux
        for _ in range(min(vn_cnt, _ELF_MAX_VERNAUX) if vn_aux > 0 else 0):
            stream.seek(aux_pos)
            aux = stream.read(16)
            if len(aux) < 16:
                break
            vna_name = int.from_bytes(aux[8:12], order)  # type: ignore[arg-type]
            vna_next = int.from_bytes(aux[12:16], order)  # type: ignore[arg-type]
            version = read_name(vna_name)
            if version:
                versions.append(version)
            if vna_next == 0:
                break
            aux_pos += vna_next
        file_name = read_name(vn_file)
        if file_name:
            results.append({"file": file_name, "versions": versions})
        if vn_next == 0:
            break
        pos += vn_next
    return results


def _elf_version_defs(
    stream: BinaryIO,
    order: str,
    off: int,
    declared: int | None,
    read_name: Callable[[int], str | None],
) -> list[dict[str, Any]]:
    """The Verdef chain: which version nodes the object *defines* (provides).

    Each 20-byte Verdef record carries flags (VER_FLG_BASE marks the node that
    names the object itself), a ``vd_cnt`` count of chained 8-byte Verdaux
    records and the ``vd_aux``/``vd_next`` relative hops. The first Verdaux of a
    record is the version node's own name (``vda_name``); any that follow name
    parent versions it inherits (e.g. PROBE_2.0 inheriting PROBE_1.0). Mirrors
    the Verneed walk's bounding exactly: every count and hop is capped and a
    malformed record stops the walk, so a hostile chain degrades to a shorter
    list rather than a large read or an unbounded loop.
    """
    results: list[dict[str, Any]] = []
    count = min(declared, _ELF_MAX_VERDEF) if declared else _ELF_MAX_VERDEF
    pos = off
    for _ in range(count):
        stream.seek(pos)
        record = stream.read(20)
        if len(record) < 20:
            break
        vd_version = int.from_bytes(record[0:2], order)  # type: ignore[arg-type]
        vd_flags = int.from_bytes(record[2:4], order)  # type: ignore[arg-type]
        vd_cnt = int.from_bytes(record[6:8], order)  # type: ignore[arg-type]
        vd_aux = int.from_bytes(record[12:16], order)  # type: ignore[arg-type]
        vd_next = int.from_bytes(record[16:20], order)  # type: ignore[arg-type]
        if vd_version != 1:  # the only revision ever defined; anything else is garbage
            break
        names: list[str] = []
        aux_pos = pos + vd_aux
        for _ in range(min(vd_cnt, _ELF_MAX_VERDAUX) if vd_aux > 0 else 0):
            stream.seek(aux_pos)
            aux = stream.read(8)
            if len(aux) < 8:
                break
            vda_name = int.from_bytes(aux[0:4], order)  # type: ignore[arg-type]
            vda_next = int.from_bytes(aux[4:8], order)  # type: ignore[arg-type]
            name = read_name(vda_name)
            if name:
                names.append(name)
            if vda_next == 0:
                break
            aux_pos += vda_next
        if names:
            # The first Verdaux is the node's own name; the rest are parents.
            results.append(
                {
                    "name": names[0],
                    "base": bool(vd_flags & _VER_FLG_BASE),
                    "parents": names[1:],
                }
            )
        if vd_next == 0:
            break
        pos += vd_next
    return results


def _elf_iter_notes(
    stream: BinaryIO, order: str, notes: list[tuple[int, int]]
) -> Iterator[tuple[int, bytes, bytes]]:
    """Yield ``(type, name, descriptor)`` for each PT_NOTE record.

    A note record is namesz/descsz/type words then the (4-aligned) name and
    descriptor. Bounded by the note count and each segment's already-capped
    size, and fail-closed: a malformed record stops the scan for that segment
    rather than raising.
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
            yield ntype, name, blob[desc_start:desc_end]
            pos = desc_end + (-descsz % 4)


def _elf_build_id(
    stream: BinaryIO, order: str, notes: list[tuple[int, int]]
) -> str | None:
    """The GNU build-id (hex) from a PT_NOTE segment, or None if absent.

    The build-id is the descriptor of the ``GNU`` note of type NT_GNU_BUILD_ID.
    """
    for ntype, name, desc in _elf_iter_notes(stream, order, notes):
        if ntype == _NT_GNU_BUILD_ID and name == b"GNU" and 0 < len(desc) <= _ELF_BUILD_ID_MAX:
            return desc.hex()
    return None


def _elf_abi_tag(
    stream: BinaryIO, order: str, notes: list[tuple[int, int]]
) -> tuple[str | None, str | None]:
    """``(abi_os, min_kernel)`` from the GNU ABI-tag note, or ``(None, None)``.

    NT_GNU_ABI_TAG's descriptor is four u32s: an OS id then the minimum kernel
    version (major, minor, subminor). This is the ELF counterpart to Mach-O's
    LC_BUILD_VERSION -- which Unix the image targets and how old a kernel it
    tolerates -- and readelf -n decodes it identically ("OS: Linux, ABI: 3.2.0").
    """
    for ntype, name, desc in _elf_iter_notes(stream, order, notes):
        if ntype == _NT_GNU_ABI_TAG and name == b"GNU" and len(desc) >= 16:
            os_id = int.from_bytes(desc[0:4], order)  # type: ignore[arg-type]
            major = int.from_bytes(desc[4:8], order)  # type: ignore[arg-type]
            minor = int.from_bytes(desc[8:12], order)  # type: ignore[arg-type]
            sub = int.from_bytes(desc[12:16], order)  # type: ignore[arg-type]
            return _ELF_ABI_OS.get(os_id, f"os_{os_id}"), f"{major}.{minor}.{sub}"
    return None, None


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


def _elf_dynamic_symbols(
    stream: BinaryIO, order: str, bits: int, shoff: int, shentsize: int, shnum: int
) -> tuple[list[str], list[str]]:
    """The (exported, imported) names of the globally/weakly bound dynamic symbols.

    Locates .dynsym through the section headers (SHT_DYNSYM), reads its linked
    string table (sh_link -> .dynstr), and splits the GLOBAL/WEAK symbols the
    way readelf --dyn-syms does: a real section index means defined here (an
    export, the object's public API surface); SHN_UNDEF means the loader must
    resolve it elsewhere (an import -- the symbol-granular capability signal
    DT_NEEDED only gives per library). Both lists are sorted for determinism.
    Every step is bounded (section count, symbol scan, string read, per-list
    cap) so a hostile or symbol-heavy image degrades to shorter lists rather
    than a large read, and any structural surprise yields empty lists.
    """
    nothing: tuple[list[str], list[str]] = ([], [])
    if shoff <= 0 or shnum <= 0 or shnum > _ELF_MAX_SHNUM:
        return nothing
    want = 64 if bits == 64 else 40
    entsize = max(shentsize, want)
    stream.seek(shoff)
    table = stream.read(entsize * shnum)
    dynsym: tuple[int, int, int, int] | None = None  # (offset, size, entsize, link)
    for i in range(shnum):
        entry = table[i * entsize : i * entsize + want]
        if len(entry) < want:
            break
        if int.from_bytes(entry[4:8], order) != _SHT_DYNSYM:  # type: ignore[arg-type]
            continue
        if bits == 64:
            sh_offset = int.from_bytes(entry[24:32], order)  # type: ignore[arg-type]
            sh_size = int.from_bytes(entry[32:40], order)  # type: ignore[arg-type]
            sh_link = int.from_bytes(entry[40:44], order)  # type: ignore[arg-type]
            sh_entsize = int.from_bytes(entry[56:64], order)  # type: ignore[arg-type]
        else:
            sh_offset = int.from_bytes(entry[16:20], order)  # type: ignore[arg-type]
            sh_size = int.from_bytes(entry[20:24], order)  # type: ignore[arg-type]
            sh_link = int.from_bytes(entry[24:28], order)  # type: ignore[arg-type]
            sh_entsize = int.from_bytes(entry[36:40], order)  # type: ignore[arg-type]
        dynsym = (sh_offset, sh_size, sh_entsize, sh_link)
        break
    if dynsym is None:
        return nothing
    sym_off, sym_size, sym_entsize, link = dynsym
    sym_stride = 24 if bits == 64 else 16
    if sym_entsize:  # honour a declared entry size, but never below the real one
        sym_stride = max(sym_stride, sym_entsize)
    if sym_off <= 0 or sym_size <= 0 or link <= 0 or link >= shnum:
        return nothing
    # The linked section is .dynstr; read it the same bounded way DT_STRTAB is.
    link_entry = table[link * entsize : link * entsize + want]
    if len(link_entry) < want:
        return nothing
    if bits == 64:
        str_off = int.from_bytes(link_entry[24:32], order)  # type: ignore[arg-type]
        str_size = int.from_bytes(link_entry[32:40], order)  # type: ignore[arg-type]
    else:
        str_off = int.from_bytes(link_entry[16:20], order)  # type: ignore[arg-type]
        str_size = int.from_bytes(link_entry[20:24], order)  # type: ignore[arg-type]
    if str_off <= 0 or not (0 < str_size <= _ELF_MAX_STRTAB):
        return nothing
    stream.seek(str_off)
    strblob = stream.read(str_size)

    def name_at(offset: int) -> str | None:
        if 0 <= offset < len(strblob):
            end = strblob.find(b"\x00", offset)
            if end == -1:
                end = len(strblob)
            return strblob[offset:end].decode("utf-8", errors="replace") or None
        return None

    count = min(sym_size // sym_stride, _ELF_MAX_DYNSYM_SCAN)
    if count <= 0:
        return nothing
    stream.seek(sym_off)
    syms = stream.read(sym_stride * count)
    exports: set[str] = set()
    imports: set[str] = set()
    for i in range(count):
        rec = syms[i * sym_stride : i * sym_stride + sym_stride]
        if len(rec) < sym_stride:
            break
        if bits == 64:
            st_name = int.from_bytes(rec[0:4], order)  # type: ignore[arg-type]
            st_info = rec[4]
            st_shndx = int.from_bytes(rec[6:8], order)  # type: ignore[arg-type]
        else:
            st_name = int.from_bytes(rec[0:4], order)  # type: ignore[arg-type]
            st_info = rec[12]
            st_shndx = int.from_bytes(rec[14:16], order)  # type: ignore[arg-type]
        # Only externally visible symbols matter; a reserved section index
        # (SHN_ABS and friends) is neither a plain definition nor an import.
        if (st_info >> 4) not in (_STB_GLOBAL, _STB_WEAK):
            continue
        if st_shndx >= _SHN_LORESERVE:
            continue
        # SHN_UNDEF means the loader resolves it elsewhere: an import. Any
        # real section index means defined here: an export.
        bucket = imports if st_shndx == _SHN_UNDEF else exports
        if len(bucket) >= _ELF_MAX_EXPORTS:
            continue
        name = name_at(st_name)
        if name:
            bucket.add(name)
    return sorted(exports), sorted(imports)


def _native_sniff_kind(head: bytes) -> str | None:
    """The executable/container kind ``head`` opens with, or None.

    Shared by the ELF and Mach-O section censuses. MZ needs the 0x40-byte floor
    a real DOS stub carries so a section that merely starts "MZ" is not a PE.
    """
    for magic, kind in _NATIVE_SECTION_KINDS:
        if head.startswith(magic):
            if kind == "pe" and len(head) < _NATIVE_SECTION_SNIFF:
                return None
            return kind
    return None


def _elf_named_sections(
    stream: BinaryIO,
    order: str,
    bits: int,
    shoff: int,
    shentsize: int,
    shnum: int,
    shstrndx: int,
) -> list[tuple[str, int, int, int]]:
    """``(name, sh_type, sh_offset, sh_size)`` per section header, names resolved.

    The shared table walk under the section-payload census and the .comment
    toolchain read: reads the header table once, resolves names through
    e_shstrndx, and falls back to ``section_{index}`` when the string table is
    missing or lying. Callers apply their own skip rules and bounds.
    """
    if shoff <= 0 or shnum <= 0 or shnum > _ELF_MAX_SHNUM:
        return []
    want = 64 if bits == 64 else 40
    entsize = max(shentsize, want)
    try:
        file_size = stream.seek(0, 2)
        stream.seek(shoff)
        table = stream.read(entsize * shnum)
    except OSError:
        return []

    def sh_fields(entry: bytes) -> tuple[int, int, int, int]:
        name = int.from_bytes(entry[0:4], order)  # type: ignore[arg-type]
        stype = int.from_bytes(entry[4:8], order)  # type: ignore[arg-type]
        if bits == 64:
            off = int.from_bytes(entry[24:32], order)  # type: ignore[arg-type]
            size = int.from_bytes(entry[32:40], order)  # type: ignore[arg-type]
        else:
            off = int.from_bytes(entry[16:20], order)  # type: ignore[arg-type]
            size = int.from_bytes(entry[20:24], order)  # type: ignore[arg-type]
        return name, stype, off, size

    # The section-name string table, resolved through e_shstrndx; without it
    # names fall back to their index, so callers still see every section.
    strtab = b""
    if 0 < shstrndx < shnum:
        entry = table[shstrndx * entsize : shstrndx * entsize + want]
        if len(entry) >= want:
            _n, _t, str_off, str_size = sh_fields(entry)
            if 0 < str_off < file_size and 0 < str_size <= _ELF_MAX_SHSTRTAB:
                try:
                    stream.seek(str_off)
                    strtab = stream.read(str_size)
                except OSError:
                    strtab = b""

    def section_name(name_off: int, index: int) -> str:
        if 0 < name_off < len(strtab):
            end = strtab.find(b"\0", name_off)
            if end > name_off:
                return strtab[name_off:end].decode("utf-8", errors="replace")
        return f"section_{index}"

    sections: list[tuple[str, int, int, int]] = []
    for i in range(shnum):
        entry = table[i * entsize : i * entsize + want]
        if len(entry) < want:
            break
        name_off, stype, sh_offset, sh_size = sh_fields(entry)
        sections.append((section_name(name_off, i), stype, sh_offset, sh_size))
    return sections


def _self_declaring_magic(head: bytes) -> bool:
    """True when ``head``'s magic already explains near-random bytes.

    Executable and container magic belongs to the embedded-payload censuses;
    compressed media, font and archive formats are near-random by design and
    say so in their first bytes. Neither is the encrypted-payload shape the
    entropy censuses exist to flag.
    """
    if any(head.startswith(magic) for magic in _ENTROPY_SELF_DECLARING):
        return True
    return head[4:8] == b"ftyp"


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: 0.0 for a constant run, 8.0 for uniform."""
    if not data:
        return 0.0
    total = len(data)
    entropy = 0.0
    for value in range(256):
        count = data.count(value)
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


def _entropy_flags(
    stream: BinaryIO,
    sections: list[tuple[str, int, int]],
) -> list[dict[str, Any]]:
    """Sections whose bytes measure near-random -- the packed-payload flags.

    ``sections`` are (name, file offset, size). Compressed or encrypted bytes
    sit near 8 bits per byte; code and tables sit well below the threshold, so
    a flagged section is where a packer parked the payload the magic-byte
    census cannot see (an encrypted stage two opens with no magic at all).
    A flag names the section, its measured entropy (rounded, over at most
    _ENTROPY_MAX_READ bytes) and its size. Bounded and fail-closed: sections
    too small for the measure to mean anything are skipped, the flag list is
    capped, and an unreadable section contributes nothing.
    """
    flagged: list[dict[str, Any]] = []
    try:
        file_size = stream.seek(0, 2)
    except OSError:
        return flagged
    for name, offset, size in sections:
        if size < _ENTROPY_MIN_SIZE or offset <= 0 or offset >= file_size:
            continue
        try:
            stream.seek(offset)
            data = stream.read(min(size, _ENTROPY_MAX_READ))
        except OSError:
            continue
        entropy = _shannon_entropy(data)
        if entropy >= _ENTROPY_THRESHOLD:
            flagged.append({"section": name, "entropy": round(entropy, 2), "size": size})
            if len(flagged) >= _ENTROPY_MAX_FLAGGED:
                break
    return flagged


def _collect_urls(buf: bytes, limit: int, found: dict[str, None]) -> None:
    """Record every URL match in ``buf`` that ends before ``limit``.

    ``found`` is an insertion-ordered set (a dict of URL -> None), so a match
    seen twice -- including one re-found in the carried tail of the previous
    chunk -- records once. A match ending at or past ``limit`` is left for the
    next round: its run may continue in bytes not read yet, and recording the
    truncated prefix now would invent a URL the file does not contain. (The
    wide pattern needs the one-byte slack in the caller's limit: a chunk can
    split a character/NUL pair.) A wide match stores every character followed
    by NUL, so its even bytes are the ASCII text. XML namespace identifiers
    are not endpoints and are skipped.
    """
    for regex, wide in ((_URL_ASCII_RE, False), (_URL_WIDE_RE, True)):
        for match in regex.finditer(buf):
            if match.end() >= limit:
                continue
            raw = match.group(0)
            url = (raw[::2] if wide else raw).decode("ascii")
            if url.lower().startswith(_URL_NAMESPACE_PREFIXES):
                continue
            found.setdefault(url, None)


def _scan_urls(stream: IO[bytes], found: dict[str, None], budget: int) -> int:
    """Stream ``stream`` through the URL patterns, recording into ``found``.

    Reads in chunks and carries the last _URL_SCAN_KEEP bytes across each
    boundary so a URL split between reads is matched whole exactly once:
    within a chunk, only matches that end short of the final byte are
    recorded (a match touching the end may continue in the next read); the
    final flush records everything left in the carry. Returns how many bytes
    were consumed so an archive walk can share one aggregate budget across
    members. Fail-closed: a read error ends the scan with what was found.
    """
    consumed = 0
    carry = b""
    while consumed < budget:
        try:
            chunk = stream.read(min(_URL_SCAN_CHUNK, budget - consumed))
        except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
            break
        if not chunk:
            break
        consumed += len(chunk)
        buf = carry + chunk
        _collect_urls(buf, len(buf) - 1, found)
        carry = buf[-_URL_SCAN_KEEP:]
    _collect_urls(carry, len(carry) + 1, found)
    return consumed


def _url_facts(found: dict[str, None]) -> dict[str, Any]:
    """The URL census facts: a bounded sample, an exact count, the cleartext share.

    ``cleartext_url_count`` counts endpoints whose scheme carries no transport
    security (http/ws/ftp) -- the binary's own uses-cleartext-traffic answer,
    the pair to the Android manifest flag of that name.
    """
    urls = list(found)
    return {
        "urls": urls[:_URL_MAX_LISTED],
        "url_count": len(urls),
        "cleartext_url_count": sum(
            1 for url in urls if not url.lower().startswith(("https://", "wss://"))
        ),
    }


def _file_url_facts(path: Path) -> dict[str, Any]:
    """The URL census over a file's raw bytes -- the flat-format wiring.

    Right for the formats whose string literals sit uncompressed in the image
    (ELF/Mach-O/PE/WASM); an APK stores its members deflated, so it gets the
    member-wise walk in _apk_url_facts instead.
    """
    found: dict[str, None] = {}
    with contextlib.suppress(OSError), path.open("rb") as stream:
        _scan_urls(stream, found, _URL_SCAN_BUDGET)
    return _url_facts(found)


def _dwarf_normalize(name: str) -> str:
    """A DWARF section name stripped to its cross-format base, or "".

    ELF names DWARF sections ``.debug_info``; Mach-O's ``__DWARF`` segment
    names them ``__debug_info``; the old GNU compressed variant is
    ``.zdebug_info``. All three describe the same logical section, so the
    container prefix (``.``/``__``) is stripped and a ``zdebug_`` spelling is
    folded to ``debug_`` -- exactly what llvm-dwarfdump reports. A name that is
    not a DWARF section yields "".
    """
    base = name.lstrip(".")
    if base.startswith("__"):
        base = base[2:]
    if base.startswith("zdebug_"):
        base = "debug_" + base[len("zdebug_") :]
    return base if base.startswith("debug_") else ""


def _debug_info_facts(sections: list[tuple[str, int]]) -> dict[str, Any]:
    """The DWARF debug-info census as ``{present, sections, size}``.

    ``sections`` are (name, byte size) pairs from the image's section table.
    DWARF (``.debug_*`` / ``__debug_*``) is what a ``-g`` build ships and a
    release build does not: source lines, types and variable names that hand
    the analyst the program in near-source form -- the native pair to the PE
    and .NET PDB facts and the WASM name section. Reports the normalized
    section names present and their total byte size; ``present`` is false with
    an empty list for a stripped or never-debug build, a real answer, so the
    census is symmetric with the entropy one (always reported when a section
    table exists). Bounded: the section list is already capped by the caller.
    """
    named = sorted({base for name, _ in sections if (base := _dwarf_normalize(name))})
    total = sum(size for name, size in sections if _dwarf_normalize(name))
    return {"present": bool(named), "sections": named, "size": total}


def _elf_toolchain(
    stream: BinaryIO,
    sections: list[tuple[str, int, int, int]],
) -> list[str]:
    """Compiler records out of ``.comment`` -- the ELF toolchain provenance.

    Every compiler that contributed objects to the link appends one
    NUL-terminated record ("GCC: (Ubuntu 13.2.0-4ubuntu3) 13.2.0", "clang
    version 17.0.6") -- the pair to the WASM producers section, a Mach-O
    LC_BUILD_VERSION tool entry and a PE Rich header, and the same strings
    ``readelf -p .comment`` prints. Deduplicated in first-seen order, both the
    list and each record bounded; a stripped or comment-less image yields an
    empty list, which the caller reads as "no provenance recorded".
    """
    for name, stype, sh_offset, sh_size in sections:
        if name != _ELF_TOOLCHAIN_SECTION or stype != _SHT_PROGBITS:
            continue
        if sh_offset <= 0 or sh_size <= 0:
            return []
        try:
            stream.seek(sh_offset)
            blob = stream.read(min(sh_size, _ELF_MAX_COMMENT))
        except OSError:
            return []
        records: list[str] = []
        for chunk in blob.split(b"\x00"):
            text = chunk.decode("utf-8", errors="replace").strip()[:_ELF_MAX_TOOLCHAIN_CHARS]
            if text and text not in records:
                records.append(text)
                if len(records) >= _ELF_MAX_TOOLCHAIN:
                    break
        return records
    return []


def _elf_section_payloads(
    stream: BinaryIO,
    sections: list[tuple[str, int, int, int]],
) -> tuple[list[dict[str, Any]], int]:
    """Sections whose bytes open with executable magic, and how many there are.

    The ELF arm of the payload census: a dropper linked as an ELF hides its
    stage two in a section it later writes out and runs (a nested ELF loader,
    a PE for a Windows drop, a zipped bundle). This sniffs the first bytes of
    every section that occupies file bytes (SHT_NOBITS and SHT_NULL hold
    none), naming each hit by its section name -- the objcopy
    ``--dump-section`` view an analyst would reach for. A census, not a
    verdict: a legitimate embedded blob lists here too.

    Bounded and fail-closed: the section list is already capped by the header
    walk, only the first 0x40 bytes of each section are read, the reported
    list is capped (the count stays exact), and any structural surprise yields
    whatever parsed cleanly.
    """
    try:
        file_size = stream.seek(0, 2)
    except OSError:
        return [], 0
    payloads: list[dict[str, Any]] = []
    found = 0
    for name, stype, sh_offset, sh_size in sections:
        if stype in (_SHT_NULL, _SHT_NOBITS):
            continue
        if sh_size < 4 or sh_offset <= 0 or sh_offset >= file_size:
            continue
        try:
            stream.seek(sh_offset)
            # Clamp the sniff to the section's own bytes so a short section
            # cannot be padded past the PE floor by whatever follows it.
            head = stream.read(min(sh_size, _NATIVE_SECTION_SNIFF))
        except OSError:
            continue
        kind = _native_sniff_kind(head)
        if kind is None:
            continue
        found += 1
        if len(payloads) < _NATIVE_MAX_SECTION_PAYLOADS:
            payloads.append({"section": name, "kind": kind, "size": sh_size})
    return payloads, found


def _elf_overlay(
    stream: BinaryIO,
    order: str,
    bits: int,
    phoff: int,
    phentsize: int,
    phnum: int,
    shoff: int,
    shentsize: int,
    shnum: int,
) -> dict[str, int] | None:
    """Appended data past everything the ELF headers map, or None when none.

    The image the loader and linker see ends at the furthest byte any program
    header (p_offset + p_filesz), any non-NOBITS section (sh_offset + sh_size),
    or either header table itself reaches. Whatever the file carries beyond
    that is invisible to both -- the ELF analogue of a PE overlay, the classic
    place a self-extractor or dropper parks its payload. Fail-closed: the fact
    is computed only when at least one table entry anchors the layout, ends
    are clamped to the file size (a lying offset cannot invent an overlay),
    and any read hiccup yields None.
    """
    try:
        file_size = stream.seek(0, 2)
    except OSError:
        return None
    end = 64 if bits == 64 else 52  # the ELF header is always mapped
    anchored = False
    if phoff > 0 and 0 < phnum <= _ELF_MAX_PHNUM:
        want = 56 if bits == 64 else 32
        entsize = max(phentsize, want)
        stream.seek(phoff)
        table = stream.read(entsize * phnum)
        for i in range(phnum):
            entry = table[i * entsize : i * entsize + want]
            if len(entry) < want:
                break
            if bits == 64:
                p_offset = int.from_bytes(entry[8:16], order)  # type: ignore[arg-type]
                p_filesz = int.from_bytes(entry[32:40], order)  # type: ignore[arg-type]
            else:
                p_offset = int.from_bytes(entry[4:8], order)  # type: ignore[arg-type]
                p_filesz = int.from_bytes(entry[16:20], order)  # type: ignore[arg-type]
            anchored = True
            end = max(end, phoff + entsize * phnum, p_offset + p_filesz)
    if shoff > 0 and 0 < shnum <= _ELF_MAX_SHNUM:
        want = 64 if bits == 64 else 40
        entsize = max(shentsize, want)
        stream.seek(shoff)
        table = stream.read(entsize * shnum)
        for i in range(shnum):
            entry = table[i * entsize : i * entsize + want]
            if len(entry) < want:
                break
            anchored = True
            end = max(end, shoff + entsize * shnum)
            # SHT_NOBITS occupies no file bytes: its sh_size is memory-only.
            if int.from_bytes(entry[4:8], order) == _SHT_NOBITS:  # type: ignore[arg-type]
                continue
            if bits == 64:
                sh_offset = int.from_bytes(entry[24:32], order)  # type: ignore[arg-type]
                sh_size = int.from_bytes(entry[32:40], order)  # type: ignore[arg-type]
            else:
                sh_offset = int.from_bytes(entry[16:20], order)  # type: ignore[arg-type]
                sh_size = int.from_bytes(entry[20:24], order)  # type: ignore[arg-type]
            end = max(end, sh_offset + sh_size)
    if not anchored:
        return None
    end = min(end, file_size)
    if end < file_size:
        return {"offset": end, "size": file_size - end}
    return None


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
        # Segments mapped writable and executable at once -- the W^X
        # violation, the pair to the ELF wx_segments count. Always present:
        # zero is a real answer.
        facts["wx_segments"] = lc["wx_segments"]
        if lc["dylibs"] is not None:
            facts["dylibs"] = lc["dylibs"]
        # LC_RPATH entries, the ELF rpath/runpath analogue; absent stays absent.
        if lc["rpaths"]:
            facts["rpath"] = lc["rpaths"]
        for key in (
            "interpreter",
            "install_name",
            "uuid",
            "platform",
            "min_os",
            "sdk",
            "build_tools",
        ):
            if lc[key] is not None:
                facts[key] = lc[key]
        entry = _macho_entry(lc["entryoff"], lc["segments"])
        if entry is not None:
            facts["entry"] = entry
        # FairPlay: an LC_ENCRYPTION_INFO with cryptid != 0 means the code is
        # ciphertext on disk; no command at all means not encrypted. When the
        # command exists, the full range is the triage map: which file bytes
        # are opaque until dumped (cryptid 1, FairPlay) -- or, cryptid 0 with
        # the command still present, the telltale of a decrypted App Store
        # dump rather than a never-encrypted build.
        encryption = lc["encryption"]
        facts["encrypted"] = bool(encryption and encryption[2])
        if encryption is not None:
            facts["encryption_info"] = {
                "offset": encryption[0],
                "size": encryption[1],
                "cryptid": encryption[2],
            }
        # The load-time constructor surface (S_MOD_INIT_FUNC_POINTERS and
        # friends), the Mach-O counterpart of the ELF init_funcs fact: how
        # many entries dyld runs before the entry point and after exit.
        # Always present: "runs nothing before main" is a real answer.
        facts["init_funcs"] = {"mod_init": lc["mod_init"], "mod_term": lc["mod_term"]}
        # Signed at all -- and by whom. macOS (and iOS unconditionally) refuse
        # unsigned code, so the macOS analogue of the APK signer facts starts
        # with whether an LC_CODE_SIGNATURE exists, then names the signing
        # identity out of the CodeDirectory it points at.
        sig = lc["code_signature"]
        facts["signed"] = sig is not None and sig[1] > 0
        if facts["signed"]:
            signature = _macho_code_signature(stream, sig[0], sig[1])
            if signature is not None:
                facts["signature"] = signature
        canary = _macho_canary(stream, lc["symtab"])
        if canary is not None:
            facts["canary"] = canary
        # The symbol surface read off LC_SYMTAB the way llvm-nm does: exports
        # (the image's public API) and imports (the undefined externals dyld
        # resolves -- the symbol-granular capability signal LC_LOAD_DYLIB only
        # gives per library). Either fact is present only when non-empty.
        exports, imports = _macho_symbol_surface(stream, lc["symtab"], bits, order)
        if exports:
            facts["exported_symbols"] = exports
        if imports:
            facts["imported_symbols"] = imports
        # Whether the local symbols strip removes are gone -- the Mach-O pair
        # to the ELF stripped fact; omitted when there is no symbol table to
        # measure, present as True/False otherwise.
        stripped = _macho_stripped(stream, lc["symtab"], bits, order)
        if stripped is not None:
            facts["stripped"] = stripped
        # Appended data past everything the load commands map -- the PE
        # overlay analogue for Mach-O. Absent means none.
        overlay = _macho_overlay(stream, cmd_off + sizeofcmds, lc, bits)
        if overlay is not None:
            facts["overlay"] = overlay
        # Sections whose bytes open with executable magic -- the section-level
        # payload census, the Mach-O pair to the ELF section census. Always
        # reported: an empty census is a real "nothing hidden here" answer.
        section_payloads, section_count = _macho_section_payloads(stream, lc["sections"])
        facts["section_payloads"] = section_payloads
        facts["section_payload_count"] = section_count
        # Near-random sections -- the packed-payload flags, the Mach-O pair
        # to the ELF and PE entropy censuses. Empty is a real answer.
        facts["high_entropy_sections"] = _entropy_flags(stream, lc["sections"])
        # DWARF sections in the __DWARF segment -- the Mach-O pair to the ELF
        # debug_info census and the PE/.NET PDB facts. Empty is a real answer.
        facts["debug_info"] = _debug_info_facts(
            [(name, size) for name, _off, size in lc["sections"]]
        )
    return facts


def _macho_overlay(
    stream: BinaryIO, header_end: int, lc: dict[str, Any], bits: int
) -> dict[str, int] | None:
    """Appended data past everything the load commands map, or None when none.

    The image dyld and the linker see ends at the furthest byte any segment
    (fileoff + filesize), the symbol/string tables (LC_SYMTAB), or the embedded
    code signature (LC_CODE_SIGNATURE) reaches -- __LINKEDIT normally spans to
    the end of a real file, so anything beyond is appended after the link, the
    Mach-O analogue of a PE overlay. Fail-closed: ends are clamped to the file
    size (a lying offset cannot invent an overlay) and a read hiccup yields
    None.
    """
    try:
        file_size = stream.seek(0, 2)
    except OSError:
        return None
    end = header_end
    for _vmaddr, fileoff, filesize in lc["segments"]:
        if filesize > 0:
            end = max(end, fileoff + filesize)
    if lc["symtab"] is not None:
        symoff, nsyms, stroff, strsize = lc["symtab"]
        if symoff > 0 and nsyms > 0:
            end = max(end, symoff + nsyms * (16 if bits == 64 else 12))
        if stroff > 0 and strsize > 0:
            end = max(end, stroff + strsize)
    if lc["code_signature"] is not None:
        dataoff, datasize = lc["code_signature"]
        if dataoff > 0 and datasize > 0:
            end = max(end, dataoff + datasize)
    end = min(end, file_size)
    if end < file_size:
        return {"offset": end, "size": file_size - end}
    return None


def _macho_code_signature(stream: BinaryIO, dataoff: int, datasize: int) -> dict[str, Any] | None:
    """The signing identity out of the embedded code-signature SuperBlob.

    LC_CODE_SIGNATURE points at a SuperBlob whose CodeDirectory slot carries
    everything triage asks of a signature without verifying it: the signing
    identifier (the bundle-id-like name the signer chose), the team id (the
    developer's Apple identity; absent for ad-hoc), whether the signature is
    ad-hoc (the CS_ADHOC flag: no certificate at all, so the binary only runs
    where it was blessed), and the digest algorithm. ``cd_sha256`` is the
    SHA-256 over the CodeDirectory blob itself -- the digest Apple's tooling
    derives the cdhash from and what rcodesign prints, so a gate can compare
    the two hex for hex.

    Fail-closed and bounded: an unreadable, truncated or foreign blob yields
    None (the image still reports ``signed``), never an exception.
    """
    if dataoff <= 0 or datasize < 20:
        return None
    try:
        stream.seek(dataoff)
        blob = stream.read(min(datasize, _CS_MAX_SIG_BYTES))
    except OSError:
        return None
    if len(blob) < 12 or int.from_bytes(blob[0:4], "big") != _CS_SUPERBLOB_MAGIC:
        return None
    count = int.from_bytes(blob[8:12], "big")
    cd_at: int | None = None
    for index in range(min(count, _CS_MAX_BLOBS)):
        entry = 12 + 8 * index
        if entry + 8 > len(blob):
            break
        if int.from_bytes(blob[entry : entry + 4], "big") == _CS_SLOT_CODEDIRECTORY:
            cd_at = int.from_bytes(blob[entry + 4 : entry + 8], "big")
            break
    if cd_at is None or cd_at + 40 > len(blob):
        return None
    if int.from_bytes(blob[cd_at : cd_at + 4], "big") != _CS_CODEDIRECTORY_MAGIC:
        return None
    cd_len = int.from_bytes(blob[cd_at + 4 : cd_at + 8], "big")
    if cd_len < 40 or cd_at + cd_len > len(blob):
        return None
    cd = blob[cd_at : cd_at + cd_len]
    version = int.from_bytes(cd[8:12], "big")
    flags = int.from_bytes(cd[12:16], "big")
    ident_off = int.from_bytes(cd[20:24], "big")
    hash_type = cd[37]
    signature: dict[str, Any] = {
        "ad_hoc": bool(flags & _CS_FLAG_ADHOC),
        "identifier": _macho_cs_string(cd, ident_off),
        "team_id": None,
        "hash_type": _CS_HASH_TYPES.get(hash_type, f"hash_{hash_type}"),
        "cd_sha256": hashlib.sha256(cd).hexdigest(),
    }
    # The team-id field only exists from CodeDirectory version 0x20200 on; a
    # zero offset means the signer recorded none (every ad-hoc signature).
    if version >= 0x20200 and len(cd) >= 52:
        team_off = int.from_bytes(cd[48:52], "big")
        if team_off:
            signature["team_id"] = _macho_cs_string(cd, team_off)
    return signature


def _macho_cs_string(cd: bytes, offset: int) -> str | None:
    """A NUL-terminated CodeDirectory string (identifier / team id), bounded."""
    if not 0 < offset < len(cd):
        return None
    raw = cd[offset : offset + _CS_MAX_NAME].split(b"\x00", 1)[0]
    return raw.decode("utf-8", errors="replace") or None


def _macho_canary(stream: BinaryIO, symtab: tuple[int, int, int, int] | None) -> bool | None:
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
    _symoff, _nsyms, stroff, strsize = symtab
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


def _macho_symbol_surface(
    stream: BinaryIO, symtab: tuple[int, int, int, int] | None, bits: int, order: str
) -> tuple[list[str], list[str]]:
    """The (exported, imported) names of the externally visible symbols.

    Walks LC_SYMTAB's nlist entries and splits those with the N_EXT bit set
    by type, the way llvm-nm does: N_SECT means defined in one of this image's
    sections (an export, the public API surface); N_UNDF means dyld must
    resolve it from a linked dylib (an import -- the symbol-granular
    capability signal LC_LOAD_DYLIB only gives per library). Names are read
    out of the string table verbatim, leading underscore and all, exactly as
    llvm-nm prints them; both lists are sorted for determinism. Every step is
    bounded (symbol scan, string read, per-list cap) so a hostile or
    symbol-heavy image degrades to shorter lists, and any structural surprise
    yields empty lists.
    """
    nothing: tuple[list[str], list[str]] = ([], [])
    if symtab is None:
        return nothing
    symoff, nsyms, stroff, strsize = symtab
    if symoff <= 0 or nsyms <= 0 or stroff <= 0 or strsize <= 0:
        return nothing
    stride = 16 if bits == 64 else 12
    count = min(nsyms, _MACHO_MAX_NSYMS_SCAN)
    try:
        stream.seek(stroff)
        strblob = stream.read(min(strsize, _ELF_MAX_STRTAB))
        stream.seek(symoff)
        syms = stream.read(stride * count)
    except OSError:
        return nothing

    def name_at(offset: int) -> str | None:
        if 0 < offset < len(strblob):
            end = strblob.find(b"\x00", offset)
            if end == -1:
                end = len(strblob)
            return strblob[offset:end].decode("utf-8", errors="replace") or None
        return None

    exports: set[str] = set()
    imports: set[str] = set()
    for i in range(count):
        rec = syms[i * stride : i * stride + stride]
        if len(rec) < stride:
            break
        n_strx = int.from_bytes(rec[0:4], order)  # type: ignore[arg-type]
        n_type = rec[4]
        if not (n_type & _N_EXT):
            continue
        kind = n_type & _N_TYPE
        # N_SECT is defined here (an export); N_UNDF is dyld's to resolve (an
        # import). Anything else (absolute, indirect, debug) is neither.
        if kind == _N_SECT:
            bucket = exports
        elif kind == _N_UNDF:
            bucket = imports
        else:
            continue
        if len(bucket) >= _MACHO_MAX_EXPORTS:
            continue
        name = name_at(n_strx)
        if name:
            bucket.add(name)
    return sorted(exports), sorted(imports)


def _macho_stripped(
    stream: BinaryIO, symtab: tuple[int, int, int, int] | None, bits: int, order: str
) -> bool | None:
    """True when LC_SYMTAB carries no local symbols; None when there is none.

    The Mach-O counterpart to the ELF ``stripped`` fact. ``strip`` removes the
    local symbols -- the debug-map STABS entries a ``-g`` build carries and the
    local defined symbols (N_SECT with N_EXT clear) -- while leaving the
    external symbols dyld needs for linking, so a stripped image is one whose
    symbol table has become all-external. A local named symbol is exactly what
    llvm-nm prints with a lowercase type letter, so the gate cross-checks the
    verdict. None when the image has no LC_SYMTAB at all (nothing to measure),
    parallel to the ELF reader returning None without a section table. The scan
    is bounded like the symbol surface's.
    """
    if symtab is None:
        return None
    symoff, nsyms, stroff, strsize = symtab
    if symoff <= 0 or nsyms <= 0 or stroff <= 0 or strsize <= 0:
        return None
    stride = 16 if bits == 64 else 12
    count = min(nsyms, _MACHO_MAX_NSYMS_SCAN)
    try:
        stream.seek(stroff)
        strblob = stream.read(min(strsize, _ELF_MAX_STRTAB))
        stream.seek(symoff)
        syms = stream.read(stride * count)
    except OSError:
        return None
    for i in range(count):
        rec = syms[i * stride : i * stride + stride]
        if len(rec) < stride:
            break
        n_strx = int.from_bytes(rec[0:4], order)  # type: ignore[arg-type]
        n_type = rec[4]
        if n_type & _N_EXT:
            continue  # external symbols survive stripping; not a local
        is_stab = bool(n_type & _N_STAB)
        is_local_defined = (n_type & _N_TYPE) == _N_SECT
        if not (is_stab or is_local_defined):
            continue
        if 0 < n_strx < len(strblob):
            end = strblob.find(b"\x00", n_strx)
            if strblob[n_strx : (end if end != -1 else len(strblob))]:
                return False  # a named local symbol remains: not stripped
    return True


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


def _macho_version(packed: int) -> str:
    """Decode an xxxx.yy.zz nibble-packed version, llvm-objdump style.

    The patch level is printed only when nonzero, so 0x000D0000 reads "13.0"
    and 0x000D0001 reads "13.0.1" -- matching the strings llvm-objdump prints,
    which the toolchain gate compares against verbatim.
    """
    major, minor, patch = packed >> 16, (packed >> 8) & 0xFF, packed & 0xFF
    return f"{major}.{minor}.{patch}" if patch else f"{major}.{minor}"


def _macho_load_commands(cmds: bytes, order: str, ncmds: int) -> dict[str, Any]:
    """Walk the load commands for the image's identity and dependency facts.

    Returns ``dylibs`` (the LC_LOAD_DYLIB / weak / reexport names, or None when
    the command count is out of range), ``interpreter`` (LC_LOAD_DYLINKER),
    ``install_name`` (LC_ID_DYLIB, a dylib's own name -- the DT_SONAME analogue),
    ``uuid`` (LC_UUID, the build id), ``entryoff`` (LC_MAIN's file offset of
    main, or None),     ``segments`` ((vmaddr, fileoff, filesize) per LC_SEGMENT
    / LC_SEGMENT_64, for mapping that offset to an address), ``symtab``
    (LC_SYMTAB's (symoff, nsyms, stroff, strsize), for the exported-symbol
    walk and the canary scan), ``encryption``
    (LC_ENCRYPTION_INFO's (cryptoff, cryptsize, cryptid), or None when the
    image carries none),
    ``code_signature`` (LC_CODE_SIGNATURE's (dataoff, datasize) locating the
    embedded signature SuperBlob, or None when unsigned),
    ``rpaths`` (the LC_RPATH search paths, the DT_RPATH/DT_RUNPATH analogue),
    ``platform``/``min_os``/``sdk`` (LC_BUILD_VERSION, or the older
    LC_VERSION_MIN_* whose command kind names the platform) and
    ``mod_init``/``mod_term`` (the entry counts of the init/term pointer
    sections dyld runs around the entry point, off the segments' section
    headers). Bounded by the command count and the region already sized; a
    command whose body runs past that region stops the walk.
    """
    result: dict[str, Any] = {
        "dylibs": None,
        "interpreter": None,
        "install_name": None,
        "uuid": None,
        "entryoff": None,
        "segments": [],
        "symtab": None,
        "encryption": None,
        "code_signature": None,
        "rpaths": [],
        "platform": None,
        "min_os": None,
        "sdk": None,
        # LC_BUILD_VERSION's ntools entries: the toolchain provenance.
        "build_tools": None,
        # The load-time constructor surface off the segments' section headers:
        # how many init/term entries dyld runs around the entry point.
        "mod_init": 0,
        "mod_term": 0,
        # (name, file offset, size) per section that occupies file bytes, for
        # the section-level payload census.
        "sections": [],
        # Segments mapped writable and executable at once (initprot), the
        # Mach-O W^X violation count.
        "wx_segments": 0,
    }
    if ncmds <= 0 or ncmds > _MACHO_MAX_LOAD_CMDS:
        return result
    names: list[str] = []
    segments: list[tuple[int, int, int]] = []
    rpaths: list[str] = []
    sections: list[tuple[str, int, int]] = []
    result["dylibs"] = names
    result["segments"] = segments
    result["rpaths"] = rpaths
    result["sections"] = sections
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
        elif cmd == _LC_BUILD_VERSION and result["platform"] is None and cmdsize >= 24:
            # platform/minos/sdk as u32s after cmd/cmdsize, then ntools
            # build_tool_version entries -- the toolchain provenance, the pair
            # to an ELF .comment and the WASM producers section.
            plat = int.from_bytes(cmds[pos + 8 : pos + 12], order)  # type: ignore[arg-type]
            result["platform"] = _MACHO_PLATFORMS.get(plat, f"platform_{plat}")
            result["min_os"] = _macho_version(
                int.from_bytes(cmds[pos + 12 : pos + 16], order)  # type: ignore[arg-type]
            )
            sdk = int.from_bytes(cmds[pos + 16 : pos + 20], order)  # type: ignore[arg-type]
            if sdk:
                result["sdk"] = _macho_version(sdk)
            ntools = int.from_bytes(cmds[pos + 20 : pos + 24], order)  # type: ignore[arg-type]
            tools: list[dict[str, str]] = []
            for index in range(min(ntools, _MACHO_MAX_TOOLS)):
                tool_off = pos + 24 + index * 8
                if tool_off + 8 > pos + cmdsize:
                    break  # a lying ntools must not read past its own command
                tool_id = int.from_bytes(cmds[tool_off : tool_off + 4], order)  # type: ignore[arg-type]
                tool_ver = int.from_bytes(cmds[tool_off + 4 : tool_off + 8], order)  # type: ignore[arg-type]
                tools.append(
                    {
                        "tool": _MACHO_TOOLS.get(tool_id, f"tool_{tool_id}"),
                        "version": _macho_version(tool_ver),
                    }
                )
            if tools:
                result["build_tools"] = tools
        elif cmd in _LC_VERSION_MIN_CMDS and result["platform"] is None and cmdsize >= 16:
            # version_min_command: version then sdk; the command kind itself
            # names the platform (the pre-LC_BUILD_VERSION encoding).
            result["platform"] = _LC_VERSION_MIN_CMDS[cmd]
            result["min_os"] = _macho_version(
                int.from_bytes(cmds[pos + 8 : pos + 12], order)  # type: ignore[arg-type]
            )
            sdk = int.from_bytes(cmds[pos + 12 : pos + 16], order)  # type: ignore[arg-type]
            if sdk:
                result["sdk"] = _macho_version(sdk)
        elif cmd == _LC_RPATH and len(rpaths) < _MACHO_MAX_DYLIBS:
            # rpath_command is an lc_str like the dylinker's; @loader_path /
            # @executable_path tokens stay verbatim -- expansion is dyld's job.
            rpath = _macho_lc_str(cmds, pos, cmdsize, order)
            if rpath:
                rpaths.append(rpath)
        elif cmd == _LC_LOAD_DYLINKER and result["interpreter"] is None:
            result["interpreter"] = _macho_lc_str(cmds, pos, cmdsize, order)
        elif cmd == _LC_ID_DYLIB and result["install_name"] is None:
            result["install_name"] = _macho_lc_str(cmds, pos, cmdsize, order)
        elif cmd == _LC_UUID and result["uuid"] is None and cmdsize >= 24:
            result["uuid"] = _macho_uuid(cmds[pos + 8 : pos + 24])
        elif cmd == _LC_MAIN and result["entryoff"] is None and cmdsize >= 24:
            result["entryoff"] = int.from_bytes(cmds[pos + 8 : pos + 16], order)  # type: ignore[arg-type]
        elif cmd == _LC_SYMTAB and result["symtab"] is None and cmdsize >= 24:
            # symoff, nsyms, stroff, strsize: the symbol table locates the
            # exported symbols and the string table both names them and is what
            # the canary scan greps for the stack-guard imports.
            result["symtab"] = (
                int.from_bytes(cmds[pos + 8 : pos + 12], order),  # type: ignore[arg-type]
                int.from_bytes(cmds[pos + 12 : pos + 16], order),  # type: ignore[arg-type]
                int.from_bytes(cmds[pos + 16 : pos + 20], order),  # type: ignore[arg-type]
                int.from_bytes(cmds[pos + 20 : pos + 24], order),  # type: ignore[arg-type]
            )
        elif (
            cmd in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64)
            and result["encryption"] is None
            and cmdsize >= 20
        ):
            # cryptoff/cryptsize then cryptid, in both the 32- and 64-bit
            # layouts (the 64-bit one only appends padding).
            result["encryption"] = (
                int.from_bytes(cmds[pos + 8 : pos + 12], order),  # type: ignore[arg-type]
                int.from_bytes(cmds[pos + 12 : pos + 16], order),  # type: ignore[arg-type]
                int.from_bytes(cmds[pos + 16 : pos + 20], order),  # type: ignore[arg-type]
            )
        elif cmd == _LC_CODE_SIGNATURE and result["code_signature"] is None and cmdsize >= 16:
            # linkedit_data_command: dataoff/datasize locate the SuperBlob.
            result["code_signature"] = (
                int.from_bytes(cmds[pos + 8 : pos + 12], order),  # type: ignore[arg-type]
                int.from_bytes(cmds[pos + 12 : pos + 16], order),  # type: ignore[arg-type]
            )
        elif cmd == _LC_SEGMENT_64 and cmdsize >= 56:
            # segname(16) then vmaddr/vmsize/fileoff/filesize as u64s.
            segments.append(
                (
                    int.from_bytes(cmds[pos + 24 : pos + 32], order),  # type: ignore[arg-type]
                    int.from_bytes(cmds[pos + 40 : pos + 48], order),  # type: ignore[arg-type]
                    int.from_bytes(cmds[pos + 48 : pos + 56], order),  # type: ignore[arg-type]
                )
            )
            # initprot at +60: write+execute together is the W^X violation.
            if cmdsize >= 64:
                initprot = int.from_bytes(cmds[pos + 60 : pos + 64], order)  # type: ignore[arg-type]
                if initprot & _VM_PROT_WRITE and initprot & _VM_PROT_EXECUTE:
                    result["wx_segments"] += 1
            # nsects section_64 headers (80 bytes: size u64 at +40, flags u32
            # at +64) follow the 72-byte segment header; the walk is bounded
            # by the command's own size, so a lying nsects reads nothing.
            if cmdsize >= 72:
                nsects = int.from_bytes(cmds[pos + 64 : pos + 68], order)  # type: ignore[arg-type]
                for i in range(nsects):
                    sect = pos + 72 + 80 * i
                    if sect + 80 > pos + cmdsize:
                        break
                    size = int.from_bytes(cmds[sect + 40 : sect + 48], order)  # type: ignore[arg-type]
                    sect_off = int.from_bytes(cmds[sect + 48 : sect + 52], order)  # type: ignore[arg-type]
                    flags = int.from_bytes(cmds[sect + 64 : sect + 68], order)  # type: ignore[arg-type]
                    _macho_tally_init_section(result, flags, size, 8)
                    if len(sections) < _NATIVE_MAX_MACHO_SECTIONS:
                        sections.append(
                            (_macho_sectname(cmds[sect : sect + 16]), sect_off, size)
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
            # initprot at +44: write+execute together is the W^X violation.
            if cmdsize >= 48:
                initprot = int.from_bytes(cmds[pos + 44 : pos + 48], order)  # type: ignore[arg-type]
                if initprot & _VM_PROT_WRITE and initprot & _VM_PROT_EXECUTE:
                    result["wx_segments"] += 1
            # nsects section headers (68 bytes: size u32 at +36, flags u32 at
            # +56) follow the 56-byte segment header, bounded the same way.
            if cmdsize >= 56:
                nsects = int.from_bytes(cmds[pos + 48 : pos + 52], order)  # type: ignore[arg-type]
                for i in range(nsects):
                    sect = pos + 56 + 68 * i
                    if sect + 68 > pos + cmdsize:
                        break
                    size = int.from_bytes(cmds[sect + 36 : sect + 40], order)  # type: ignore[arg-type]
                    sect_off = int.from_bytes(cmds[sect + 40 : sect + 44], order)  # type: ignore[arg-type]
                    flags = int.from_bytes(cmds[sect + 56 : sect + 60], order)  # type: ignore[arg-type]
                    _macho_tally_init_section(result, flags, size, 4)
                    if len(sections) < _NATIVE_MAX_MACHO_SECTIONS:
                        sections.append(
                            (_macho_sectname(cmds[sect : sect + 16]), sect_off, size)
                        )
        pos += cmdsize
    return result


def _macho_tally_init_section(
    result: dict[str, Any], flags: int, size: int, ptr_width: int
) -> None:
    """Count one section's contribution to the load-time init/term surface.

    Init and term pointer sections hold pointer-width entries; the newer
    S_INIT_FUNC_OFFSETS type holds 32-bit offsets regardless of pointer width.
    Counts are clamped so a section header lying about its size yields a
    bounded number rather than a fantastical one.
    """
    section_type = flags & _S_SECTION_TYPE_MASK
    if section_type == _S_MOD_INIT_FUNC_POINTERS:
        key, width = "mod_init", ptr_width
    elif section_type == _S_MOD_TERM_FUNC_POINTERS:
        key, width = "mod_term", ptr_width
    elif section_type == _S_INIT_FUNC_OFFSETS:
        key, width = "mod_init", 4
    else:
        return
    total = result[key] + max(size, 0) // width
    result[key] = min(total, _MACHO_MAX_INIT_FUNCS)


def _macho_sectname(raw: bytes) -> str:
    """Decode a Mach-O 16-byte sectname field (null-padded, "__data" style)."""
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")


def _macho_section_payloads(
    stream: BinaryIO, sections: list[tuple[str, int, int]]
) -> tuple[list[dict[str, Any]], int]:
    """Sections whose bytes open with executable magic, and how many there are.

    The Mach-O arm of the payload census, symmetrical to the ELF one: a dropper
    linked as a Mach-O hides its stage two in a section (a ``__data,__payload``
    it writes out and runs). Each section carries a file offset and size in the
    segment's section header; this sniffs the first bytes of every section that
    occupies file bytes (a zero offset means S_ZEROFILL/__bss, no file content)
    and names each hit by its section name -- the llvm-objdump ``-s`` view.

    Bounded and fail-closed: the section list is already capped by the caller,
    only the first 0x40 bytes of each are read, the reported list is capped (the
    count stays exact), and any read hiccup skips that section.
    """
    try:
        file_size = stream.seek(0, 2)
    except OSError:
        return [], 0
    payloads: list[dict[str, Any]] = []
    found = 0
    for name, offset, size in sections:
        if size < 4 or offset <= 0 or offset >= file_size:
            continue
        try:
            stream.seek(offset)
            # Clamp the sniff to the section's own bytes so a short section
            # cannot be padded past the PE floor by whatever follows it.
            head = stream.read(min(size, _NATIVE_SECTION_SNIFF))
        except OSError:
            continue
        kind = _native_sniff_kind(head)
        if kind is None:
            continue
        found += 1
        if len(payloads) < _NATIVE_MAX_SECTION_PAYLOADS:
            payloads.append({"section": name, "kind": kind, "size": size})
    return payloads, found


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
