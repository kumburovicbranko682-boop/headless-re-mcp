"""Mach-O static-analysis service methods (pure stdlib, no external backend).

With PE covered by a whole tool line and ELF by elf.summary/elf.symbols, Mach-O
-- a macOS dylib, an iOS app's main binary, a Mach-O malware sample -- was the
one first-class native format that could not be opened here at all. This mixin
reads a standalone Mach-O (thin or universal) by path with the stdlib alone:
macho_summary returns the header/segment/dylib/platform triage, macho_symbols
pages through the LC_SYMTAB nlist array (imports and exports), macho_signature
decodes the LC_CODE_SIGNATURE SuperBlob (signing identity, team ID, cdhash,
flags and entitlements) and macho_strings extracts printable literals labelled
by the two-level section they sit in. These are core,
path-based tools -- no session, no target kind -- so they stay visible in every
workspace profile.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.macho import (
    MachoParseError,
    list_macho_strings,
    list_macho_symbols,
    read_macho_signature,
    summarize_macho,
)
from headless_re_mcp.core.limits import MACHO_SUMMARY_MAX_BYTES
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _failure, _success

JsonObject = dict[str, Any]


def _err(code: str, message: str, **details: object) -> Result[JsonObject]:
    return Result[JsonObject](ok=False, error=RpcError(code=code, message=message, details=details))


class _MachoFileError(Exception):
    """A path that cannot be read as a Mach-O, carrying its error envelope."""

    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.details = details


def _load_macho(path: str) -> bytes:
    """The bytes of the Mach-O at ``path``, or _MachoFileError naming what's wrong."""
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise _MachoFileError("not_found", "mach-o file not found", path=str(resolved))
    try:
        size = int(resolved.stat().st_size)
    except OSError as exc:
        raise _MachoFileError(
            "backend_error", f"mach-o unreadable: {exc}", path=str(resolved)
        ) from exc
    if size > MACHO_SUMMARY_MAX_BYTES:
        raise _MachoFileError(
            "too_large",
            f"mach-o is {size} bytes, over the {MACHO_SUMMARY_MAX_BYTES}-byte limit",
            path=str(resolved),
            size=size,
            cap=MACHO_SUMMARY_MAX_BYTES,
        )
    try:
        return resolved.read_bytes()
    except OSError as exc:
        raise _MachoFileError(
            "backend_error", f"mach-o unreadable: {exc}", path=str(resolved)
        ) from exc


class MachoAnalysisMixin:
    """Bounded, offline Mach-O triage for a standalone binary given by path."""

    def macho_summary(self, path: str) -> Result[JsonObject]:
        """Summarise a Mach-O binary with the stdlib -- no external backend.

        Reads a standalone Mach-O (a macOS executable/dylib, an iOS app's main
        binary, or a universal binary) by path and returns the header (CPU,
        filetype, flags), the segments, the linked dylibs/rpaths, the UUID,
        the target platform and minimum OS, and the pie/signed/encrypted/
        stripped booleans; a fat binary answers with one summary per
        architecture slice. A file that is not a Mach-O is invalid_params, one
        over the 128 MiB cap too_large, a missing one not_found.
        """
        try:
            summary = summarize_macho(_load_macho(path))
            return _success(summary, backend="macho")
        except _MachoFileError as exc:
            return _err(exc.code, str(exc), **exc.details)
        except MachoParseError as exc:
            return _err("invalid_params", str(exc))
        except BaseException as exc:
            return _failure(exc)

    def macho_symbols(self, path: str, *, offset: int = 0, limit: int = 200) -> Result[JsonObject]:
        """One page of a Mach-O's LC_SYMTAB symbols: what it imports and exports.

        Names each symbol and says whether it is imported (an undefined
        external, resolved to the dylib its library ordinal names) or exported
        (a defined external); debug stabs are marked as such. A fat binary is
        read on its first architecture slice (the arch and slice list are
        reported); an image with no LC_SYMTAB is an empty listing with a
        warning. The same file-level failures as macho_summary apply.
        """
        try:
            listing = list_macho_symbols(_load_macho(path), offset=offset, limit=limit)
            return _success(listing, backend="macho")
        except _MachoFileError as exc:
            return _err(exc.code, str(exc), **exc.details)
        except MachoParseError as exc:
            return _err("invalid_params", str(exc))
        except BaseException as exc:
            return _failure(exc)

    def macho_signature(self, path: str) -> Result[JsonObject]:
        """The embedded code signature, decoded: identity, flags, entitlements.

        Reads the LC_CODE_SIGNATURE SuperBlob and answers with the
        CodeDirectory identity (signing identifier, Apple Developer team ID,
        cdhash), the decoded flags with the adhoc/hardened_runtime/
        linker_signed verdicts stated directly, the entitlements plist as a
        bounded dict, and the CMS blob size (0 for an ad-hoc signature). An
        unsigned image is signed=false with a warning; a fat binary is read on
        its first architecture slice. The same file-level failures as
        macho_summary apply.
        """
        try:
            listing = read_macho_signature(_load_macho(path))
            return _success(listing, backend="macho")
        except _MachoFileError as exc:
            return _err(exc.code, str(exc), **exc.details)
        except MachoParseError as exc:
            return _err("invalid_params", str(exc))
        except BaseException as exc:
            return _failure(exc)

    def macho_strings(
        self,
        path: str,
        *,
        min_length: int = 4,
        offset: int = 0,
        limit: int = 200,
        section: str | None = None,
    ) -> Result[JsonObject]:
        """Printable string literals, located by the Mach-O section they sit in.

        Extracts runs of printable bytes (at least min_length long) the way
        ``strings`` does, but keeps each one's two-level provenance: the
        segment and section it came from (__TEXT,__cstring for C constants,
        __TEXT,__objc_methname for Objective-C selectors, __objc_classname for
        class names), its file offset and virtual address. A section filter
        (full label or bare name) narrows the scan; a fat binary is read on its
        first slice. The same file-level failures as macho_summary apply.
        """
        try:
            listing = list_macho_strings(
                _load_macho(path),
                min_length=min_length,
                offset=offset,
                limit=limit,
                section=section,
            )
            return _success(listing, backend="macho")
        except _MachoFileError as exc:
            return _err(exc.code, str(exc), **exc.details)
        except MachoParseError as exc:
            return _err("invalid_params", str(exc))
        except BaseException as exc:
            return _failure(exc)
