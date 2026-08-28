"""ELF static-analysis service methods (pure stdlib, no r2/Ghidra).

Native code -- an Android app's ``lib/**/*.so``, a Linux executable, an ELF
malware sample -- could only be opened here through r2 or Ghidra, external tools
that are not always installed. This mixin reads a standalone ELF by path with the
stdlib alone: elf_summary returns the header/section/dependency triage,
elf_symbols pages through the dynamic symbol table (imports and exports) and
elf_segments reads the program header table (the loadable view plus the
interp/nx/relro/W^X security posture), so a native binary is a first-class
thing to inspect offline. These are core,
path-based tools -- no session, no target kind -- so they stay visible in every
workspace profile.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.elf import (
    ElfParseError,
    list_elf_segments,
    list_elf_symbols,
    summarize_elf,
)
from headless_re_mcp.core.limits import ELF_SUMMARY_MAX_BYTES
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _failure, _success

JsonObject = dict[str, Any]


def _err(code: str, message: str, **details: object) -> Result[JsonObject]:
    return Result[JsonObject](ok=False, error=RpcError(code=code, message=message, details=details))


class _ElfFileError(Exception):
    """A path that cannot be read as an ELF, carrying its error envelope."""

    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.details = details


def _load_elf(path: str) -> bytes:
    """The bytes of the ELF at ``path``, or _ElfFileError naming what's wrong."""
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise _ElfFileError("not_found", "elf file not found", path=str(resolved))
    try:
        size = int(resolved.stat().st_size)
    except OSError as exc:
        raise _ElfFileError("backend_error", f"elf unreadable: {exc}", path=str(resolved)) from exc
    if size > ELF_SUMMARY_MAX_BYTES:
        raise _ElfFileError(
            "too_large",
            f"elf is {size} bytes, over the {ELF_SUMMARY_MAX_BYTES}-byte limit",
            path=str(resolved),
            size=size,
            cap=ELF_SUMMARY_MAX_BYTES,
        )
    try:
        return resolved.read_bytes()
    except OSError as exc:
        raise _ElfFileError("backend_error", f"elf unreadable: {exc}", path=str(resolved)) from exc


class ElfAnalysisMixin:
    """Bounded, offline ELF triage for a standalone binary given by path."""

    def elf_summary(self, path: str) -> Result[JsonObject]:
        """Summarise an ELF binary with the stdlib -- no r2/Ghidra needed.

        Reads a standalone ELF (a Linux executable, or an .so pulled from an
        APK) by path and returns the header (class/endianness/type/machine/
        entry), the section list and the shared-library dependencies from
        .dynamic, plus whether it is stripped. A file that is not an ELF is
        invalid_params, one over the 128 MiB cap too_large, a missing one
        not_found.
        """
        try:
            summary = summarize_elf(_load_elf(path))
            return _success(summary, backend="elf")
        except _ElfFileError as exc:
            return _err(exc.code, str(exc), **exc.details)
        except ElfParseError as exc:
            return _err("invalid_params", str(exc))
        except BaseException as exc:
            return _failure(exc)

    def elf_symbols(self, path: str, *, offset: int = 0, limit: int = 200) -> Result[JsonObject]:
        """One page of an ELF's dynamic symbols: what it imports and exports.

        Reads .dynsym -- the symbol table that survives stripping -- and names
        each entry with its binding, type, value, size and section index, plus
        imported/exported booleans. A binary with no .dynsym (statically
        linked) is an empty listing with a warning, not an error; the same
        file-level failures as elf_summary apply.
        """
        try:
            listing = list_elf_symbols(_load_elf(path), offset=offset, limit=limit)
            return _success(listing, backend="elf")
        except _ElfFileError as exc:
            return _err(exc.code, str(exc), **exc.details)
        except ElfParseError as exc:
            return _err("invalid_params", str(exc))
        except BaseException as exc:
            return _failure(exc)

    def elf_segments(self, path: str) -> Result[JsonObject]:
        """The ELF program header table: loadable segments and security posture.

        Reads the program headers -- the segments the kernel maps -- the way
        ``readelf -l`` shows them: each with type, rwx permissions, offsets and
        sizes; plus the dynamic linker path from PT_INTERP, whether the stack is
        non-executable (nx), whether RELRO is present (relro) and whether any
        loadable segment is both writable and executable (a W^X violation). The
        same file-level failures as elf_summary apply.
        """
        try:
            listing = list_elf_segments(_load_elf(path))
            return _success(listing, backend="elf")
        except _ElfFileError as exc:
            return _err(exc.code, str(exc), **exc.details)
        except ElfParseError as exc:
            return _err("invalid_params", str(exc))
        except BaseException as exc:
            return _failure(exc)
