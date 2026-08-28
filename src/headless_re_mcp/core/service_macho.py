"""Mach-O static-summary service method (pure stdlib, no external backend).

With PE covered by a whole tool line and ELF by elf.summary/elf.symbols, Mach-O
-- a macOS dylib, an iOS app's main binary, a Mach-O malware sample -- was the
one first-class native format that could not be opened here at all. This mixin
reads a standalone Mach-O (thin or universal) by path with the stdlib alone and
returns the header/segment/dylib/platform triage. It is a core, path-based tool
-- no session, no target kind -- so it stays visible in every workspace profile.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.macho import MachoParseError, summarize_macho
from headless_re_mcp.core.limits import MACHO_SUMMARY_MAX_BYTES
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _failure, _success

JsonObject = dict[str, Any]


def _err(code: str, message: str, **details: object) -> Result[JsonObject]:
    return Result[JsonObject](ok=False, error=RpcError(code=code, message=message, details=details))


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
            resolved = Path(path).expanduser()
            if not resolved.is_file():
                return _err("not_found", "mach-o file not found", path=str(resolved))
            try:
                size = int(resolved.stat().st_size)
            except OSError as exc:
                return _err("backend_error", f"mach-o unreadable: {exc}", path=str(resolved))
            if size > MACHO_SUMMARY_MAX_BYTES:
                return _err(
                    "too_large",
                    f"mach-o is {size} bytes, over the {MACHO_SUMMARY_MAX_BYTES}-byte limit",
                    path=str(resolved),
                    size=size,
                    cap=MACHO_SUMMARY_MAX_BYTES,
                )
            summary = summarize_macho(resolved.read_bytes())
            return _success(summary, backend="macho")
        except MachoParseError as exc:
            return _err("invalid_params", str(exc))
        except BaseException as exc:
            return _failure(exc)
