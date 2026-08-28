"""ELF static-summary service method (pure stdlib, no r2/Ghidra).

Native code -- an Android app's ``lib/**/*.so``, a Linux executable, an ELF
malware sample -- could only be opened here through r2 or Ghidra, external tools
that are not always installed. This mixin reads a standalone ELF by path with the
stdlib alone and returns the header/section/dependency triage, so a native binary
is a first-class thing to inspect offline. It is a core, path-based tool -- no
session, no target kind -- so it stays visible in every workspace profile.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.elf import ElfParseError, summarize_elf
from headless_re_mcp.core.limits import ELF_SUMMARY_MAX_BYTES
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _failure, _success

JsonObject = dict[str, Any]


def _err(code: str, message: str, **details: object) -> Result[JsonObject]:
    return Result[JsonObject](ok=False, error=RpcError(code=code, message=message, details=details))


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
            resolved = Path(path).expanduser()
            if not resolved.is_file():
                return _err("not_found", "elf file not found", path=str(resolved))
            try:
                size = int(resolved.stat().st_size)
            except OSError as exc:
                return _err("backend_error", f"elf unreadable: {exc}", path=str(resolved))
            if size > ELF_SUMMARY_MAX_BYTES:
                return _err(
                    "too_large",
                    f"elf is {size} bytes, over the {ELF_SUMMARY_MAX_BYTES}-byte limit",
                    path=str(resolved),
                    size=size,
                    cap=ELF_SUMMARY_MAX_BYTES,
                )
            summary = summarize_elf(resolved.read_bytes())
            return _success(summary, backend="elf")
        except ElfParseError as exc:
            return _err("invalid_params", str(exc))
        except BaseException as exc:
            return _failure(exc)
