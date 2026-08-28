"""jadx Java decompiler wrapped as a bounded one-shot subprocess.

Same shape as the Ghidra adapter: a configured CLI is invoked with a bounded
timeout into a per-session output directory, and results are read back from
disk. jadx needs a JRE on PATH; when either is missing the tool degrades to
``capability_unavailable`` rather than blocking readiness.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import (
    InvalidTimeout,
    TimedOut,
    clamp_cli_timeout,
    run_bounded,
)
from headless_re_mcp.backends.common.zip_guard import ZipExpansionError, check_zip_expansion

JsonObject = dict[str, Any]
_MAX_SOURCE_BYTES = 400_000
# apk.decompile / export_sources both declare le=1800 in their schema.
_MAX_TIMEOUT_S = 1800.0
_MAX_STDERR = 8000
_MAX_LISTED_FILES = 2000
_MAX_COUNTED_FILES = 50_000


def _capped_java_listing(root: Path, *, cap: int) -> tuple[list[str], int, bool, bool]:
    """Return a sorted alphabetical prefix of the ``.java`` tree, its total,
    whether the returned page is clipped, and whether the *count itself* is a floor.

    Sort before the cap, not after. The whole tree (up to the walk ceiling
    ``_MAX_COUNTED_FILES``) is collected and sorted, then sliced to ``cap`` -- so
    the page is a genuine alphabetical prefix, not an arbitrary rglob-order slice
    that was merely sorted for display. Otherwise a class that sorts early but is
    walked late would sit past ``cap`` and vanish from the middle of a page that
    looked ordered, and a caller scanning the listing for a class name would read
    that gap as "absent". The walk itself is bounded (``_MAX_COUNTED_FILES``), so
    the pre-sort set stays in hand; matches apk.classes / device.packages, which
    page their sorted set rather than sort a raw slice.

    Two truncations are reported separately, matching the jsre unpack listing
    (``has_more`` for the page, ``listing_truncated`` for the walk ceiling) rather
    than folding both into one flag. ``has_more`` says the returned names are a
    clipped view; ``listing_truncated`` says the walk stopped at the ceiling, so
    ``total`` is a floor -- an APK with more than ``_MAX_COUNTED_FILES`` small
    ``.java`` files (well under the tree byte cap that ``_refuse_oversized_tree``
    enforces, so it is not refused first) would otherwise report that ceiling as
    an exact ``java_file_count``, and a caller could not tell it from a tree that
    happens to hold exactly that many.
    """
    if not root.is_dir():
        return [], 0, False, False
    names: list[str] = []
    scan_capped = False
    for path in root.rglob("*.java"):
        if not path.is_file():
            continue
        if len(names) >= _MAX_COUNTED_FILES:
            scan_capped = True
            break
        names.append(str(path.relative_to(root)))
    total = len(names)
    names.sort()
    has_more = total > cap or scan_capped
    return names[:cap], total, has_more, scan_capped


class JadxError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _note_partial_decompile(result: JsonObject, *, code: int, stderr: str) -> JsonObject:
    """Say when jadx exited non-zero but still wrote a source tree.

    jadx routinely exits non-zero on a per-class decompile failure while still
    emitting a usable tree for everything else, so ``_run`` keeps the output
    rather than failing (it only raises when nothing landed on disk). But the
    reply then looked exactly like a clean run, so a caller had no way to tell
    "jadx decompiled the whole APK" from "jadx choked on some classes and these
    are the ones that survived". ``tool_failed`` is distinct from the source
    ``truncated`` flag: it means jadx itself reported failure, so the tree may
    be missing classes for a reason we cannot see here.
    """
    if code != 0:
        result["exit_code"] = code
        result["tool_failed"] = True
        result["stderr"] = stderr[:_MAX_STDERR]
    return result


class JadxClient:
    def __init__(self, executable: Path | None = None) -> None:
        self.executable = executable

    @property
    def available(self) -> bool:
        return self.executable is not None and self.executable.is_file()

    def export_sources(
        self,
        apk: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        no_imports: bool = False,
    ) -> JsonObject:
        """Decompile the whole APK into ``out_dir`` and summarise the tree."""
        _, stderr, code = self._run(
            apk,
            ["--output-dir", str(out_dir), *(["--no-imports"] if no_imports else [])],
            out_dir,
            timeout=timeout,
        )
        sources_root = out_dir / "sources"
        java_files, java_file_count, has_more, listing_truncated = _capped_java_listing(
            out_dir, cap=_MAX_LISTED_FILES
        )
        result: JsonObject = {
            "output_dir": str(out_dir),
            "sources_dir": str(sources_root) if sources_root.is_dir() else None,
            "java_file_count": java_file_count,
            "java_files": java_files,
            "has_more": has_more,
            # java_file_count is a floor when the walk hit its ceiling; a caller
            # reading it as exact would undercount an oversized-by-count tree.
            "listing_truncated": listing_truncated,
        }
        return _note_partial_decompile(result, code=code, stderr=stderr)

    def decompile(
        self,
        apk: Path,
        out_dir: Path,
        class_name: str,
        *,
        timeout: float = 300.0,
    ) -> JsonObject:
        """Decompile the whole APK, then return one class's Java source."""
        target = class_name.strip()
        if not target:
            raise JadxError("invalid_params", "class_name is required")
        # Resolve the class name to its relative source path before the
        # (whole-APK) decompile. _class_to_java_path is a pure local check, and a
        # malformed class_name (a \, :, or NUL character, or a .. / empty path
        # segment) is a cheap local fact that should fail fast as invalid_params
        # -- not after paying for a full jadx run of the entire APK, and not
        # masked by the capability_unavailable that export_sources raises when
        # jadx is missing. A bad class name is bad with or without a decompiler.
        rel = _class_to_java_path(target)
        export = self.export_sources(apk, out_dir, timeout=timeout)
        output_root = out_dir.expanduser().resolve()
        sources = (output_root / "sources").resolve()
        if sources == output_root or not sources.is_relative_to(output_root):
            raise JadxError("backend_error", "jadx sources directory escaped its output root")
        candidate = (sources / rel).resolve()
        if candidate == sources or not candidate.is_relative_to(sources):
            raise JadxError("invalid_params", "class_name escapes the jadx sources directory")
        if not candidate.is_file():
            match = None
            if sources.is_dir():
                # A simple-name walk used to return the first Main.java in the
                # tree, which is whoever jadx happened to emit first -- not
                # necessarily the class the caller named.
                matches = []
                for path in sources.rglob(candidate.name):
                    try:
                        resolved = path.resolve()
                    except (OSError, RuntimeError):
                        continue
                    if resolved.is_relative_to(sources) and resolved.is_file():
                        matches.append(resolved)
                if len(matches) == 1:
                    match = matches[0]
            if match is None:
                raise JadxError(
                    "not_found",
                    "decompiled class not found",
                    class_name=class_name,
                    expected=str(rel),
                )
            candidate = match
        try:
            with candidate.open("rb") as handle:
                raw = handle.read(_MAX_SOURCE_BYTES + 1)
        except OSError as exc:
            raise JadxError("backend_error", f"failed to read source: {exc}") from exc
        truncated = len(raw) > _MAX_SOURCE_BYTES
        source = raw[:_MAX_SOURCE_BYTES].decode("utf-8", errors="replace")
        result: JsonObject = {
            "class_name": target,
            "path": str(candidate),
            "source": source,
            "truncated": truncated,
        }
        # The named class may have decompiled cleanly even when jadx choked on
        # others; carry the whole-run verdict so a partial tree is not read as
        # a complete one.
        for key in ("exit_code", "tool_failed", "stderr"):
            if key in export:
                result[key] = export[key]
        return result

    def _run(
        self,
        apk: Path,
        extra: list[str],
        out_dir: Path,
        *,
        timeout: float,
    ) -> tuple[str, str, int]:
        try:
            timeout = clamp_cli_timeout(timeout, maximum=_MAX_TIMEOUT_S)
        except InvalidTimeout as exc:
            raise JadxError("invalid_params", str(exc)) from exc
        # Validate the caller's apk before the capability gate, the same order
        # decompile's class_name check settled on just above (and web.open /
        # adb._device / jsre): a missing apk (not_found) or a declared zip bomb
        # (too_large) is the caller's mistake with or without jadx installed, and
        # capability_unavailable would send an agent to install a tool when the
        # real fix is the path. Both checks are pure file reads, and the bomb
        # check still lands before the JVM -- its whole purpose.
        # Capability before the apk-existence check, deliberately: when jadx is
        # not installed a missing/bad apk must still read as capability_unavailable
        # (the degradation contract in test_backend_degradation), so a missing
        # optional tool is never misreported as a bad path on a core install.
        # This is the mirror of decompile's class_name check, which runs *before*
        # this: a structurally malformed argument (a pure regex fact) fails as
        # invalid_params up front, but a resource-existence fact waits until the
        # tool that would consume it is known present.
        if not self.available or self.executable is None:
            raise JadxError("capability_unavailable", "jadx is not configured")
        if not apk.is_file():
            raise JadxError("not_found", "apk not found", path=str(apk))
        # jadx extracts resources and writes decompiled sources with only the
        # timeout as a bound; a central directory declaring petabytes fills
        # the disk for minutes before that fires. Refuse before the JVM runs.
        try:
            check_zip_expansion(apk)
        except ZipExpansionError as exc:
            raise JadxError(exc.code, exc.message, **exc.details) from exc
        out_dir.mkdir(parents=True, exist_ok=True)
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        cmd = [str(self.executable), *extra, str(apk)]
        try:
            completed = run_bounded(cmd, timeout=timeout, creationflags=creationflags)
        except TimedOut as exc:
            raise JadxError(
                "timeout", "jadx timed out", timeout=timeout, killed_pids=exc.killed
            ) from exc
        except OSError as exc:
            raise JadxError("backend_error", f"failed to launch jadx: {exc}") from exc
        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace")
        # jadx exits non-zero on partial decompile failures but still writes
        # usable sources, so only fail hard when nothing landed on disk.
        if completed.returncode != 0 and not any(out_dir.rglob("*.java")):
            raise JadxError(
                "backend_error",
                "jadx produced no sources",
                exit_code=int(completed.returncode),
                stderr=stderr[:_MAX_STDERR],
            )
        return stdout, stderr, int(completed.returncode)


def _class_to_java_path(class_name: str) -> Path:
    smali = class_name.strip()
    if smali.startswith("L") and smali.endswith(";"):
        smali = smali[1:-1]
    if any(char in smali for char in ("\\", ":", "\x00")):
        raise JadxError("invalid_params", "class_name contains an invalid path character")
    dotted = smali.replace("/", ".")
    # jadx drops inner-class suffixes into the outer file.
    dotted = dotted.split("$", 1)[0]
    parts = dotted.split(".")
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise JadxError("invalid_params", "class_name contains an invalid path segment")
    return Path(*parts).with_suffix(".java")
