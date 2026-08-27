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

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.common.json_budget import (
    RESULT_BUDGET_BYTES,
    fit_json_list,
    fit_json_text,
)

JsonObject = dict[str, Any]
_MAX_STDERR = 8000
_MAX_LISTED_FILES = 2000
_MAX_COUNTED_FILES = 50_000


def _capped_java_listing(root: Path, *, cap: int) -> tuple[list[str], int, bool]:
    names: list[str] = []
    total = 0
    has_more = False
    if not root.is_dir():
        return [], 0, False
    for path in root.rglob("*.java"):
        if not path.is_file():
            continue
        total += 1
        if len(names) < cap:
            names.append(str(path.relative_to(root)))
        else:
            has_more = True
        if total >= _MAX_COUNTED_FILES:
            has_more = True
            break
    names.sort()
    return names, total, has_more


class JadxError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _note_partial_decompile(result: JsonObject, *, code: int, stderr: str) -> JsonObject:
    """Say when jadx exited non-zero but still wrote sources.

    jadx is deliberately kept on the "return what we got" path: it exits
    non-zero when it fails to decompile some classes yet still writes the ones
    it managed, and writes a stub carrying a ``// jadx failed to decompile ...``
    comment for the ones it did not. ``_run`` only fails hard when *nothing*
    landed; a partial run otherwise came back indistinguishable from a clean
    one, so an agent read a tree missing classes (or a class body that is really
    a jadx error stub) as the finished decompilation. ``tool_failed`` -- the same
    flag the jsre/wabt CLIs already raise for their own partial exits -- says the
    child itself signalled failure, so the sources may be incomplete for a reason
    this side cannot see.
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
        java_files, java_file_count, has_more = _capped_java_listing(
            out_dir, cap=_MAX_LISTED_FILES
        )
        # Bound the listing by its JSON-encoded size too, not only the count cap:
        # 2000 deeply-nested class paths can sum past the result budget on a large
        # APK, and the transport then discards the whole export result --
        # output_dir, counts, and all -- for a ~16 KiB summary. fit_json_list drops
        # trailing paths so the reply survives; has_more already means "the listing
        # is incomplete", so folding the budget cut into it keeps that honest.
        java_files, _dropped, budget_cut = fit_json_list(java_files)
        result: JsonObject = {
            "output_dir": str(out_dir),
            "sources_dir": str(sources_root) if sources_root.is_dir() else None,
            "java_file_count": java_file_count,
            "java_files": java_files,
            "has_more": has_more or budget_cut,
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
        export = self.export_sources(apk, out_dir, timeout=timeout)
        rel = _class_to_java_path(target)
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
                raw = handle.read(RESULT_BUDGET_BYTES + 1)
        except OSError as exc:
            raise JadxError("backend_error", f"failed to read source: {exc}") from exc
        # Read only as many raw bytes as could ever survive the encoded budget
        # (the JSON-encoded form is never smaller than the raw bytes), plus one
        # to notice a larger file, then bound the returned text by its encoded
        # size. A raw-byte cap above the transport budget -- the old 400 KB one
        # was -- meant a big class was discarded for a ~16 KiB summary instead of
        # returned cleanly truncated.
        file_truncated = len(raw) > RESULT_BUDGET_BYTES
        text = raw[:RESULT_BUDGET_BYTES].decode("utf-8", errors="replace")
        source, _source_bytes, fit_truncated = fit_json_text(text)
        result: JsonObject = {
            "class_name": target,
            "path": str(candidate),
            "source": source,
            "truncated": file_truncated or fit_truncated,
        }
        # Carry the overall-run failure forward: the requested class exists, but a
        # jadx that exited non-zero may have written this very file as a
        # "// jadx failed to decompile" stub, so the caller must not read the body
        # as clean output just because a file was returned.
        if export.get("tool_failed"):
            result["tool_failed"] = True
            if "exit_code" in export:
                result["exit_code"] = export["exit_code"]
        return result

    def _run(
        self,
        apk: Path,
        extra: list[str],
        out_dir: Path,
        *,
        timeout: float,
    ) -> tuple[str, str, int]:
        if not self.available or self.executable is None:
            raise JadxError("capability_unavailable", "jadx is not configured")
        if not apk.is_file():
            raise JadxError("not_found", "apk not found", path=str(apk))
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
