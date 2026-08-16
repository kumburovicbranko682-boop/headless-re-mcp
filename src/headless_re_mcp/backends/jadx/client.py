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

JsonObject = dict[str, Any]
_MAX_SOURCE_BYTES = 400_000
_MAX_STDERR = 8000


class JadxError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


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
        self._run(
            apk,
            ["--output-dir", str(out_dir), *(["--no-imports"] if no_imports else [])],
            out_dir,
            timeout=timeout,
        )
        sources_root = out_dir / "sources"
        java_files = (
            sorted(str(p.relative_to(out_dir)) for p in out_dir.rglob("*.java"))
            if out_dir.is_dir()
            else []
        )
        listed = java_files[:2000]
        return {
            "output_dir": str(out_dir),
            "sources_dir": str(sources_root) if sources_root.is_dir() else None,
            "java_file_count": len(java_files),
            "java_files": listed,
            # A caller deciding "these are all the classes" has to know
            # whether the tree ended or this list merely stopped.
            "has_more": len(java_files) > len(listed),
        }

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
        self.export_sources(apk, out_dir, timeout=timeout)
        rel = _class_to_java_path(target)
        candidate = out_dir / "sources" / rel
        if not candidate.is_file():
            matches = (
                [p for p in (out_dir / "sources").rglob(candidate.name)]
                if (out_dir / "sources").is_dir()
                else []
            )
            if not matches:
                raise JadxError(
                    "not_found",
                    "decompiled class not found",
                    class_name=class_name,
                    expected=str(rel),
                )
            candidate = matches[0]
        source = candidate.read_text(encoding="utf-8", errors="replace")
        return {
            "class_name": target,
            "path": str(candidate),
            "source": source[:_MAX_SOURCE_BYTES],
            "truncated": len(source) > _MAX_SOURCE_BYTES,
        }

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
    smali = class_name
    if smali.startswith("L") and smali.endswith(";"):
        smali = smali[1:-1]
    dotted = smali.replace("/", ".")
    # jadx drops inner-class suffixes into the outer file.
    dotted = dotted.split("$", 1)[0]
    return Path(*dotted.split(".")).with_suffix(".java")
