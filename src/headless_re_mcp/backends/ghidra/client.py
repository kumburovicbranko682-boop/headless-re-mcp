from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded

JsonObject = dict[str, Any]
_SCRIPT_DIR = Path(__file__).resolve().parent / "scripts"
_EXPORT_SCRIPT = "ExportJson.py"
_MAX_STDOUT = 200_000
_MAX_ANALYZE_EXCERPT = 8000
# Same cap as ExportJson.py. The script cuts first so the JSON on disk stays
# bounded; this side says so even when an older script omitted the mark.
_MAX_DECOMPILE_CHARS = 200_000


def _page_export(payload: JsonObject, *, limit: int) -> JsonObject:
    """Cut an export list to the page and say whether anything was left out.

    Measured: 500 functions with limit=256 came back as count=256 and no
    has_more, so an agent treated one page as every function Ghidra found.
    """
    items = payload.get("items")
    if not isinstance(items, list):
        return payload
    page = items[:limit]
    payload["items"] = page
    payload["count"] = len(page)
    payload["limit"] = limit
    payload["has_more"] = bool(payload.get("has_more")) or len(items) > limit
    return payload


def _disclose_decompile(payload: JsonObject) -> JsonObject:
    """Mark a decompilation that was cut at the inline cap.

    Measured: a 250_000-character function came back as 200_000 characters
    with no truncated flag, so an agent treated the prefix as the whole C.
    """
    text = payload.get("decompiled")
    if not isinstance(text, str):
        return payload
    reported = payload.get("bytes")
    original = reported if isinstance(reported, int) and reported >= 0 else len(text)
    already = payload.get("truncated")
    truncated = bool(already) or original > _MAX_DECOMPILE_CHARS or (
        already is None and len(text) >= _MAX_DECOMPILE_CHARS
    )
    payload["decompiled"] = text[:_MAX_DECOMPILE_CHARS]
    payload["truncated"] = truncated
    payload["bytes"] = original
    return payload


class GhidraError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


class GhidraClient:
    def __init__(self, home: Path | None = None, java: Path | None = None) -> None:
        self.home = home
        self.java = java or _which("java")
        self.analyze = _find_analyze_headless(home)
        self._last_stdout_chars: int | None = None

    @property
    def available(self) -> bool:
        return self.analyze is not None and self.java is not None

    def analyze_binary(
        self,
        binary: Path,
        project_dir: Path,
        *,
        timeout: float = 120.0,
        max_heap: str = "2G",
        delete_project: bool = True,
    ) -> JsonObject:
        if not self.available or self.analyze is None:
            raise GhidraError("capability_unavailable", "Ghidra analyzeHeadless is not configured")
        if not binary.is_file():
            raise GhidraError("not_found", "binary not found", path=str(binary))
        project_dir.mkdir(parents=True, exist_ok=True)
        self._last_stdout_chars = None
        stdout, stderr, code = self._run_headless(
            project_dir,
            binary=binary,
            extra=[],
            timeout=timeout,
            max_heap=max_heap,
            delete_project=delete_project,
        )
        if code != 0:
            raise GhidraError(
                "backend_error",
                "analyzeHeadless failed",
                exit_code=code,
                # The failure reason is at the end. Measured: 56032 characters
                # of stderr still came back as 4000 leading I's, so the ERROR
                # line was gone and an agent retried a run it could not see.
                stderr=stderr[-4000:],
            )
        original = (
            self._last_stdout_chars if self._last_stdout_chars is not None else len(stdout)
        )
        excerpt = stdout[-_MAX_ANALYZE_EXCERPT:]
        result: JsonObject = {
            "project_dir": str(project_dir),
            "stdout_excerpt": excerpt,
            "note": "headless import/analyze completed; use ghidra.functions/decompile/symbols/xrefs for exports",
        }
        if original > _MAX_ANALYZE_EXCERPT:
            # Measured: 250000 characters were first sliced to the opening
            # 200000, then tailed to 8000, so the excerpt was the middle of
            # the run and stdout_chars said 200000. An agent treated that
            # middle as the end of analyze.
            result["truncated"] = True
            result["stdout_chars"] = original
            result["returned_chars"] = len(excerpt)
        return result

    def functions(
        self,
        binary: Path,
        project_dir: Path,
        *,
        limit: int = 256,
        timeout: float = 180.0,
        max_heap: str = "2G",
    ) -> JsonObject:
        return self._export(
            binary,
            project_dir,
            mode="functions",
            limit=limit,
            timeout=timeout,
            max_heap=max_heap,
        )

    def symbols(
        self,
        binary: Path,
        project_dir: Path,
        *,
        limit: int = 256,
        timeout: float = 180.0,
        max_heap: str = "2G",
    ) -> JsonObject:
        return self._export(
            binary,
            project_dir,
            mode="symbols",
            limit=limit,
            timeout=timeout,
            max_heap=max_heap,
        )

    def xrefs(
        self,
        binary: Path,
        project_dir: Path,
        address: str | int,
        *,
        limit: int = 256,
        timeout: float = 180.0,
        max_heap: str = "2G",
    ) -> JsonObject:
        return self._export(
            binary,
            project_dir,
            mode="xrefs",
            limit=limit,
            address=address,
            timeout=timeout,
            max_heap=max_heap,
        )

    def decompile(
        self,
        binary: Path,
        project_dir: Path,
        address: str | int,
        *,
        timeout: float = 180.0,
        max_heap: str = "2G",
    ) -> JsonObject:
        return self._export(
            binary,
            project_dir,
            mode="decompile",
            limit=1,
            address=address,
            timeout=timeout,
            max_heap=max_heap,
        )

    def _export(
        self,
        binary: Path,
        project_dir: Path,
        *,
        mode: str,
        limit: int,
        address: str | int | None = None,
        timeout: float,
        max_heap: str,
    ) -> JsonObject:
        if not self.available or self.analyze is None:
            raise GhidraError("capability_unavailable", "Ghidra analyzeHeadless is not configured")
        if not binary.is_file():
            raise GhidraError("not_found", "binary not found", path=str(binary))
        if not (_SCRIPT_DIR / _EXPORT_SCRIPT).is_file():
            raise GhidraError("backend_error", "ExportJson.py missing from package")
        project_dir.mkdir(parents=True, exist_ok=True)
        out_path = project_dir / f"export_{mode}.json"
        if out_path.exists():
            out_path.unlink()
        addr = "" if address is None else (hex(address) if isinstance(address, int) else str(address))
        capped = max(1, min(int(limit), 1024))
        extra = [
            "-scriptPath",
            str(_SCRIPT_DIR),
            "-postScript",
            _EXPORT_SCRIPT,
            mode,
            str(out_path),
            # One extra so a page that fills can be told from a list that ended.
            str(capped + 1),
            addr,
        ]
        stdout, stderr, code = self._run_headless(
            project_dir,
            binary=binary,
            extra=extra,
            timeout=timeout,
            max_heap=max_heap,
            delete_project=True,
        )
        if code != 0 and not out_path.is_file():
            raise GhidraError(
                "backend_error",
                "analyzeHeadless export failed",
                exit_code=code,
                stderr=stderr[-4000:],
                stdout_excerpt=stdout[-4000:],
            )
        if not out_path.is_file():
            raise GhidraError(
                "backend_error",
                "export JSON missing after postScript",
                stderr=stderr[-2000:],
            )
        try:
            payload = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise GhidraError("backend_error", "export JSON invalid", error=str(exc)) from exc
        if not isinstance(payload, dict):
            raise GhidraError("backend_error", "export JSON must be an object")
        payload["export_path"] = str(out_path)
        payload["project_dir"] = str(project_dir)
        if isinstance(payload.get("decompiled"), str):
            _disclose_decompile(payload)
        elif mode != "decompile":
            _page_export(payload, limit=capped)
        return payload

    def _run_headless(
        self,
        project_dir: Path,
        *,
        binary: Path,
        extra: list[str],
        timeout: float,
        max_heap: str,
        delete_project: bool,
    ) -> tuple[str, str, int]:
        assert self.analyze is not None
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        env = os.environ.copy()
        # Bound JVM heap; CREATE_NO_WINDOW keeps analyzer GUI-free.
        env["JAVA_TOOL_OPTIONS"] = f"-Xmx{max_heap}"
        cmd = [
            str(self.analyze),
            str(project_dir),
            "HeadlessRE",
            "-import",
            str(binary),
            *extra,
        ]
        if delete_project:
            cmd.append("-deleteProject")
        try:
            completed = run_bounded(
                cmd, timeout=timeout, creationflags=creationflags, env=env
            )
        except TimedOut as exc:
            # analyzeHeadless is a script that starts a JVM. Killing the script
            # alone left that JVM analysing a large binary with nobody waiting
            # for it, holding a core and the project directory.
            raise GhidraError(
                "timeout",
                "ghidra analyzeHeadless timed out",
                timeout=timeout,
                killed_pids=exc.killed,
            ) from exc
        stdout_text = completed.stdout.decode("utf-8", errors="replace")
        stderr_text = completed.stderr.decode("utf-8", errors="replace")
        self._last_stdout_chars = len(stdout_text)
        # Keep the tail: analyzeHeadless writes the outcome at the end, and
        # analyze_binary already excerpts stdout[-8000:]. A prefix cut threw
        # that tail away and then reported the middle as the end of the run.
        stdout = (
            stdout_text[-_MAX_STDOUT:] if len(stdout_text) > _MAX_STDOUT else stdout_text
        )
        stderr = (
            stderr_text[-50_000:] if len(stderr_text) > 50_000 else stderr_text
        )
        return stdout, stderr, int(completed.returncode)


def _which(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found) if found else None


def _find_analyze_headless(home: Path | None) -> Path | None:
    if home is None:
        return None
    for rel in (
        "support/analyzeHeadless.bat",
        "support/analyzeHeadless",
        "analyzeHeadless.bat",
        "analyzeHeadless",
    ):
        candidate = home / rel
        if candidate.is_file():
            return candidate
    return None
