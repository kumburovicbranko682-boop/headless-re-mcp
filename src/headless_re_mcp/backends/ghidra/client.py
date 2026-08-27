from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from threading import RLock
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded

JsonObject = dict[str, Any]
_SCRIPT_DIR = Path(__file__).resolve().parent / "scripts"
_EXPORT_SCRIPT = "ExportJson.py"
_MAX_STDOUT = 200_000
_MAX_EXPORT_BYTES = 2_000_000
_PROJECT_LOCKS = tuple(RLock() for _ in range(64))


def _project_lock(project_dir: Path) -> Any:
    key = os.path.normcase(str(project_dir.expanduser().resolve()))
    return _PROJECT_LOCKS[hash(key) % len(_PROJECT_LOCKS)]


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
                stderr=stderr[:4000],
            )
        return {
            "project_dir": str(project_dir),
            "stdout_excerpt": stdout[-8000:],
            "note": (
                "headless import/analyze completed and the project was deleted; "
                "ghidra.functions/decompile/symbols/xrefs each import the binary again"
            ),
        }

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
        with _project_lock(project_dir):
            return self._export_unlocked(
                binary,
                project_dir,
                mode=mode,
                limit=limit,
                address=address,
                timeout=timeout,
                max_heap=max_heap,
            )

    def _export_unlocked(
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
            str(capped),
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
                stderr=stderr[:4000],
                stdout_excerpt=stdout[-4000:],
            )
        if not out_path.is_file():
            raise GhidraError(
                "backend_error",
                "export JSON missing after postScript",
                stderr=stderr[:2000],
            )
        try:
            with out_path.open("rb") as stream:
                encoded = stream.read(_MAX_EXPORT_BYTES + 1)
        except OSError as exc:
            raise GhidraError("backend_error", f"export JSON unreadable: {exc}") from exc
        if len(encoded) > _MAX_EXPORT_BYTES:
            raise GhidraError(
                "too_large",
                "export JSON exceeds cap",
                path=str(out_path),
                size_at_least=len(encoded),
                cap=_MAX_EXPORT_BYTES,
            )
        try:
            payload = json.loads(encoded.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise GhidraError(
                "backend_error",
                "export JSON invalid",
                error=f"{type(exc).__name__}: {exc}",
            ) from exc
        if not isinstance(payload, dict):
            raise GhidraError("backend_error", "export JSON must be an object")
        if code != 0 and not _export_has_content(payload, mode):
            # analyzeHeadless often exits 1 after a real postScript write, so a
            # non-zero exit that still produced content is a success. An empty
            # payload left by a failed script is not that write: returning it
            # would read as a binary with no functions, symbols, xrefs or code.
            raise GhidraError(
                "backend_error",
                "analyzeHeadless export failed",
                exit_code=code,
                stderr=stderr[:4000],
                stdout_excerpt=stdout[-4000:],
            )
        payload["export_path"] = str(out_path)
        payload["project_dir"] = str(project_dir)
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
            with _project_lock(project_dir):
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
        except OSError as exc:
            # A launcher that is present but cannot be executed -- not marked
            # +x, or gone between discovery and spawn -- makes Popen raise
            # OSError. Uncaught, that surfaces as an internal_error incident
            # instead of a backend problem, unlike the sibling run_bounded
            # adapters (jadx, apktool, jsre, windbg) which all map it here.
            raise GhidraError(
                "backend_error",
                f"failed to launch analyzeHeadless: {exc}",
            ) from exc
        stdout = completed.stdout.decode("utf-8", errors="replace")[:_MAX_STDOUT]
        stderr = completed.stderr.decode("utf-8", errors="replace")[:50_000]
        return stdout, stderr, int(completed.returncode)


def _export_has_content(payload: JsonObject, mode: str) -> bool:
    if mode == "decompile":
        text = payload.get("decompiled")
        return isinstance(text, str) and bool(text.strip())
    items = payload.get("items")
    return isinstance(items, list) and bool(items)


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
