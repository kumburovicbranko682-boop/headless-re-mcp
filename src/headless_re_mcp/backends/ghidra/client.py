from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
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
        # Ghidra >= 11.3 dropped the Jython script provider for PyGhidra, so a
        # -postScript .py run only works when launched through PyGhidra. Detect
        # that install shape once and route the launch accordingly, leaving the
        # analyzeHeadless/Jython path (still shipped by <= 11.2 and by Windows
        # installs) exactly as it was.
        self.uses_pyghidra = _pyghidra_required(home)

    @property
    def available(self) -> bool:
        if self.analyze is None or self.java is None:
            return False
        if self.uses_pyghidra:
            return importlib.util.find_spec("pyghidra") is not None
        return True

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
        payload["export_path"] = str(out_path)
        payload["project_dir"] = str(project_dir)
        if mode == "decompile":
            # The postScript records `function`/`entry` only when it found one
            # containing the address; an address inside no function comes back
            # with `decompiled` empty, which reads exactly like a function whose
            # body decompiled to nothing. Surface `found` so a caller can tell
            # "no function here" from "decompiled to nothing". The JSON crosses
            # a foreign-interpreter boundary, so derive it here when the script
            # did not emit it rather than trusting the field to be present.
            payload.setdefault("found", bool(payload.get("function")))
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
        if self.uses_pyghidra:
            return self._run_pyghidra(
                project_dir,
                binary=binary,
                extra=extra,
                timeout=timeout,
                max_heap=max_heap,
                delete_project=delete_project,
            )
        assert self.analyze is not None
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        env = os.environ.copy()
        # Bound JVM heap; CREATE_NO_WINDOW keeps analyzer GUI-free. Prepend, do
        # not overwrite: operators set JAVA_TOOL_OPTIONS for a proxy, an encoding,
        # or the --add-opens a JDK 17+ Ghidra needs, and clobbering it here would
        # silently break analyzeHeadless on their machine. Ours goes first so the
        # heap bound is the default while an explicit operator -Xmx, which the JVM
        # parses last, still wins.
        existing = env.get("JAVA_TOOL_OPTIONS", "").strip()
        env["JAVA_TOOL_OPTIONS"] = f"-Xmx{max_heap} {existing}".strip()
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

    def _run_pyghidra(
        self,
        project_dir: Path,
        *,
        binary: Path,
        extra: list[str],
        timeout: float,
        max_heap: str,
        delete_project: bool,
    ) -> tuple[str, str, int]:
        """Launch the same export script through PyGhidra for modern Ghidra.

        PyGhidra runs a ``.py`` script directly rather than via analyzeHeadless'
        ``-postScript``/``-scriptPath`` machinery, so the analyzeHeadless flags
        are translated into PyGhidra's positional model. The Ghidra project is
        kept in a private subdirectory so the export JSON the caller reads back
        (written under ``project_dir``) survives the post-run cleanup, matching
        the ``-deleteProject`` behaviour of the Jython path.
        """
        script_name, script_args = _split_post_script(extra)
        # Ghidra's ProjectLocator rejects path elements beginning with '.', so
        # this holding directory for the throwaway project must be dot-free.
        proj_home = project_dir / "pyghidra_project"
        proj_home.mkdir(parents=True, exist_ok=True)
        if script_name is None:
            # A bare PyGhidra invocation with no script drops into a REPL, which
            # would hang headless. analyze-only callers just want import+analyze,
            # so run the export in a throwaway mode to drive analysis and discard
            # the result into the project directory that is about to be deleted.
            script_name = _EXPORT_SCRIPT
            script_args = ["functions", str(proj_home / "_analyze_probe.json"), "1", ""]
        script_path = _SCRIPT_DIR / script_name
        env = os.environ.copy()
        env["GHIDRA_INSTALL_DIR"] = str(self.home)
        env["JAVA_TOOL_OPTIONS"] = f"-Xmx{max_heap}"
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        cmd = [
            sys.executable,
            "-m",
            "pyghidra",
            "--project-path",
            str(proj_home),
            "--project-name",
            "HeadlessRE",
            str(binary),
            str(script_path),
            *script_args,
        ]
        try:
            with _project_lock(project_dir):
                completed = run_bounded(
                    cmd, timeout=timeout, creationflags=creationflags, env=env
                )
        except TimedOut as exc:
            raise GhidraError(
                "timeout",
                "ghidra pyghidra headless timed out",
                timeout=timeout,
                killed_pids=exc.killed,
            ) from exc
        except OSError as exc:
            raise GhidraError(
                "backend_error",
                f"failed to launch pyghidra: {exc}",
            ) from exc
        finally:
            if delete_project:
                shutil.rmtree(proj_home, ignore_errors=True)
        stdout = completed.stdout.decode("utf-8", errors="replace")[:_MAX_STDOUT]
        stderr = completed.stderr.decode("utf-8", errors="replace")[:50_000]
        return stdout, stderr, int(completed.returncode)


def _which(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found) if found else None


def _find_analyze_headless(home: Path | None) -> Path | None:
    if home is None:
        return None
    # Ghidra ships both launchers side by side: analyzeHeadless.bat for Windows
    # and an extensionless shell script for POSIX. The .bat is not executable on
    # Linux, so picking it first (as a fixed tuple did) made a real install fail
    # to launch. Prefer the current platform's own launcher, keeping the other
    # as a fallback for unusual layouts.
    names = (
        ("analyzeHeadless.bat", "analyzeHeadless")
        if os.name == "nt"
        else ("analyzeHeadless", "analyzeHeadless.bat")
    )
    for base in (home / "support", home):
        for name in names:
            candidate = base / name
            if candidate.is_file():
                return candidate
    return None


def _pyghidra_required(home: Path | None) -> bool:
    """Whether this install needs PyGhidra to run a Python postScript.

    Ghidra >= 11.3 removed the Jython feature and routes ``.py`` scripts through
    PyGhidra. Detect that by the presence of the PyGhidra feature together with
    the absence of Jython, so a Jython-capable install (<= 11.2) keeps the
    analyzeHeadless launch that the rest of the adapter and its tests assume.
    """
    if home is None:
        return False
    features = home / "Ghidra" / "Features"
    return (features / "PyGhidra").is_dir() and not (features / "Jython").is_dir()


def _split_post_script(extra: list[str]) -> tuple[str | None, list[str]]:
    """Pull the postScript name and its arguments out of analyzeHeadless flags.

    The adapter builds one ``extra`` list for both launch paths; PyGhidra takes
    the script positionally, so recover ``(script_name, script_args)`` from the
    ``-postScript`` marker and drop the ``-scriptPath``/``-postScript`` flags.
    """
    if "-postScript" not in extra:
        return None, []
    index = extra.index("-postScript")
    name = extra[index + 1] if index + 1 < len(extra) else None
    return name, list(extra[index + 2 :])
