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
# A Java GhidraScript rather than a .py one: from Ghidra 11.2 the bundled Jython
# is gone and .py postScripts need PyGhidra enabled, which analyzeHeadless does
# not do, so the Python export silently produced nothing. Java scripts compile
# and run under every analyzeHeadless on every OS with no extra runtime.
_EXPORT_SCRIPT = "ExportJson.java"
_MAX_STDOUT = 200_000
_MAX_EXPORT_BYTES = 2_000_000
_PROJECT_LOCKS = tuple(RLock() for _ in range(64))
# One extension install runs at a time: the destination is the shared Ghidra
# install, not a per-project dir, so it cannot key off the project lock.
_PLUGIN_INSTALL_LOCK = RLock()


def _project_lock(project_dir: Path) -> Any:
    key = os.path.normcase(str(project_dir.expanduser().resolve()))
    return _PROJECT_LOCKS[hash(key) % len(_PROJECT_LOCKS)]


def _install_extension(home: Path | None, plugin: Path | None) -> Path | None:
    """Make a configured Ghidra extension discoverable by analyzeHeadless.

    analyzeHeadless only loads extensions that live in a directory it scans --
    chiefly ``<home>/Ghidra/Extensions/<name>``. A plugin the operator unpacked
    somewhere else (``HEADLESS_RE_GHIDRA_WASM_PLUGIN`` points straight at the
    extracted extension dir) is invisible until it sits there, which is why that
    setting used to do nothing and the WASM-via-Ghidra path never engaged.

    Copy it in once, idempotently and best-effort: an already-present or
    already-in-place extension is left alone, and a read-only install (or any
    OSError) simply degrades to "no plugin" -- exactly the prior behaviour --
    rather than failing the analysis. Returns the install path when the
    extension is (now) present, else ``None``.
    """
    if home is None or plugin is None:
        return None
    src = plugin.expanduser()
    # Only an *extracted* extension is safe to drop in; a bare path or a zip is
    # not something analyzeHeadless can load from Extensions/ as-is.
    if not (src / "Module.manifest").is_file():
        return None
    ext_root = home.expanduser().resolve() / "Ghidra" / "Extensions"
    dest = ext_root / src.name
    try:
        if src.resolve() == dest.resolve():
            # Operator already pointed the setting at the install copy.
            return dest
    except OSError:
        pass
    with _PLUGIN_INSTALL_LOCK:
        if dest.exists():
            return dest
        tmp = ext_root / f".{src.name}.tmp-{os.getpid()}"
        try:
            ext_root.mkdir(parents=True, exist_ok=True)
            if tmp.exists():
                shutil.rmtree(tmp, ignore_errors=True)
            shutil.copytree(src, tmp)
            try:
                os.rename(tmp, dest)
            except OSError:
                # Lost the race or dest appeared underneath us; drop the temp.
                shutil.rmtree(tmp, ignore_errors=True)
        except OSError:
            shutil.rmtree(tmp, ignore_errors=True)
            return None
    return dest if dest.exists() else None


class GhidraError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


class GhidraClient:
    def __init__(
        self,
        home: Path | None = None,
        java: Path | None = None,
        wasm_plugin: Path | None = None,
    ) -> None:
        self.home = home
        self.java = java or _which("java")
        self.analyze = _find_analyze_headless(home)
        # Extracted Ghidra extension dir (e.g. ghidra-wasm-plugin) that adds a
        # loader for a non-native format. Installed lazily before the first
        # headless run so construction stays side-effect-free.
        self.wasm_plugin = wasm_plugin

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
            raise GhidraError("backend_error", f"{_EXPORT_SCRIPT} missing from package")
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
        # A configured extension has to be in place before the JVM starts, or
        # the loader it provides (WASM, etc.) is not registered for the import.
        if self.wasm_plugin is not None:
            _install_extension(self.home, self.wasm_plugin)
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


def _which(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found) if found else None


def _find_analyze_headless(home: Path | None) -> Path | None:
    if home is None:
        return None
    # Ghidra ships both launchers side by side in ``support/``: the ``.bat`` for
    # Windows and an extension-less shell script for POSIX. A plain name-order
    # search picked the ``.bat`` first on every platform, so on Linux/macOS the
    # backend tried to exec a non-executable Windows batch file and every call
    # failed with "Permission denied" -- the portable backend was unusable off
    # Windows. Prefer the launcher that matches the host, keeping the historical
    # ``support/`` before top-level preference for each.
    if os.name == "nt":
        names = ("analyzeHeadless.bat", "analyzeHeadless")
    else:
        names = ("analyzeHeadless", "analyzeHeadless.bat")
    candidates = [f"support/{name}" for name in names] + list(names)
    for rel in candidates:
        candidate = home / rel
        if candidate.is_file():
            return candidate
    return None
