from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from threading import RLock
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.ghidra.mapping import enrich_ghidra_payload
from headless_re_mcp.backends.r2.mapping import macho_slice_span
from headless_re_mcp.core.models import Architecture

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
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        if not self.available or self.analyze is None:
            raise GhidraError("capability_unavailable", "Ghidra analyzeHeadless is not configured")
        if not binary.is_file():
            raise GhidraError("not_found", "binary not found", path=str(binary))
        project_dir.mkdir(parents=True, exist_ok=True)
        import_target = (
            binary if slice_arch is None else _carve_slice(binary, project_dir, slice_arch)
        )
        stdout, stderr, code = self._run_headless(
            project_dir,
            binary=import_target,
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
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        return self._export(
            binary,
            project_dir,
            mode="functions",
            limit=limit,
            timeout=timeout,
            max_heap=max_heap,
            slice_arch=slice_arch,
        )

    def symbols(
        self,
        binary: Path,
        project_dir: Path,
        *,
        limit: int = 256,
        timeout: float = 180.0,
        max_heap: str = "2G",
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        return self._export(
            binary,
            project_dir,
            mode="symbols",
            limit=limit,
            timeout=timeout,
            max_heap=max_heap,
            slice_arch=slice_arch,
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
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        return self._export(
            binary,
            project_dir,
            mode="xrefs",
            limit=limit,
            address=address,
            timeout=timeout,
            max_heap=max_heap,
            slice_arch=slice_arch,
        )

    def decompile(
        self,
        binary: Path,
        project_dir: Path,
        address: str | int,
        *,
        timeout: float = 180.0,
        max_heap: str = "2G",
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        return self._export(
            binary,
            project_dir,
            mode="decompile",
            limit=1,
            address=address,
            timeout=timeout,
            max_heap=max_heap,
            slice_arch=slice_arch,
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
        slice_arch: Architecture | None = None,
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
                slice_arch=slice_arch,
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
        slice_arch: Architecture | None = None,
    ) -> JsonObject:
        if not self.available or self.analyze is None:
            raise GhidraError("capability_unavailable", "Ghidra analyzeHeadless is not configured")
        if not binary.is_file():
            raise GhidraError("not_found", "binary not found", path=str(binary))
        if not (_SCRIPT_DIR / _EXPORT_SCRIPT).is_file():
            raise GhidraError("backend_error", "ExportJson.py missing from package")
        project_dir.mkdir(parents=True, exist_ok=True)
        # Ghidra's headless importer offers no load spec for a fat/universal
        # Mach-O (and -processor merely forces a language, importing every
        # slice wrong), so directing Ghidra at a slice means carving that
        # slice -- a complete thin Mach-O -- and importing the carved file.
        # Coordinates are still derived from the original fat, so the module
        # name and frame match what r2 reports for its -a/-b selection.
        import_target = (
            binary if slice_arch is None else _carve_slice(binary, project_dir, slice_arch)
        )
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
            binary=import_target,
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
        payload = enrich_ghidra_payload(payload, binary=binary, slice_arch=slice_arch)
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


def _carve_slice(binary: Path, project_dir: Path, slice_arch: Architecture) -> Path:
    """Extract the ``slice_arch`` slice of a fat Mach-O into the project dir.

    The carved bytes are a complete thin Mach-O (fat table offsets/sizes span
    whole slice files), written under ``slices/<arch>/`` with the original
    file name so the imported program keeps a recognisable identity. Raises
    invalid_params when the file has no such slice -- the same rejection the
    service issues, kept here too so a directly-driven client cannot silently
    import the wrong bytes -- and when a malformed table points past EOF.
    """
    span = macho_slice_span(binary, slice_arch)
    if span is None:
        raise GhidraError(
            "invalid_params",
            f"no {slice_arch.value} slice in this file: slice_arch needs a "
            "fat/universal Mach-O that contains that architecture",
            path=str(binary),
        )
    offset, size = span
    dest_dir = project_dir / "slices" / slice_arch.value
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / binary.name
    remaining = size
    try:
        with binary.open("rb") as source, dest.open("wb") as sink:
            source.seek(offset)
            while remaining > 0:
                chunk = source.read(min(1 << 20, remaining))
                if not chunk:
                    break
                sink.write(chunk)
                remaining -= len(chunk)
    except OSError as exc:
        raise GhidraError("backend_error", f"carving fat slice failed: {exc}") from exc
    if remaining:
        dest.unlink(missing_ok=True)
        raise GhidraError(
            "invalid_params",
            "fat slice table points past the end of the file",
            path=str(binary),
            missing_bytes=remaining,
        )
    return dest


def _which(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found) if found else None


def _find_analyze_headless(home: Path | None) -> Path | None:
    if home is None:
        return None
    # Ghidra ships both launchers side by side: analyzeHeadless (a shell script)
    # and analyzeHeadless.bat. On Linux/macOS the .bat is a Windows batch file
    # the OS cannot exec ("Exec format error"), and on Windows the reverse, so
    # the OS-appropriate launcher has to win rather than whichever is listed
    # first. Both the support/ layout and a flattened root are still accepted.
    names = ("analyzeHeadless.bat", "analyzeHeadless") if os.name == "nt" \
        else ("analyzeHeadless", "analyzeHeadless.bat")
    for directory in (home / "support", home):
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None
