"""webcrack (JS) and wabt (WASM) wrapped as bounded one-shot subprocesses.

Both CLIs are optional and user-provided, exactly like UPX/DIE: a missing tool
degrades to ``capability_unavailable`` rather than blocking readiness. webcrack
needs Node.js 22 or 24; wabt provides ``wasm2wat`` and ``wasm-objdump``.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded

JsonObject = dict[str, Any]
_MAX_INLINE = 400_000
_MAX_STDERR = 8000
_MAX_LISTED_FILES = 2000
_MAX_COUNTED_FILES = 50_000
# Output is already sliced. The child still has to load the file, and an
# unattended pass that pointed js.deobfuscate at a captured bundle started
# node on whatever sat on disk -- measured 2,097,152 bytes still reached
# run_bounded. Sixteen mebibytes is enough for a real module and not enough
# to keep a core busy for the rest of the timeout.
_MAX_INPUT_BYTES = 16 * 1024 * 1024


def _capped_file_listing(root: Path, *, cap: int) -> tuple[list[str], int, bool]:
    names: list[str] = []
    total = 0
    has_more = False
    if not root.is_dir():
        return [], 0, False
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if total >= _MAX_COUNTED_FILES:
            has_more = True
            break
        total += 1
        if len(names) < cap:
            names.append(str(path.relative_to(root)))
        else:
            has_more = True
    names.sort()
    return names, total, has_more


class JsReError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _require_existing_file(path: Path, *, missing: str) -> Path:
    """Resolve a regular file, or refuse one that would bind the child unbounded."""
    resolved = path.expanduser()
    if not resolved.is_file():
        raise JsReError("not_found", missing, path=str(resolved))
    try:
        size = int(resolved.stat().st_size)
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    cap = _MAX_INPUT_BYTES
    if size > cap:
        raise JsReError(
            "too_large",
            f"input exceeds the {cap}-byte tool limit",
            path=str(resolved),
            size=size,
            max_file_size=cap,
        )
    return resolved


def _run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        completed = run_bounded(cmd, timeout=timeout, creationflags=creationflags)
    except TimedOut as exc:
        # webcrack runs under node, which the launcher starts as a child, so
        # the deadline has to reach it too.
        raise JsReError(
            "timeout", "tool timed out", timeout=timeout, killed_pids=exc.killed
        ) from exc
    except OSError as exc:
        raise JsReError("backend_error", f"failed to launch {cmd[0]}: {exc}") from exc
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    return stdout, stderr, int(completed.returncode)


def _bounded_output(
    text: str,
    key: str,
    *,
    include_bytes: bool,
    spill_path: Path | None = None,
) -> JsonObject:
    payload = text.encode("utf-8", errors="replace")
    truncated = len(payload) > _MAX_INLINE
    result: JsonObject = {
        key: payload[:_MAX_INLINE].decode("utf-8", errors="ignore"),
        "truncated": truncated,
    }
    if include_bytes:
        result["bytes"] = len(payload)
    # A truncated inline blob is a dead end: the caller gets the first 400 KB of
    # a deobfuscated bundle or a WAT dump and no way to reach the rest, and a
    # non-trivial module blows past that easily. When the output was cut, write
    # the whole thing next to the other jsre artifacts and hand back its path so
    # the full result stays retrievable (the same spill the web/proxy bodies do).
    if truncated and spill_path is not None:
        try:
            spill_path.parent.mkdir(parents=True, exist_ok=True)
            spill_path.write_bytes(payload)
            result[f"{key}_path"] = str(spill_path)
        except OSError as exc:
            result[f"{key}_path_error"] = str(exc)
    return result


class JsClient:
    """webcrack-backed JavaScript deobfuscation and bundle unpacking."""

    def __init__(self, executable: Path | None = None) -> None:
        self.executable = executable or _discover_webcrack()

    @property
    def available(self) -> bool:
        return self.executable is not None

    def _require_input(self, path: Path) -> Path:
        if self.executable is None:
            raise JsReError(
                "capability_unavailable", "webcrack is not configured (needs Node 22/24)"
            )
        return _require_existing_file(path, missing="input file not found")

    def deobfuscate(
        self, path: Path, *, timeout: float = 120.0, spill_path: Path | None = None
    ) -> JsonObject:
        resolved = self._require_input(path)
        stdout, stderr, code = _run([str(self.executable), str(resolved)], timeout=timeout)
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "webcrack failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _bounded_output(stdout, "code", include_bytes=True, spill_path=spill_path)

    def beautify(
        self, path: Path, *, timeout: float = 120.0, spill_path: Path | None = None
    ) -> JsonObject:
        # webcrack always unminifies; expose it under a formatting-focused name.
        return self.deobfuscate(path, timeout=timeout, spill_path=spill_path)

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        resolved = self._require_input(path)
        # webcrack creates the -o directory itself and refuses to write into one
        # that already exists ("output directory already exists", exit 1).
        # Pre-creating it here made unpack fail every time on webcrack 2.x. Make
        # the parent only; if a caller reuses an empty path, drop it so webcrack
        # can own it, but never clobber a directory that has contents.
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        if out_dir.exists() and out_dir.is_dir() and not any(out_dir.iterdir()):
            with contextlib.suppress(OSError):
                out_dir.rmdir()
        if out_dir.exists():
            # webcrack will not write into an existing directory, so anything
            # here now is pre-existing content, not output. Refuse rather than
            # run webcrack (which would fail) and then report those foreign
            # files as if they were the unpack result.
            raise JsReError(
                "invalid_params",
                "output directory already exists and is not empty",
                path=str(out_dir),
            )
        stdout, stderr, code = _run(
            [str(self.executable), str(resolved), "-o", str(out_dir)], timeout=timeout
        )
        files, file_count, listed_more = _capped_file_listing(out_dir, cap=_MAX_COUNTED_FILES)
        if code != 0 and not files:
            raise JsReError(
                "backend_error",
                "webcrack unpack failed",
                exit_code=code,
                stderr=stderr[:_MAX_STDERR],
            )
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_LISTED_FILES))
        window = files[start : start + cap]
        return {
            "output_dir": str(out_dir),
            "file_count": file_count,
            "files": window,
            "count": len(window),
            "total": file_count,
            "offset": start,
            "has_more": start + len(window) < file_count,
            "listing_truncated": listed_more,
        }


class WasmClient:
    """wabt-backed WebAssembly inspection (wasm2wat, wasm-objdump)."""

    def __init__(self, wabt: Path | None = None) -> None:
        self._wasm2wat = _resolve_wabt_tool(wabt, "wasm2wat")
        self._objdump = _resolve_wabt_tool(wabt, "wasm-objdump")

    @property
    def available(self) -> bool:
        return self._wasm2wat is not None

    def _require_input(self, path: Path, tool: Path | None, name: str) -> Path:
        if tool is None:
            raise JsReError("capability_unavailable", f"{name} (wabt) is not configured")
        return _require_existing_file(path, missing="wasm file not found")

    def wat(
        self, path: Path, *, timeout: float = 120.0, spill_path: Path | None = None
    ) -> JsonObject:
        resolved = self._require_input(path, self._wasm2wat, "wasm2wat")
        assert self._wasm2wat is not None
        stdout, stderr, code = _run([str(self._wasm2wat), str(resolved)], timeout=timeout)
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm2wat failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _bounded_output(stdout, "wat", include_bytes=True, spill_path=spill_path)

    def summary(self, path: Path) -> JsonObject:
        """Structured import/export/memory summary parsed straight from the binary.

        Needs no wabt tool: the module's section table is read in pure Python,
        so the interop surface is available even when wasm2wat/wasm-objdump are
        not configured.
        """
        from headless_re_mcp.backends.jsre.wasm_summary import summarize_wasm

        return summarize_wasm(path)

    def strings(
        self, path: Path, *, min_length: int = 4, contains: str | None = None
    ) -> JsonObject:
        """Printable strings from the module's data segments (pure Python).

        Needs no wabt tool: the data section that initializes linear memory --
        where compiled WASM keeps its string literals -- is parsed directly, so
        the URLs/keys/messages a module embeds are recoverable even when
        wasm2wat/wasm-objdump are not configured.
        """
        from headless_re_mcp.backends.jsre.wasm_summary import extract_wasm_strings

        return extract_wasm_strings(path, min_length=min_length, contains=contains)

    def names(self, path: Path, *, contains: str | None = None) -> JsonObject:
        """Module and function names from the ``name`` custom section (pure Python).

        Needs no wabt tool: the name section -- WASM's debug symbol table, where
        a non-stripped build maps each function index to a readable name -- is
        parsed directly, so internal function names that never reach the export
        table are recoverable even when wasm2wat/wasm-objdump are not configured.
        """
        from headless_re_mcp.backends.jsre.wasm_summary import extract_wasm_names

        return extract_wasm_names(path, contains=contains)

    def sections(self, path: Path) -> JsonObject:
        """The module's section table: id, name, size and file offset (pure Python).

        Needs no wabt tool: the section framing is read directly, so the layout
        -- where the code/data sections start and how big each section is, plus
        every custom section's name and payload size -- is available even when
        wasm2wat/wasm-objdump are not configured.
        """
        from headless_re_mcp.backends.jsre.wasm_summary import extract_wasm_sections

        return extract_wasm_sections(path)

    def functions(self, path: Path, *, contains: str | None = None) -> JsonObject:
        """The module's function table with resolved signatures (pure Python).

        Needs no wabt tool: the type, import and function sections are joined
        directly (and the name section attached when present), so the
        imported-vs-defined split and each function's param/result signature --
        the JS/WASM ABI -- are available even when wasm2wat/wasm-objdump are not
        configured.
        """
        from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_functions

        return list_wasm_functions(path, contains=contains)

    def exports(self, path: Path, *, contains: str | None = None) -> JsonObject:
        """The module's export table -- its callable surface -- with signatures.

        Needs no wabt tool: the export section is joined to the type/import/
        function sections directly, so each exported function's resolved
        params/results (the ABI JS calls into) and the internal name behind the
        export name are available even when wasm2wat/wasm-objdump are absent.
        """
        from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_exports

        return list_wasm_exports(path, contains=contains)

    def imports(self, path: Path, *, contains: str | None = None) -> JsonObject:
        """The module's import table -- what it requires from the host -- decoded.

        Needs no wabt tool: the import section's descriptors are decoded
        directly (func signatures joined through the type section, memory/table
        limits, global mutability), so the host boundary -- env vs WASI, shared
        memory, mutable globals -- is readable even when wasm2wat/wasm-objdump
        are absent.
        """
        from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_imports

        return list_wasm_imports(path, contains=contains)

    def globals(self, path: Path) -> JsonObject:
        """The module's defined globals with type, mutability and init value.

        Needs no wabt tool: the global section is decoded directly, so the
        module's mutable state and seed constants -- the shadow stack pointer,
        the heap base, feature flags -- are readable even when wasm2wat/
        wasm-objdump are absent.
        """
        from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_globals

        return list_wasm_globals(path)

    def info(
        self, path: Path, *, timeout: float = 120.0, spill_path: Path | None = None
    ) -> JsonObject:
        resolved = self._require_input(path, self._objdump, "wasm-objdump")
        assert self._objdump is not None
        stdout, stderr, code = _run(
            [str(self._objdump), "-h", "-x", str(resolved)], timeout=timeout
        )
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm-objdump failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _bounded_output(stdout, "objdump", include_bytes=False, spill_path=spill_path)


def _discover_webcrack() -> Path | None:
    found = shutil.which("webcrack")
    return Path(found) if found else None


def _resolve_wabt_tool(wabt: Path | None, tool: str) -> Path | None:
    exe = tool + (".exe" if os.name == "nt" else "")
    if wabt is not None:
        candidate = wabt if wabt.name.lower().startswith(tool) else wabt / exe
        if candidate.is_file():
            return candidate
        # wabt may point at the bin directory.
        alt = wabt / "bin" / exe
        if alt.is_file():
            return alt
    found = shutil.which(tool)
    return Path(found) if found else None
