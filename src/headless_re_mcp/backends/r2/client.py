from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload, parse_r2_json

JsonObject = dict[str, Any]
_MAX_OUTPUT = 1_000_000
# The same 4096 bound the enrich path uses for object lists; a real dependency
# list is a handful of names, so anything near this is a hostile fan-out.
_MAX_LIBRARIES = 4096
_ALLOWED = frozenset(
    {
        "i",
        "ii",
        "iI",
        "is",
        "il",
        "ie",
        "aflj",
        "izj",
        "izzj",
        "iij",
        "iEj",
        "iSj",
        "isj",
        "irj",
        "ilj",
        "iej",
        "pdj",
        "axj",
        "aa",
    }
)
_PDJ_COMMAND = re.compile(r"pdj ([1-9][0-9]*) @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
# axj (all refs), axtj (refs to a seek), axfj (refs from a seek); the seek is
# what makes the address meaningful, so only the seeked forms are whitelisted.
_AXJ_COMMAND = re.compile(r"ax[tf]?j @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")


class R2Error(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _require_allowed_command(command: str) -> None:
    if command in _ALLOWED:
        return
    pdj = _PDJ_COMMAND.fullmatch(command)
    if pdj is not None and int(pdj.group(1)) <= 512:
        return
    if _AXJ_COMMAND.fullmatch(command) is not None:
        return
    raise R2Error("invalid_params", "r2 command not whitelisted", command=command)


class R2Client:
    def __init__(self, executable: Path | None = None) -> None:
        self.executable = executable or _discover()

    @property
    def available(self) -> bool:
        return self.executable is not None and self.executable.is_file()

    def open(self, binary: Path, *, timeout: float = 30.0) -> JsonObject:
        """Validate that r2 can open ``binary`` (one-shot; no persistent pipe)."""
        if not binary.is_file():
            raise R2Error("not_found", "binary not found", path=str(binary))
        data = self.run(binary, ["i"], timeout=timeout)
        return {
            "opened": True,
            "binary": str(binary),
            "info": data.get("raw", "")[:8000],
            "note": "r2.open is one-shot validation; subsequent tools reopen the binary",
        }

    def disasm(
        self,
        binary: Path,
        address: int,
        *,
        count: int = 32,
        timeout: float = 30.0,
    ) -> JsonObject:
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        if type(count) is not int or not 1 <= count <= 512:
            raise R2Error("invalid_params", "count must be 1..512")
        cmd = f"pdj {count} @ {address}"
        data = self.run(binary, ["aa", cmd], timeout=timeout)
        data = dict(data)
        data["address"] = address
        data["count"] = count
        return enrich_r2_payload(data, binary=binary)

    def xrefs(
        self,
        binary: Path,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> JsonObject:
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        # axtj lists refs *to* this address, honoring the seek. Plain `axj @ x`
        # ignores the seek entirely and dumps every ref in the binary -- so the
        # requested address was silently discarded and the answer was the same
        # program-wide list no matter what was asked.
        cmd = f"axtj @ {address}"
        data = self.run(binary, ["aa", cmd], timeout=timeout)
        data = dict(data)
        data["address"] = address
        return enrich_r2_payload(data, binary=binary)

    def libraries(self, binary: Path, *, timeout: float = 30.0) -> JsonObject:
        """Linked shared libraries the binary depends on (``ilj``).

        ELF: the ``DT_NEEDED`` list (``libc.so.6`` ...). PE: the imported DLLs.
        This is the "what does it link against" view, distinct from r2.imports
        which lists the individual symbols pulled in. ``ilj`` is a JSON array of
        library-name strings, so the shared enrich path (which shapes arrays of
        objects into addressed items) leaves it empty; the string list is parsed
        here instead. A statically linked binary answers with an empty list.
        """
        data = self.run(binary, ["ilj"], timeout=timeout)
        parsed = parse_r2_json(str(data.get("raw") or ""))
        names: list[str] = []
        total = 0
        truncated = False
        if isinstance(parsed, list):
            for entry in parsed:
                if isinstance(entry, str):
                    name = entry
                elif isinstance(entry, dict):
                    # Newer r2 builds may wrap each library in an object; take a
                    # name/library field so the tool survives that format shift.
                    candidate = entry.get("name") or entry.get("library")
                    name = str(candidate) if candidate else ""
                else:
                    name = ""
                if not name:
                    continue
                total += 1
                if len(names) >= _MAX_LIBRARIES:
                    truncated = True
                    continue
                names.append(name)
        result: JsonObject = {
            "libraries": names,
            "count": len(names),
            "total": total,
            "module": binary.name,
            "commands": ["ilj"],
        }
        if truncated:
            result["libraries_truncated"] = True
            result["libraries_total"] = total
            result["libraries_limit"] = _MAX_LIBRARIES
        return result

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0) -> JsonObject:
        if not self.available or self.executable is None:
            raise R2Error("capability_unavailable", "radare2/rizin is not installed")
        if not binary.is_file():
            raise R2Error("not_found", "binary not found", path=str(binary))
        for cmd in commands:
            _require_allowed_command(cmd)
        script = "\n".join([*commands, "q"])
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            # r2 on PATH is often a launcher script, and subprocess.run kills
            # only that process then drains with no deadline. Measured: a stub
            # that started a child and held the pipes did not return 8s after a
            # 0.8s timeout, and the child was still running.
            completed = run_bounded(
                [str(self.executable), "-q0", "-c", script, str(binary)],
                timeout=timeout,
                creationflags=creationflags,
            )
        except TimedOut as exc:
            raise R2Error(
                "timeout",
                "r2 timed out",
                timeout=timeout,
                killed_pids=exc.killed,
            ) from exc
        except OSError as exc:
            # A configured executable that is present but cannot be launched --
            # not marked +x, or replaced between the is_file() check and the
            # spawn -- makes Popen raise OSError (PermissionError for a
            # non-executable file). Uncaught, that reaches the service envelope
            # as an internal_error with a logged incident, casting a backend
            # misconfiguration as a server defect. The sibling adapters (jadx,
            # apktool, jsre, windbg) all map this to backend_error; r2 did not.
            raise R2Error(
                "backend_error",
                f"failed to launch {self.executable}: {exc}",
            ) from exc
        produced = len(completed.stdout)
        out = completed.stdout[:_MAX_OUTPUT]
        err = completed.stderr[:_MAX_OUTPUT]
        if completed.returncode != 0:
            raise R2Error(
                "backend_error",
                "r2 exited non-zero",
                exit_code=completed.returncode,
                stderr=err.decode("utf-8", errors="replace")[:2000],
            )
        payload: JsonObject = {
            "raw": out.decode("utf-8", errors="replace"),
            "commands": commands,
        }
        if produced > _MAX_OUTPUT:
            # Cut silently, a listing that stopped at the buffer looks like a
            # listing that ended, and this is the analysis text a caller reads
            # to decide where a function finishes.
            payload["truncated"] = True
            payload["output_bytes"] = produced
            payload["returned_bytes"] = len(out)
        return enrich_r2_payload(payload, binary=binary)


def _discover() -> Path | None:
    for name in ("r2", "rizin", "radare2"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None
