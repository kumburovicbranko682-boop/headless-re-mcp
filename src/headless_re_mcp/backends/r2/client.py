from __future__ import annotations

import json
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
        "iij",
        "iEj",
        "pdj",
        "aa",
    }
)
_PDJ_COMMAND = re.compile(r"pdj ([1-9][0-9]*) @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
# axtj (references *to*) and axfj (references *from*) at a bounded address.
# Plain ``axj`` is deliberately not accepted: in modern radare2 it is a write
# command ("add jmp reference"), not a listing, so xrefs uses the per-address
# ``ax[tf]j`` list commands instead.
_AXTF_COMMAND = re.compile(r"ax[tf]j @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")


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
    if _AXTF_COMMAND.fullmatch(command) is not None:
        return
    raise R2Error("invalid_params", "r2 command not whitelisted", command=command)


def _xref_entries(value: object) -> list[JsonObject]:
    """The dict entries of a parsed ax*j array, dropping anything malformed."""
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


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
        # Modern radare2's ``axj`` is a write ("add jmp reference"), not a
        # listing, so references are gathered with the per-address list commands:
        # ``axtj`` for references *to* the address and ``axfj`` for references
        # *from* it. They are run as separate analyses so an empty side stays an
        # empty list instead of being swallowed by the other command's output.
        to_raw = self._exec(binary, ["aa", f"axtj @ {address}"], timeout=timeout)
        from_raw = self._exec(binary, ["aa", f"axfj @ {address}"], timeout=timeout)
        merged: list[JsonObject] = []
        for entry in _xref_entries(parse_r2_json(to_raw.decode("utf-8", errors="replace"))):
            item = dict(entry)
            # axtj names only the source; the queried address is the target.
            item.setdefault("to", address)
            merged.append(item)
        for entry in _xref_entries(parse_r2_json(from_raw.decode("utf-8", errors="replace"))):
            item = dict(entry)
            item.setdefault("from", address)
            merged.append(item)
        payload: JsonObject = {
            "raw": json.dumps(merged),
            "commands": [f"axtj @ {address}", f"axfj @ {address}"],
            "address": address,
        }
        return enrich_r2_payload(payload, binary=binary)

    def _exec(self, binary: Path, commands: list[str], *, timeout: float) -> bytes:
        """Run whitelisted r2 commands one-shot and return raw stdout, or raise."""
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
        if completed.returncode != 0:
            raise R2Error(
                "backend_error",
                "r2 exited non-zero",
                exit_code=completed.returncode,
                stderr=completed.stderr[:_MAX_OUTPUT].decode("utf-8", errors="replace")[:2000],
            )
        return completed.stdout

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0) -> JsonObject:
        stdout = self._exec(binary, commands, timeout=timeout)
        produced = len(stdout)
        out = stdout[:_MAX_OUTPUT]
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
