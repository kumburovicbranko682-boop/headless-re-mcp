from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import (
    InvalidTimeout,
    TimedOut,
    clamp_cli_timeout,
    run_bounded,
)
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload, parse_r2_json_values

JsonObject = dict[str, Any]
_MAX_OUTPUT = 1_000_000
# Every r2 tool schema declares ``0 < timeout <= 120``. See clamp_cli_timeout.
_MAX_TIMEOUT_S = 120.0
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
# axtj (refs to the seek) and axfj (refs from it) are the address-scoped xref
# queries. Bare "axj @ N" is deliberately not whitelisted: axj ignores the
# seek and dumps the program's whole xref database, so the form reads as
# address-scoped while the address is inert -- exactly the bug xrefs() had.
_AXREF_COMMAND = re.compile(r"ax[tf]j @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")


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
    if _AXREF_COMMAND.fullmatch(command) is not None:
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
        # This used to run "axj @ addr", but axj ignores the seek and lists the
        # program's entire xref database: measured against a real binary, every
        # address -- including 0 -- got the same 1044 entries back, so the
        # address parameter did nothing. axtj (refs to the seek) and axfj
        # (refs from it) are the scoped queries; one process runs both so
        # "aa" pays for analysis once.
        commands = ["aa", f"axtj @ {address}", f"axfj @ {address}"]
        payload = self._run_raw(binary, commands, timeout=timeout)
        values = parse_r2_json_values(str(payload.get("raw") or ""))
        arrays = [value for value in values if isinstance(value, list)]
        combined: list[JsonObject] | None = None
        if len(arrays) >= 2:
            # Print order follows command order, so the first root array is
            # axtj's and the second axfj's. Fewer than two arrays means a
            # command produced no JSON (truncated output, unsupported form):
            # attributing a lone array to a direction would be a guess, so
            # that case reports parsed: False with the raw text intact.
            combined = []
            for direction, entries in (("to", arrays[0]), ("from", arrays[1])):
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    item = dict(entry)
                    item["direction"] = direction
                    # axtj rows name only the referencing side (the referenced
                    # side is the seek address itself); mirror for axfj so
                    # every item carries both endpoints for enrichment.
                    item.setdefault("to" if direction == "to" else "from", address)
                    combined.append(item)
        data = dict(payload)
        data["address"] = address
        return enrich_r2_payload(data, binary=binary, parsed=combined)

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0) -> JsonObject:
        return enrich_r2_payload(
            self._run_raw(binary, commands, timeout=timeout), binary=binary
        )

    def _run_raw(self, binary: Path, commands: list[str], *, timeout: float = 30.0) -> JsonObject:
        """Launch r2, enforce the whitelist and bounds, and return the raw payload."""
        try:
            timeout = clamp_cli_timeout(timeout, maximum=_MAX_TIMEOUT_S)
        except InvalidTimeout as exc:
            raise R2Error("invalid_params", str(exc)) from exc
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
        return payload


def _discover() -> Path | None:
    for name in ("r2", "rizin", "radare2"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None
