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
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload

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
        "axj",
        "agCj",
        "aa",
    }
)
_PDJ_COMMAND = re.compile(r"pdj ([1-9][0-9]*) @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
_AXJ_COMMAND = re.compile(r"axj @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")


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

    def callgraph(self, binary: Path, *, timeout: float = 30.0) -> JsonObject:
        """Program-wide call graph via agCj (analysis first).

        agCj nodes are keyed by name, not address -- each is
        ``{name, size, imports:[callee names]}`` -- so the generic address
        mapping finds nothing to map. Rename ``imports`` to ``calls`` (these
        are callees, not the imported symbols r2.imports lists) and add the
        per-node and total edge counts.
        """
        data = self.run(binary, ["aa", "agCj"], timeout=timeout)
        raw_items = data.get("items")
        nodes = raw_items if isinstance(raw_items, list) else []
        out_nodes: list[JsonObject] = []
        edge_total = 0
        for node in nodes:
            if not isinstance(node, dict):
                continue
            name = node.get("name")
            calls = node.get("imports")
            call_names = [c for c in calls if isinstance(c, str)] if isinstance(calls, list) else []
            edge_total += len(call_names)
            entry: JsonObject = {
                "name": name if isinstance(name, str) else "",
                "calls": call_names,
                "call_count": len(call_names),
            }
            size = node.get("size")
            if type(size) is int:
                entry["size"] = size
            out_nodes.append(entry)
        data = dict(data)
        data["items"] = out_nodes
        data["count"] = len(out_nodes)
        # Edges among the returned (possibly capped) nodes; items_truncated
        # from enrich already says when the node list itself was cut.
        data["edge_count"] = edge_total
        return data

    def xrefs(
        self,
        binary: Path,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> JsonObject:
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        cmd = f"axj @ {address}"
        data = self.run(binary, ["aa", cmd], timeout=timeout)
        data = dict(data)
        data["address"] = address
        return enrich_r2_payload(data, binary=binary)

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0) -> JsonObject:
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
        return enrich_r2_payload(payload, binary=binary)


def _discover() -> Path | None:
    for name in ("r2", "rizin", "radare2"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None
