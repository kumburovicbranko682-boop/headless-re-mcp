from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]
_ALLOWED_CMDS = frozenset({"lm", "k", "r", "u", "~*", "version", "vertarget"})


class WindbgError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


class WindbgClient:
    def __init__(self, cdb: Path | None = None, *, allow_kernel: bool = False) -> None:
        self.cdb = cdb or _discover_cdb()
        self.allow_kernel = bool(allow_kernel)

    @property
    def available(self) -> bool:
        return self.cdb is not None and self.cdb.is_file()

    def open_dump(
        self,
        dump: Path,
        commands: list[str],
        *,
        timeout: float = 60.0,
        kernel: bool = False,
    ) -> JsonObject:
        if kernel and not self.allow_kernel:
            raise WindbgError(
                "permission_denied",
                "kernel dump analysis requires explicit HEADLESS_RE_WINDBG_ALLOW_KERNEL=1",
            )
        return self._run_dump(dump, commands, timeout=timeout)

    def threads(self, dump: Path, *, timeout: float = 60.0) -> JsonObject:
        data = self._run_dump(dump, ["~*"], timeout=timeout)
        return {"dump": str(dump), "threads": data.get("output", ""), "raw": data}

    def modules(self, dump: Path, *, timeout: float = 60.0) -> JsonObject:
        data = self._run_dump(dump, ["lm"], timeout=timeout)
        return {"dump": str(dump), "modules": data.get("output", ""), "raw": data}

    def disasm(
        self,
        dump: Path,
        address: str | int,
        *,
        length: int = 16,
        timeout: float = 60.0,
    ) -> JsonObject:
        if type(length) is not int or not 1 <= length <= 256:
            raise WindbgError("invalid_params", "length must be 1..256")
        if isinstance(address, int):
            if address < 0:
                raise WindbgError("invalid_params", "address must be non-negative")
            addr = hex(address)
        else:
            addr = str(address).strip()
            if not addr or any(ch in addr for ch in ";|&"):
                raise WindbgError("invalid_params", "invalid disasm address")
        # Whitelisted form: u <addr> L<count>
        cmd = f"u {addr} L{length}"
        data = self._run_dump(dump, [cmd], timeout=timeout)
        return {
            "dump": str(dump),
            "address": addr,
            "length": length,
            "disasm": data.get("output", ""),
            "raw": data,
        }


    def attach(self, pid: int, *, allowed_pid: int, timeout: float = 30.0) -> JsonObject:
        """Non-invasive user-mode probe against a session debuggee PID."""
        data = self._run_process(
            pid,
            ["vertarget", "version"],
            allowed_pid=allowed_pid,
            timeout=timeout,
        )
        return {
            "pid": pid,
            "attached": True,
            "mode": "noninvasive",
            "note": "cdb -pv probe; detached via q",
            "output": data.get("output", "")[:8000],
            "raw": data,
        }

    def live_threads(self, pid: int, *, allowed_pid: int, timeout: float = 30.0) -> JsonObject:
        data = self._run_process(pid, ["~*"], allowed_pid=allowed_pid, timeout=timeout)
        return {"pid": pid, "threads": data.get("output", ""), "raw": data}

    def live_modules(self, pid: int, *, allowed_pid: int, timeout: float = 30.0) -> JsonObject:
        data = self._run_process(pid, ["lm"], allowed_pid=allowed_pid, timeout=timeout)
        return {"pid": pid, "modules": data.get("output", ""), "raw": data}

    def live_disasm(
        self,
        pid: int,
        address: str | int,
        *,
        allowed_pid: int,
        length: int = 16,
        timeout: float = 30.0,
    ) -> JsonObject:
        if type(length) is not int or not 1 <= length <= 256:
            raise WindbgError("invalid_params", "length must be 1..256")
        if isinstance(address, int):
            if address < 0:
                raise WindbgError("invalid_params", "address must be non-negative")
            addr = hex(address)
        else:
            addr = str(address).strip()
            if not addr or any(ch in addr for ch in ";|&"):
                raise WindbgError("invalid_params", "invalid disasm address")
        cmd = f"u {addr} L{length}"
        data = self._run_process(pid, [cmd], allowed_pid=allowed_pid, timeout=timeout)
        return {
            "pid": pid,
            "address": addr,
            "length": length,
            "disasm": data.get("output", ""),
            "raw": data,
        }

    def _run_process(
        self,
        pid: int,
        commands: list[str],
        *,
        allowed_pid: int,
        timeout: float,
    ) -> JsonObject:
        if not self.available or self.cdb is None:
            raise WindbgError("capability_unavailable", "cdb/WinDbg is not installed")
        if type(pid) is not int or pid <= 0:
            raise WindbgError("invalid_params", "pid must be a positive integer")
        if pid != allowed_pid:
            raise WindbgError(
                "permission_denied",
                "windbg user-mode limited to session debuggee pid",
                pid=pid,
                allowed_pid=allowed_pid,
            )
        for cmd in commands:
            head = cmd.strip().split(" ", 1)[0]
            if head not in _ALLOWED_CMDS and cmd.strip() not in _ALLOWED_CMDS:
                raise WindbgError("invalid_params", "cdb command not whitelisted", command=cmd)
        script = "; ".join([*commands, "q"])
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        # -pv: non-invasive; can coexist with another debugger on the same PID.
        argv = [str(self.cdb), "-pv", "-p", str(pid), "-c", script]
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout,
                check=False,
                creationflags=creationflags,
            )
        except subprocess.TimeoutExpired as exc:
            raise WindbgError("timeout", "cdb timed out", timeout=timeout) from exc
        out = completed.stdout.decode("utf-8", errors="replace")[:500_000]
        err = completed.stderr.decode("utf-8", errors="replace")[:50_000]
        if completed.returncode not in {0, 1} and not out:
            raise WindbgError(
                "backend_error",
                "cdb user-mode probe failed",
                exit_code=completed.returncode,
                stderr=err[:2000],
            )
        return {
            "pid": pid,
            "mode": "noninvasive",
            "output": out,
            "stderr": err,
            "exit_code": completed.returncode,
        }

    def _run_dump(self, dump: Path, commands: list[str], *, timeout: float) -> JsonObject:
        if not self.available or self.cdb is None:
            raise WindbgError("capability_unavailable", "cdb/WinDbg is not installed")
        if not dump.is_file():
            raise WindbgError("not_found", "dump file not found", path=str(dump))
        for cmd in commands:
            head = cmd.strip().split(" ", 1)[0]
            if head not in _ALLOWED_CMDS and cmd.strip() not in _ALLOWED_CMDS:
                raise WindbgError("invalid_params", "cdb command not whitelisted", command=cmd)
        script = "; ".join([*commands, "q"])
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            completed = subprocess.run(
                [str(self.cdb), "-z", str(dump), "-c", script],
                capture_output=True,
                timeout=timeout,
                check=False,
                creationflags=creationflags,
            )
        except subprocess.TimeoutExpired as exc:
            raise WindbgError("timeout", "cdb timed out", timeout=timeout) from exc
        out = completed.stdout.decode("utf-8", errors="replace")[:500_000]
        err = completed.stderr.decode("utf-8", errors="replace")[:50_000]
        return {"dump": str(dump), "output": out, "stderr": err, "exit_code": completed.returncode}


def _discover_cdb() -> Path | None:
    env = os.environ.get("HEADLESS_RE_CDB")
    if env and Path(env).is_file():
        return Path(env)
    # Prefer the verified project runtime over a WindowsApps execution alias whose
    # package ACL can make ``is_file`` true while CreateProcess is denied.
    tools = Path(__file__).resolve().parents[4] / "artifacts" / "tools" / "cdb-amd64" / "cdb.exe"
    if tools.is_file():
        return tools
    found = shutil.which("cdb")
    if found and "windowsapps" not in found.lower():
        return Path(found)
    roots = [
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Windows Kits",
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Windows Kits",
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "WindowsApps",
    ]
    for root in roots:
        if not root.is_dir():
            continue
        matches = (
            list(root.glob("**/Debuggers/x64/cdb.exe"))
            + list(root.glob("**/amd64/cdb.exe"))
            + list(root.glob("**/x64/cdb.exe"))
            + list(root.glob("**/x86/cdb.exe"))
        )
        for match in matches:
            if match.is_file():
                return match
    return None
