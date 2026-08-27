"""apktool decode/build and apksigner re-signing as bounded subprocesses.

Both CLIs need a JRE and are user-provided, so a missing tool degrades to
``capability_unavailable`` instead of blocking readiness. Keystore passwords
never reach the child's argv: apksigner takes them from an environment variable
(``env:`` spec), not ``pass:``, so the secret stays out of the world-readable
``/proc/<pid>/cmdline``. As a second layer, a failed sign reports the tool's
stderr with any occurrence of the password scrubbed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded

JsonObject = dict[str, Any]
_MAX_STDERR = 8000
_DEBUG_KEYSTORE = Path.home() / ".android" / "debug.keystore"
_DEBUG_ALIAS = "androiddebugkey"
_DEBUG_PASSWORD = "android"
# apksigner reads the keystore/key password from this variable (via the env:
# spec) instead of taking it on the command line, where /proc/<pid>/cmdline is
# world-readable. Only the same-uid process owner can read /proc/<pid>/environ.
_KS_PASS_ENV = "HRE_APKSIGNER_KS_PASS"


class ApktoolError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _run(
    cmd: list[str], *, timeout: float, env: dict[str, str] | None = None
) -> tuple[str, str, int]:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        completed = run_bounded(cmd, timeout=timeout, creationflags=creationflags, env=env)
    except TimedOut as exc:
        # apktool and apksigner are scripts that start a JVM, so the deadline
        # has to bind the JVM too, not just the script that launched it.
        raise ApktoolError(
            "timeout",
            f"{Path(cmd[0]).name} timed out",
            timeout=timeout,
            killed_pids=exc.killed,
        ) from exc
    except OSError as exc:
        raise ApktoolError("backend_error", f"failed to launch {cmd[0]}: {exc}") from exc
    return (
        completed.stdout.decode("utf-8", errors="replace"),
        completed.stderr.decode("utf-8", errors="replace"),
        int(completed.returncode),
    )


class ApktoolClient:
    def __init__(self, apktool: Path | None = None, apksigner: Path | None = None) -> None:
        self.apktool = apktool
        self.apksigner = apksigner

    @property
    def available(self) -> bool:
        return self.apktool is not None and self.apktool.is_file()

    @property
    def signer_available(self) -> bool:
        return self.apksigner is not None and self.apksigner.is_file()

    def decode(
        self,
        apk: Path,
        out_dir: Path,
        *,
        timeout: float = 600.0,
        no_resources: bool = False,
    ) -> JsonObject:
        """Decode an APK into smali + resources for editing."""
        if not self.available or self.apktool is None:
            raise ApktoolError("capability_unavailable", "apktool is not configured (needs a JRE)")
        if not apk.is_file():
            raise ApktoolError("not_found", "apk not found", path=str(apk))
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        args = [str(self.apktool), "d", str(apk), "-o", str(out_dir), "-f"]
        if no_resources:
            args.append("-r")
        _, stderr, code = _run(args, timeout=timeout)
        manifest = out_dir / "AndroidManifest.xml"
        if code != 0 or not manifest.is_file():
            raise ApktoolError(
                "backend_error",
                "apktool decode failed",
                exit_code=code,
                stderr=stderr[:_MAX_STDERR],
            )
        smali_dirs = sorted(str(p.name) for p in out_dir.glob("smali*") if p.is_dir())
        return {
            "decoded_dir": str(out_dir),
            "manifest": str(manifest) if manifest.is_file() else None,
            "smali_dirs": smali_dirs,
            "has_resources": (out_dir / "res").is_dir(),
        }

    def build(self, decoded_dir: Path, out_apk: Path, *, timeout: float = 600.0) -> JsonObject:
        """Rebuild an APK from a previously decoded (and possibly edited) tree."""
        if not self.available or self.apktool is None:
            raise ApktoolError("capability_unavailable", "apktool is not configured (needs a JRE)")
        if not decoded_dir.is_dir():
            raise ApktoolError("not_found", "decoded directory not found", path=str(decoded_dir))
        if not (decoded_dir / "AndroidManifest.xml").is_file():
            raise ApktoolError(
                "invalid_params",
                "directory does not look like an apktool decode output",
                path=str(decoded_dir),
            )
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        _, stderr, code = _run(
            [str(self.apktool), "b", str(decoded_dir), "-o", str(out_apk)],
            timeout=timeout,
        )
        if code != 0 or not out_apk.is_file():
            raise ApktoolError(
                "backend_error",
                "apktool build failed",
                exit_code=code,
                stderr=stderr[:_MAX_STDERR],
            )
        return {
            "apk": str(out_apk),
            "size": out_apk.stat().st_size,
            "signed": False,
            "note": "unsigned; call apk.sign before installing",
        }

    def sign(
        self,
        apk: Path,
        out_apk: Path,
        *,
        keystore: Path | None = None,
        keystore_password: str = "",
        key_alias: str = "",
        timeout: float = 300.0,
    ) -> JsonObject:
        """Sign an APK, defaulting to the standard Android debug keystore."""
        if not self.signer_available or self.apksigner is None:
            raise ApktoolError(
                "capability_unavailable", "apksigner is not configured (needs a JRE)"
            )
        if not apk.is_file():
            raise ApktoolError("not_found", "apk not found", path=str(apk))
        store = keystore or _DEBUG_KEYSTORE
        if not store.is_file():
            raise ApktoolError(
                "not_found",
                "keystore not found; pass keystore or create the Android debug keystore",
                path=str(store),
            )
        using_debug = keystore is None
        password = keystore_password or (_DEBUG_PASSWORD if using_debug else "")
        alias = key_alias or (_DEBUG_ALIAS if using_debug else "")
        if not password or not alias:
            raise ApktoolError(
                "invalid_params",
                "keystore_password and key_alias are required for a custom keystore",
            )
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        # Deliver the password through the environment, not the argv: apksigner's
        # env: spec names a variable it reads, so the secret never lands in
        # /proc/<pid>/cmdline (world-readable) -- only in /proc/<pid>/environ,
        # which is readable only by the same uid that started the process.
        child_env = {**os.environ, _KS_PASS_ENV: password}
        _, stderr, code = _run(
            [
                str(self.apksigner),
                "sign",
                "--ks",
                str(store),
                "--ks-pass",
                f"env:{_KS_PASS_ENV}",
                "--ks-key-alias",
                alias,
                "--key-pass",
                f"env:{_KS_PASS_ENV}",
                "--out",
                str(out_apk),
                str(apk),
            ],
            timeout=timeout,
            env=child_env,
        )
        if code != 0 or not out_apk.is_file():
            # The password is no longer on the argv, but scrub stderr anyway in
            # case a keystore path or prompt ever echoes it -- defense in depth.
            scrubbed = stderr.replace(password, "***") if password else stderr
            raise ApktoolError(
                "backend_error",
                "apksigner failed",
                exit_code=code,
                stderr=scrubbed[:_MAX_STDERR],
            )
        verify_timeout = min(60.0, max(5.0, float(timeout)))
        _, verify_stderr, verify_code = _run(
            [str(self.apksigner), "verify", str(out_apk)],
            timeout=verify_timeout,
        )
        if verify_code != 0:
            scrubbed = (
                verify_stderr.replace(password, "***") if password else verify_stderr
            )
            raise ApktoolError(
                "backend_error",
                "apksigner reported the output is not signed",
                exit_code=verify_code,
                stderr=scrubbed[:_MAX_STDERR],
            )
        return {
            "apk": str(out_apk),
            "size": out_apk.stat().st_size,
            "signed": True,
            "keystore": str(store),
            "debug_keystore": using_debug,
        }
