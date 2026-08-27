"""apktool decode/build and apksigner re-signing as bounded subprocesses.

Both CLIs need a JRE and are user-provided, so a missing tool degrades to
``capability_unavailable`` instead of blocking readiness. Keystore passwords
never reach an observable channel: each password travels to apksigner in an
environment variable (its native ``env:`` source) rather than on argv -- a
command line is world-readable in the process table for as long as the signing
JVM runs -- and a failed sign scrubs every password from stderr before it
enters error details. A release keystore may guard its key with a password
distinct from the store password; when the caller supplies one it rides its own
child-only variable, otherwise both sources point at the single store password.
"""

from __future__ import annotations

import os
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import (
    InvalidTimeout,
    TimedOut,
    clamp_cli_timeout,
    run_bounded,
)

JsonObject = dict[str, Any]
_MAX_STDERR = 8000
# apk.decode / repack / sign all declare le=1800 in their schema.
_MAX_TIMEOUT_S = 1800.0
_DEBUG_KEYSTORE = Path.home() / ".android" / "debug.keystore"
_DEBUG_ALIAS = "androiddebugkey"
_DEBUG_PASSWORD = "android"
# The child-only variable --ks-pass reads via env:NAME (and --key-pass too when
# the key shares the store password). Deliberately not HEADLESS_RE_*: that
# prefix is the operator config namespace, and this is not a knob -- it exists
# only in the signer's copied environment.
_PASSWORD_ENV = "APKSIGNER_KS_PASS"
# The separate child-only variable --key-pass reads when the caller gives the
# key its own password. Only set on the child's environment in that case, so
# the common shared-password path keeps carrying exactly one secret.
_KEY_PASSWORD_ENV = "APKSIGNER_KEY_PASS"


def _scrub_secrets(text: str, *secrets: str) -> str:
    """Mask every non-empty secret in tool output before it enters an error.

    apksigner echoes its argument vector on a usage error and can name a
    password in a diagnostic; the store and key passwords may differ, so both
    are masked. Masking each independently is order-safe: once one is replaced
    it is gone, and equal secrets collapse to a single ``***``.
    """
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


class ApktoolError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _require_apk_zip(apk: Path) -> None:
    """Refuse a non-zip APK before launching the JVM.

    apktool ``d`` and apksigner both require a zip-format APK; handed anything
    else -- a truncated download, a path pointing at the wrong file, or a build
    output that slipped past its own check -- they still start a JVM and only
    then fail with an opaque Java error, after paying that startup cost and
    reporting a parameter mistake as a backend failure. ``zipfile.is_zipfile``
    reads only the archive's tail (it does not decompress, so the check itself
    has no zip-bomb exposure) and turns that cryptic failure into a precise
    ``invalid_params`` up front -- the same fail-fast shape as ``build``
    validating its own output is a real zip and the wasm tools checking the
    ``\\0asm`` magic before launching wabt.
    """
    if not zipfile.is_zipfile(apk):
        raise ApktoolError(
            "invalid_params",
            "input is not a valid APK (not a zip archive)",
            path=str(apk),
        )


def _run(
    cmd: list[str], *, timeout: float, env: dict[str, str] | None = None
) -> tuple[str, str, int]:
    try:
        timeout = clamp_cli_timeout(timeout, maximum=_MAX_TIMEOUT_S)
    except InvalidTimeout as exc:
        raise ApktoolError("invalid_params", str(exc)) from exc
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
        _require_apk_zip(apk)
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
        # apktool can exit 0 yet leave a truncated or empty file (a build that
        # aborted after creating the output, a full disk). An APK is a zip, so a
        # zero-byte or non-zip result is a failed rebuild -- reporting it as a
        # rebuilt apk would send an unusable file into apk.sign/install.
        size = out_apk.stat().st_size
        if size == 0 or not zipfile.is_zipfile(out_apk):
            raise ApktoolError(
                "backend_error",
                "apktool build produced an empty or invalid apk",
                exit_code=code,
                size=size,
                stderr=stderr[:_MAX_STDERR],
            )
        return {
            "apk": str(out_apk),
            "size": size,
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
        key_password: str = "",
        timeout: float = 300.0,
    ) -> JsonObject:
        """Sign an APK, defaulting to the standard Android debug keystore."""
        if not self.signer_available or self.apksigner is None:
            raise ApktoolError(
                "capability_unavailable", "apksigner is not configured (needs a JRE)"
            )
        if not apk.is_file():
            raise ApktoolError("not_found", "apk not found", path=str(apk))
        _require_apk_zip(apk)
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
        # A release keystore can guard the key with a password of its own; when
        # none is given it falls back to the store password (the common case,
        # and every debug keystore), so the shared-password path is unchanged.
        key_pass = key_password or password
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        # pass:<password> would put the secret on argv, and argv is readable by
        # every local process (/proc/<pid>/cmdline, Windows process listings)
        # for as long as the signing JVM runs. apksigner reads env:NAME
        # natively, and the copied environment is visible only to the child.
        sign_env = dict(os.environ)
        sign_env[_PASSWORD_ENV] = password
        # Only allocate the second variable when the key password truly differs,
        # so the shared-password path carries exactly one secret as before.
        if key_pass != password:
            sign_env[_KEY_PASSWORD_ENV] = key_pass
            key_pass_source = f"env:{_KEY_PASSWORD_ENV}"
        else:
            key_pass_source = f"env:{_PASSWORD_ENV}"
        _, stderr, code = _run(
            [
                str(self.apksigner),
                "sign",
                "--ks",
                str(store),
                "--ks-pass",
                f"env:{_PASSWORD_ENV}",
                "--ks-key-alias",
                alias,
                "--key-pass",
                key_pass_source,
                "--out",
                str(out_apk),
                str(apk),
            ],
            timeout=timeout,
            env=sign_env,
        )
        if code != 0 or not out_apk.is_file():
            # argv no longer carries either password, but keep scrubbing stderr
            # as defense in depth: the tool's own diagnostics must never leak it.
            scrubbed = _scrub_secrets(stderr, password, key_pass)
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
            scrubbed = _scrub_secrets(verify_stderr, password, key_pass)
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
