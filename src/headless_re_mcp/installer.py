"""One-command installer for Python dependencies and local analysis runtimes."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import uuid4

from headless_re_mcp.config import (
    Settings,
    default_config_path,
    default_data_path,
    discover_ida_home,
    update_config_values,
    validate_ida_home,
)

JsonObject = dict[str, Any]
_RELEASE_MANIFEST = Path(__file__).with_name("dependency_release.json")
_DOWNLOAD_CHUNK = 1024 * 1024
_MAX_ARCHIVE_FILES = 20_000
_MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_MANIFEST_BYTES = 1024 * 1024


class InstallError(RuntimeError):
    """Installation failed without leaving a partially activated dependency tree."""


def _read_manifest(path: Path, *, label: str) -> bytes:
    try:
        with path.open("rb") as stream:
            payload = stream.read(_MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise InstallError(f"{label} is unreadable: {exc}") from exc
    if len(payload) > _MAX_MANIFEST_BYTES:
        raise InstallError(f"{label} exceeds {_MAX_MANIFEST_BYTES} bytes")
    return payload


def load_dependency_release() -> JsonObject:
    encoded = _read_manifest(
        _RELEASE_MANIFEST, label="dependency release manifest"
    )
    try:
        raw = json.loads(encoded.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"dependency release manifest is unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise InstallError("dependency release manifest root must be an object")
    payload = cast(JsonObject, raw)
    if payload.get("schema_version") != 1:
        raise InstallError("unsupported dependency release manifest")
    for field in ("tag", "asset"):
        value = payload.get(field)
        if (
            not isinstance(value, str)
            or not value
            or value in {".", ".."}
            or "/" in value
            or "\\" in value
        ):
            raise InstallError(f"dependency release manifest has an invalid {field}")
    size = payload.get("size")
    if type(size) is not int or size <= 0:
        raise InstallError("dependency release manifest has an invalid size")
    digest = str(payload.get("sha256") or "").lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise InstallError("dependency release manifest has an invalid SHA-256")
    if payload.get("never_bundles_ida") is not True:
        raise InstallError("dependency release must explicitly exclude IDA")
    urls = payload.get("download_urls")
    if not isinstance(urls, list) or not urls:
        raise InstallError("dependency release has no download URLs")
    if any(not isinstance(url, str) or not _is_safe_download_url(url) for url in urls):
        raise InstallError("dependency release has an invalid download URL")
    return payload


def _is_safe_download_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_DOWNLOAD_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download_one(url: str, destination: Path, *, expected_size: int) -> None:
    if not _is_safe_download_url(url):
        raise InstallError("dependency download URL must be credential-free HTTPS")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": "headless-re-mcp-one-click-setup/1",
        },
    )
    context = ssl.create_default_context()
    written = 0
    with urllib.request.urlopen(request, timeout=45, context=context) as response:  # noqa: S310
        status = getattr(response, "status", 200)
        if status != 200:
            raise InstallError(f"download returned HTTP {status}")
        header_size = response.headers.get("Content-Length")
        if header_size and int(header_size) != expected_size:
            raise InstallError(
                f"download size header mismatch: got {header_size}, expected {expected_size}"
            )
        with destination.open("wb") as output:
            while True:
                chunk = response.read(_DOWNLOAD_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > expected_size:
                    raise InstallError("download exceeded the pinned release size")
                output.write(chunk)
                if written == expected_size or written % (16 * _DOWNLOAD_CHUNK) < len(chunk):
                    percent = min(100, int(written * 100 / expected_size))
                    print(f"  下载进度：{percent}% ({written // _DOWNLOAD_CHUNK} MiB)", flush=True)
    if written != expected_size:
        raise InstallError(f"download is incomplete: got {written}, expected {expected_size} bytes")


def download_dependency_release(
    destination_dir: Path | None = None,
    *,
    urls: list[str] | None = None,
) -> JsonObject:
    """Download the pinned release with mirror fallback and mandatory SHA verification."""

    release = load_dependency_release()
    root = (destination_dir or (default_data_path() / "dependencies")).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    archive = root / str(release["asset"])
    expected_sha = str(release["sha256"]).lower()
    expected_size = int(release["size"])
    if archive.is_file() and archive.stat().st_size == expected_size:
        if _sha256(archive) == expected_sha:
            return {"ok": True, "archive": str(archive), "cached": True, "sha256": expected_sha}
        archive.unlink()

    attempts: list[JsonObject] = []
    candidates = urls or [str(item) for item in release["download_urls"]]
    for index, url in enumerate(candidates, start=1):
        partial = archive.with_name(f".{archive.name}.part-{os.getpid()}-{uuid4().hex}")
        print(f"  下载依赖包（源 {index}/{len(candidates)}）：{url}", flush=True)
        try:
            _download_one(url, partial, expected_size=expected_size)
            actual_sha = _sha256(partial)
            if actual_sha != expected_sha:
                raise InstallError(
                    f"SHA-256 mismatch: got {actual_sha}, expected {expected_sha}"
                )
            os.replace(partial, archive)
            return {
                "ok": True,
                "archive": str(archive),
                "cached": False,
                "source": url,
                "sha256": actual_sha,
                "attempts": attempts,
            }
        except (OSError, ValueError, InstallError, urllib.error.URLError) as exc:
            partial.unlink(missing_ok=True)
            attempts.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
            print(f"  当前源失败，尝试下一个：{type(exc).__name__}: {exc}", flush=True)
    summary = json.dumps(attempts, ensure_ascii=False)
    raise InstallError(f"all dependency release sources failed: {summary}")


def _safe_extract(archive: Path, destination: Path) -> None:
    destination_resolved = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > _MAX_ARCHIVE_FILES:
            raise InstallError("dependency archive contains too many files")
        total = sum(item.file_size for item in members)
        if total > _MAX_EXTRACTED_BYTES:
            raise InstallError("dependency archive expands beyond the safety limit")
        for item in members:
            mode = (item.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise InstallError(f"dependency archive contains a symlink: {item.filename}")
            target = (destination / item.filename).resolve()
            try:
                target.relative_to(destination_resolved)
            except ValueError as exc:
                raise InstallError(
                    f"dependency archive path escapes root: {item.filename}"
                ) from exc
        bundle.extractall(destination)


def extract_dependency_release(
    archive: Path,
    destination_dir: Path | None = None,
) -> JsonObject:
    release = load_dependency_release()
    archive = archive.expanduser().resolve()
    if not archive.is_file():
        raise InstallError(f"dependency archive not found: {archive}")
    expected_sha = str(release["sha256"]).lower()
    actual_sha = _sha256(archive)
    if actual_sha != expected_sha:
        raise InstallError(f"dependency archive SHA-256 mismatch: {actual_sha}")

    parent = (destination_dir or archive.parent).expanduser().resolve()
    final = parent / str(release["tag"])
    existing = _find_bundle_root(final)
    if existing is not None:
        return {"ok": True, "root": str(existing), "cached": True, "sha256": actual_sha}

    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="deps-extract-", dir=parent))
    try:
        _safe_extract(archive, staging)
        bundle_root = _find_bundle_root(staging)
        if bundle_root is None:
            raise InstallError("MANIFEST.json missing from dependency release")
        manifest = _load_bundle_manifest(bundle_root / "MANIFEST.json")
        if manifest.get("never_bundles_ida") is not True:
            raise InstallError("dependency bundle does not prove that IDA is excluded")
        if final.exists():
            shutil.rmtree(final)
        os.replace(staging, final)
        installed_root = _find_bundle_root(final)
        if installed_root is None:
            raise InstallError("dependency bundle disappeared after activation")
        return {"ok": True, "root": str(installed_root), "cached": False, "sha256": actual_sha}
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _find_bundle_root(root: Path) -> Path | None:
    direct = root / "MANIFEST.json"
    if direct.is_file():
        return root.resolve()
    if not root.is_dir():
        return None
    matches = list(root.glob("*/MANIFEST.json"))
    return matches[0].parent.resolve() if len(matches) == 1 else None


def _load_bundle_manifest(path: Path) -> JsonObject:
    encoded = _read_manifest(path, label="dependency bundle manifest")
    try:
        raw = json.loads(encoded.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"dependency bundle manifest is unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise InstallError("dependency bundle manifest root must be an object")
    return cast(JsonObject, raw)


def configure_dependency_bundle(bundle_root: Path) -> JsonObject:
    """Validate the bundle manifest and persist only executable paths it declares."""

    root = bundle_root.expanduser().resolve()
    manifest_path = root / "MANIFEST.json"
    if not manifest_path.is_file():
        raise InstallError(f"dependency MANIFEST.json not found under {root}")
    manifest = _load_bundle_manifest(manifest_path)
    if manifest.get("never_bundles_ida") is not True:
        raise InstallError("refusing a dependency bundle that may contain IDA")
    included = manifest.get("included")
    if not isinstance(included, list):
        raise InstallError("dependency bundle included list is invalid")

    key_by_id = {
        "x64dbg-x64": "x64dbg_headless_x64",
        "x64dbg-x86": "x64dbg_headless_x86",
        "upx": "upx",
        "die": "diec",
        "cdb": "cdb",
        "de4dot": "de4dot",
        "net_reactor_slayer": "net_reactor_slayer",
    }
    updates: dict[str, Path] = {}
    rejected: list[str] = []
    for item in included:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id") or "")
        key = key_by_id.get(item_id)
        if key is None:
            continue
        candidate = (root / str(item.get("path") or "")).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            rejected.append(item_id)
            continue
        if not candidate.is_file():
            rejected.append(item_id)
            continue
        updates[key] = candidate
    if rejected:
        raise InstallError(f"dependency bundle contains invalid executable paths: {rejected}")
    if "x64dbg_headless_x64" not in updates or "x64dbg_headless_x86" not in updates:
        raise InstallError("dependency release is missing an x86 or x64 headless runtime")
    config_path = update_config_values(updates)
    return {
        "ok": True,
        "bundle_root": str(root),
        "config_path": str(config_path),
        "configured": {key: str(value) for key, value in sorted(updates.items())},
        "missing_optional": list(manifest.get("missing") or []),
    }


def _prompt_ida_path() -> Path | None:
    print("未自动找到 IDA Professional 9.x（IDA 不会包含在依赖包中）。", flush=True)
    raw = input("请输入授权 IDA 安装目录，暂不配置可输入 -：").strip().strip('"')
    if raw in {"", "-", "skip"}:
        return None
    return Path(raw).expanduser().resolve()


def run_one_click_setup(
    *,
    download_release: bool = True,
    non_interactive: bool = False,
    ida_home: Path | None = None,
    activate_ida: bool = True,
    dependencies_dir: Path | None = None,
) -> JsonObject:
    """Finish all local configuration after Python package dependencies are installed."""

    steps: list[JsonObject] = []
    settings = Settings.load()
    on_windows = os.name == "nt"
    release_paths = (
        settings.x64dbg_headless_x64,
        settings.x64dbg_headless_x86,
        settings.upx,
        settings.diec,
        settings.cdb,
        settings.de4dot,
        settings.net_reactor_slayer,
    )
    release_incomplete = any(path is None or not path.is_file() for path in release_paths)
    if download_release and release_incomplete and on_windows:
        downloaded = download_dependency_release(dependencies_dir)
        steps.append({"step": "download_release", **downloaded})
        extracted = extract_dependency_release(
            Path(str(downloaded["archive"])), dependencies_dir
        )
        steps.append({"step": "extract_release", **extracted})
        configured = configure_dependency_bundle(Path(str(extracted["root"])))
        steps.append({"step": "configure_release", **configured})
    elif download_release and not on_windows:
        steps.append(
            {
                "step": "windows_dependency_release",
                "ok": True,
                "status": "unsupported_on_platform",
                "message": (
                    "Skipped the Windows x64dbg/cdb dependency bundle; "
                    "Linux uses portable backends installed separately."
                ),
            }
        )

    selected_ida = (
        ida_home.expanduser().resolve()
        if ida_home is not None
        else settings.ida_home or discover_ida_home()
    )
    if selected_ida is None and not non_interactive and on_windows:
        selected_ida = _prompt_ida_path()
    ida_result: JsonObject
    if selected_ida is not None:
        checked = validate_ida_home(selected_ida)
        if not checked.get("ok"):
            raise InstallError(str(checked.get("message") or "IDA path is invalid"))
        from headless_re_mcp.web.setup import configure_ida

        ida_result = configure_ida(ida_home=selected_ida, activate=activate_ida)
        if not ida_result.get("ok"):
            raise InstallError(f"IDA configuration failed: {ida_result}")
    else:
        ida_result = {
            "ok": not on_windows,
            "code": "ida_not_configured",
            "status": "required" if on_windows else "optional",
            "message": (
                "IDA is not configured; install licensed IDA 9.x and rerun "
                "python setup.py --ida-home PATH to enable static.idalib"
            ),
            "never_bundled": True,
        }
    steps.append({"step": "configure_ida", **ida_result})

    update_config_values(
        {"local_full_access": True, "http_host": "127.0.0.1", "http_port": 8765}
    )
    from headless_re_mcp.config_generate import export_mcp_environment
    from headless_re_mcp.doctor import run_doctor

    settings = Settings.load()
    export = export_mcp_environment(
        settings,
        persist=True,
        config_path=default_config_path(),
    )
    steps.append(
        {
            "step": "generate_mcp",
            "ok": bool(export.get("ok")),
            "written": export.get("written") or {},
        }
    )
    doctor = run_doctor(settings)
    steps.append(
        {
            "step": "doctor",
            "ok": doctor.ready,
            "probes": [
                {"name": item.name, "status": item.status.value, "summary": item.summary}
                for item in doctor.probes
            ],
        }
    )
    return {
        "ok": doctor.ready,
        "configured": True,
        "platform": "windows" if on_windows else "linux",
        "config_path": str(default_config_path()),
        "ida_configured": selected_ida is not None,
        "doctor_ready": doctor.ready,
        "steps": steps,
    }


def print_setup_summary(result: JsonObject) -> None:
    print("\n======== 一键配置结果 ========", flush=True)
    print(f"配置文件：{result.get('config_path')}", flush=True)
    for step in result.get("steps") or []:
        if isinstance(step, dict):
            print(f"  [{'OK' if step.get('ok') else 'WARN'}] {step.get('step')}", flush=True)
    print(f"doctor.ready = {result.get('doctor_ready')}", flush=True)
    if not result.get("ida_configured"):
        qualifier = "Windows 必需" if result.get("platform") == "windows" else "Linux 可选"
        print(
            f"IDA 尚未配置（{qualifier}）；安装授权 IDA 后重跑："
            "python setup.py --ida-home <目录>",
            flush=True,
        )
    print("启动 Web：python start_web.py", flush=True)
    print("启动 MCP：python -m headless_re_mcp serve", flush=True)
    print("==============================", flush=True)


if __name__ == "__main__":  # pragma: no cover - setup.py is the public bootstrap
    print("Run the repository bootstrap instead: python setup.py", file=sys.stderr)
    raise SystemExit(2)
