"""Headless RE-MCP one-command bootstrap: ``python setup.py``.

This is intentionally an installer entry point, not setuptools metadata. Project
packaging remains defined by ``pyproject.toml``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import traceback
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BOOTSTRAP_LOG = Path.home() / ".headless-re-mcp" / "logs" / "setup.log"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Headless RE-MCP 一键安装与配置")
    parser.add_argument("--skip-pip", action="store_true", help="跳过 Python 依赖安装")
    parser.add_argument("--skip-release", action="store_true", help="不下载 Release 依赖包")
    parser.add_argument("--non-interactive", action="store_true", help="不询问 IDA 路径")
    parser.add_argument("--ida-home", type=Path, help="授权 IDA Professional 9.x 安装目录")
    parser.add_argument("--deps-dir", type=Path, help="Release 依赖包下载与解压目录")
    parser.add_argument("--no-activate-ida", action="store_true", help="不运行 idalib 激活脚本")
    parser.add_argument(
        "--extras",
        default="ida,pe,web,native",
        help="安装的 pyproject extras（默认：ida,pe,web,native）",
    )
    return parser


def _write_bootstrap_failure(exc: BaseException, incident: str) -> None:
    BOOTSTRAP_LOG.parent.mkdir(parents=True, exist_ok=True)
    with BOOTSTRAP_LOG.open("a", encoding="utf-8") as stream:
        stream.write(
            f"\n[{datetime.now(UTC).isoformat()}] incident={incident} "
            f"type={type(exc).__name__} message={exc}\n"
        )
        traceback.print_exception(type(exc), exc, exc.__traceback__, file=stream)


def _install_python_dependencies(extras: str) -> None:
    requirement = f".[{extras}]" if extras.strip() else "."
    command = [sys.executable, "-m", "pip", "install", "-e", requirement]
    print(f"[1/4] 安装 Python 依赖：{' '.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"pip install failed with exit code {completed.returncode}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if sys.version_info < (3, 11):  # noqa: UP036 - bootstrap runs before packaging metadata
        raise RuntimeError("Python 3.11 or newer is required")
    os.chdir(ROOT)
    if not args.skip_pip:
        _install_python_dependencies(args.extras)
    src = ROOT / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))

    from headless_re_mcp.error_boundary import install_global_exception_hooks
    from headless_re_mcp.installer import print_setup_summary, run_one_click_setup

    install_global_exception_hooks("setup")
    print("[2/4] 检测本机路径与现有配置", flush=True)
    print("[3/4] 配置 Release 依赖与授权 IDA", flush=True)
    result = run_one_click_setup(
        download_release=not args.skip_release,
        non_interactive=args.non_interactive,
        ida_home=args.ida_home,
        activate_ida=not args.no_activate_ida,
        dependencies_dir=args.deps_dir,
    )
    print("[4/4] 生成 MCP 配置并运行 Doctor", flush=True)
    print_setup_summary(result)
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except SystemExit:
        raise
    except BaseException as exc:  # bootstrap must work before project dependencies exist
        incident = uuid.uuid4().hex
        with suppress(OSError):
            _write_bootstrap_failure(exc, incident)
        payload = {
            "ok": False,
            "error": {
                "code": "setup_failed",
                "message": f"{type(exc).__name__}: {exc}",
                "details": {"incident_id": incident, "log_path": str(BOOTSTRAP_LOG)},
            },
        }
        print(json.dumps(payload, ensure_ascii=False), file=sys.stderr, flush=True)
        raise SystemExit(1) from None
