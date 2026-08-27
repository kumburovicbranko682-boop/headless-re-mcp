#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "install-linux.sh supports Linux only" >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64|amd64) ;;
  *)
    echo "Headless RE-MCP currently supports Linux x86_64 only" >&2
    exit 2
    ;;
esac

python_bin="${PYTHON:-python3}"
extras="${HEADLESS_RE_EXTRAS:-pe,web}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

"${python_bin}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
  echo "Python 3.11 or newer is required" >&2
  exit 2
}

"${python_bin}" -m pip install -e "${repo_root}[${extras}]"

# Optionally pull in the portable native backends (radare2, wabt, webcrack) so
# the Web and radare2 integration gates run instead of skipping. Off by default
# because it uses the system package manager and npm; opt in with
# HEADLESS_RE_INSTALL_BACKENDS=1.
if [[ "${HEADLESS_RE_INSTALL_BACKENDS:-0}" == "1" ]]; then
  # Best-effort: a missing backend degrades a tool, it does not fail the install.
  "${script_dir}/install-linux-backends.sh" || \
    echo "Some portable backends were not installed; continuing." >&2
fi

"${python_bin}" -m headless_re_mcp doctor
